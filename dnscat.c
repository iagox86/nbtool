/* dnscat.c
 * By Ron Bowes
 * Created January, 2010
 *
 * (See LICENSE.txt)
 *
 * For up to date documentation, please see the wiki:
 * http://www.skullsecurity.org/wiki/index.php/Dnscat
 *
 */

#define _POSIX_SOURCE /* For fileno(). */

#include <ctype.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef WIN32
#include <io.h>
#include <winsock2.h>
#else
#include <netdb.h>
#include <strings.h>
#include <unistd.h>
#endif

#include "buffer.h"
#include "dns.h"
#include "memory.h"
#include "my_getopt.h"
#include "select_group.h"
#include "session.h"
#include "types.h"
#include "udp.h"

/* Used for a state machine when processing packets. */
typedef enum
{
	PROCESSING_STATE_SIG,
	PROCESSING_STATE_FLAGS,
	PROCESSING_STATE_IDENTIFIER,
	PROCESSING_STATE_SESSION,
	PROCESSING_STATE_SEQ,
	PROCESSING_STATE_COUNT,
	PROCESSING_STATE_DATA,
	PROCESSING_STATE_ERROR_CODE,
	PROCESSING_STATE_GARBAGE,
	PROCESSING_STATE_DOMAIN
} processing_state_t;

/* Flags for the packets. */
typedef enum
{
	FLAG_STREAM     = 0x00000001,
/*	FLAG_SYN        = 0x00000002, Deprecated */
/*	FLAG_ACK        = 0x00000004, Deprecated */
	FLAG_RST        = 0x00000008, 
	FLAG_HEX        = 0x00000010,
	FLAG_SESSION    = 0x00000020,
	FLAG_IDENTIFIER = 0x00000040,
} flags_t;

/* Error code for remote connections. */
typedef enum
{
	REMOTE_ERROR_SUCCESS            = 0x00000000,
	REMOTE_ERROR_BUSY               = 0x00000001,
	REMOTE_ERROR_INVALID_IN_STATE   = 0x00000002,
	REMOTE_ERROR_FIN                = 0x00000003,
	REMOTE_ERROR_4                  = 0x00000004, /* Left to take up space. */
	REMOTE_ERROR_BAD_SEQ            = 0x00000005,
	REMOTE_ERROR_NOT_IMPL           = 0x00000006,
	REMOTE_ERROR_TESTING            = 0xFFFFFFFF
	/* Don't forget to update REMOTE_ERROR_MAX. */
} remote_error_t;

/* Encoding types. */
typedef enum
{
	ENCODING_NETBIOS,
	ENCODING_HEX
} encoding_t;

/* An array for the errors (not currently being used). */
static char *remote_error[] = {"ERROR_SUCCESS", "ERROR_BUSY", "ERROR_INVALID_IN_STATE", "ERROR_FIN", "ERROR_4", "ERROR_BAD_SEQ", "ERROR_NOT_IMPL", "ERROR_TESTING"};

/* The maximum remote error, to prevent overflows. */
#define REMOTE_ERROR_MAX REMOTE_ERROR_NOT_IMPL

/* A macro to display remote protocol errors. */
#define REMOTE_ERROR(s) ((s < 0 || s > REMOTE_ERROR_MAX) ? "(unknown error)" : remote_error[s])

/* Local errors. */
typedef enum
{
	LOCAL_ERROR_SUCCESS       = 0x00000000, /* Everything's okay! */
	LOCAL_ERROR_WRONG_DOMAIN  = 0x00000001, /* Packet is sent to incorrect domain. */
	LOCAL_ERROR_INVALID       = 0x00000002, /* Packet couldn't be parsed (wrong number of fields, wrong type, etc.) */
	LOCAL_ERROR_BAD_SIGNATURE = 0x00000003, /* Packet didn't start with the proper signature. */
	/* Don't forget to update LOCAL_ERROR_MAX. */
} local_error_t;
static char *local_error[] = {"ERROR_SUCCESS", "ERROR_WRONG_DOMAIN", "ERROR_INVALID", "ERROR_BAD_SIGNATURE"};

/* The maximum local error, to prevent overflows. */
#define LOCAL_ERROR_MAX LOCAL_ERROR_BAD_SIGNATURE

/* A macro to display local protocol errors. */
#define LOCAL_ERROR(s) ((s < 0 || s > LOCAL_ERROR_MAX) ? "(unknown error)" : local_error[s])

/* The size of chunks to send when --stage is enabled. */
#define STAGE_CHUNK_SIZE 255

/* Some defaults. */
#define DEFAULT_CHUNK_SIZE    62
#define DEFAULT_SECTION_COUNT 3
#define DEFAULT_SIGNATURE     "dnscat"
#define DEFAULT_REQUEST_TYPE  DNS_TYPE_CNAME
#define DEFAULT_USE_STREAM    TRUE
#define DEFAULT_USER          "nobody"
#define DEFAULT_DOMAIN_NAME   "*"
#define DEFAULT_FREQUENCY     1000
#define DEFAULT_TIMEOUT       5
#define DEFAULT_ENCODING      ENCODING_NETBIOS
#define DEFAULT_PORT          53
#define DEFAULT_SOURCE_ADDR   "0.0.0.0"

#define NAME "dnscat"

typedef struct
{
	int socket; /* Store the socket. */
	NBBOOL is_server; /* Set to TRUE if it's a listener, FALSE otherwise. */
	NBBOOL built_in; /* Set to TRUE to use built-in functions (gethostbyname()) instead of our custom resolver. */
	char *signature; /* The signature to prefix each request with (and to check each incoming request for). */
	char *identifier; /* The identifier we're sending (client only). */
	char *session; /* The session that we're a part of (client only). */
	NBBOOL no_session; /* If set, sessionid won't be included in packets. */
	char *domain; /* The domain to append to each request (and to check for, in server mode). */
	char *source; /* The source address (Default: 0.0.0.0). */
	uint16_t port; /* The source port in listener mode, the target port otherwise. */

	NBBOOL waiting_for_ack; /* Waiting for the server to acknowledge our message. */

	dns_types_t request_type; /* The request type (CNAME, MX, AAAA, etc). */
#ifndef WIN32
	NBBOOL AAAA; /* Set to TRUE to display AAAA requests. They aren't displayed by default. */
#endif

	sessions_t *sessions; /* Store the list of sessions running. */

	NBBOOL use_stream; /* Set to TRUE to use stream mode (default); otherwise, uses datagram mode. */
	int timeout; /* The amount of time before a connection resets. */

	uint32_t chunk_size; /* The maximum encoded size of a DNS section. Protocol states that 64 is the max, including the one-byte prefix. */
	uint32_t section_count; /* The number of DNS sections to send. Any more than 3 results in packets that are too long. */
	int   frequency; /* The frequency with which the client polls the server. */

	char *user; /* The user to drop privileges to. */
	NBBOOL keep_root; /* Set to TRUE to keep root privileges (no dropping). */

	select_group_t *select_group; /* Used to keep track of the sockets. */

	char *dns_user; /* The user-supplied DNS server. Takes precident over dns_system. */
	char *dns_system; /* The system-wide DNS server. */

	NBBOOL multi; /* If set, one server will talk to multiple clients. */

	char *exec; /* The program to execute. */
	NBBOOL exec_no_stderr; /* Ignore stderr. */

	char *stage; /* Set to the 'stage' file. */
	FILE *stage_file; /* The handle to the stage file. */

	char *log_filename; /* The file to use for logging. */

	encoding_t encoding; /* The type of payload encoding to use. */

#if TEST
	/* Testing stuff. */
	NBBOOL test_errors;
#endif
} settings_t;

/* The data stored in a single dnscat packet. This is encoded as a DNS name. */
typedef struct
{
	char          *signature;
	uint32_t       flags;
	char          *identifier;
	char          *session;
	uint32_t       seq;
	uint8_t       *data;
	uint32_t       data_length;
	char          *domain;
	remote_error_t error_code;
} dnscat_packet_t;

/* We need this for catching signals and cleaning up properly. */
static settings_t *global_settings = NULL;

/* Client only. Get the DNS server that's being used to send requests. This is
 * either the system DNS or the DNS given by the user. */
static char *get_dns(settings_t *settings)
{
	if(settings->dns_user)
		return settings->dns_user;
	return settings->dns_system;
}

/* Take the given packet and convert it into a DNS name. The data section will
 * be encoded in as many chunks as necessary. The packet->flags field is used
 * to decide which fields to include. */
static char *packet_to_name(settings_t *settings, dnscat_packet_t *packet)
{
	buffer_t *name = buffer_create(BO_NETWORK);
	char number[9]; /* Used throughout as a buffer. */
	uint8_t i;

	/* Twiddle the flags if the use requested no session. */
	if(settings->no_session)
		packet->flags = packet->flags & (~FLAG_SESSION);

	/* Add the signature. */
	buffer_add_string(name, packet->signature);
	buffer_add_int8(name, '.');

	/* Add the flags. */
#ifdef WIN32
	sprintf_s(number, 9, "%x", packet->flags);
#else
	sprintf(number, "%x", packet->flags);
#endif
	buffer_add_string(name, number);
	buffer_add_int8(name, '.');

	/* Add the identifier, if required. */
	if(packet->flags & FLAG_IDENTIFIER)
	{
		buffer_add_string(name, packet->identifier);
		buffer_add_int8(name, '.');
	}

	/* Add the session id, if required. */
	if(packet->flags & FLAG_SESSION)
	{
		buffer_add_string(name, packet->session);
		buffer_add_int8(name, '.');
	}

	/* Add the sequence number, if required. */
	if(packet->flags & FLAG_STREAM)
	{
#ifdef WIN32
		sprintf_s(number, 9, "%x", packet->seq);
#else
		sprintf(number, "%x", packet->seq);
#endif
		buffer_add_string(name, number);
		buffer_add_int8(name, '.');
	}

	/* Add the error, if required. */
	if(packet->flags & FLAG_RST)
	{
#ifdef WIN32
		sprintf_s(number, 9, "%x", packet->error_code);
#else
		sprintf(number, "%x", packet->error_code);
#endif
		buffer_add_string(name, number);
		buffer_add_int8(name, '.');
	}
	else
	{
		/* This is where it gets a little more complicated. We have to marshall up the 
		 * data into chunks, encode it, then add the length to the beginning. */
		buffer_t *data = buffer_create(BO_NETWORK);
		uint32_t index = 0;
		uint32_t length = 0;
		uint32_t sections = 0;

		/* Loop until we're out of data. */
		while(index < packet->data_length)
		{
			while(length < settings->chunk_size && index < packet->data_length)
			{
				if(packet->flags & FLAG_HEX)
				{
					uint8_t bit;

					bit = packet->data[index] >> 4;
					buffer_add_int8(data, bit > 9 ? ('a' + bit - 10) : ('0' + bit));
					length++;

					bit = packet->data[index] & 0x0F;
					buffer_add_int8(data, bit > 9 ? ('a' + bit - 10) : ('0' + bit));
					length++;

				}
				else
				{
					buffer_add_int8(data, ((packet->data[index] >> 4) & 0x0F) + 'a');
					length++;
					buffer_add_int8(data, ((packet->data[index] >> 0) & 0x0F) + 'a');
					length++;
				}

				/* Increment the index. */
				index++;
			}
			buffer_add_int8(data, '.');
			length = 0;
			sections++;
		}

		/* Now that we've built up the name, add the appropriate count and data. */
#ifdef WIN32
		sprintf_s(number, 9, "%x", sections);
#else
		sprintf(number, "%x", sections);
#endif
		buffer_add_string(name, number);
		buffer_add_int8(name, '.');
		buffer_add_buffer(name, data);

		/* Clean up data. */
		buffer_destroy(data);
	}

	/* Add some randomness to prevent caching. */
	for(i = 0; i < 4; i++)
		buffer_add_int8(name, 'a' + (rand() % 26));
	buffer_add_int8(name, '.');

	/* Add the domain. */
	buffer_add_string(name, packet->domain);

	/* Terminate with a NULL. */
	buffer_add_int8(name, 0);

	/* Convert the whole thing into a string. */
	return (char*)buffer_create_string_and_destroy(name, NULL);
}

static char *get_next_request_server(settings_t *settings, dnscat_packet_t *incoming, remote_error_t error)
{
	/* Generate the next name to send out. This is largely based on the incoming packet's values. */
	dnscat_packet_t packet;
	uint32_t flags = 0;
	char *result;

	if(error != REMOTE_ERROR_SUCCESS)
		fprintf(stderr, "Sending error: %s (%d)\n", REMOTE_ERROR(error), error);

	/* Initialize the packet to 0. */
	memset(&packet, 0, sizeof(dnscat_packet_t));

	packet.signature = incoming->signature;
	packet.domain = incoming->domain;

	if(incoming->flags & FLAG_IDENTIFIER)
	{
		packet.identifier = incoming->identifier;
		flags = flags | FLAG_IDENTIFIER;
	}

	if(incoming->flags & FLAG_SESSION)
	{
		packet.session = incoming->session;
		flags = flags | FLAG_SESSION;
	}

	if(incoming->flags & FLAG_STREAM)
	{
		packet.seq = incoming->seq;
		flags = flags | FLAG_STREAM;
	}

	if(error != REMOTE_ERROR_SUCCESS)
	{
		packet.error_code = error;
		flags = flags | FLAG_RST;
	}

	packet.flags = flags;

	if(error == REMOTE_ERROR_SUCCESS)
	{
		/* Finally, grab just the right amount of data. */
		packet.data_length = ((settings->chunk_size - 1) / 2) * settings->section_count; /* Maximum amount of data. */

		/* If we're in 'multi' mode, read data from the given session.
		 * Otherwise, read it from the NULL session. */
		packet.data = session_read(settings->sessions, incoming->session, &packet.data_length);

		/* If session_read() failed for some reason, reply with an error and delete the session. */
		if(packet.data == NULL)
		{
			fprintf(stderr, "An error occurred in session %s, closing\n", incoming->session);
			packet.error_code = REMOTE_ERROR_FIN;
			flags = flags | FLAG_RST;

			session_delete(settings->sessions, incoming->session);
		}
	}

	/* Convert the request into a dns name. */
	result = packet_to_name(settings, &packet);

	if(packet.data)
		safe_free(packet.data);

	return result;
}

static char *get_next_request_client(settings_t *settings, remote_error_t error)
{
	/* Generate the next name to send out. This is largely based on the 'settings' values. */
	dnscat_packet_t packet;
	uint32_t flags = 0;
	char *result;

	if(error != REMOTE_ERROR_SUCCESS)
		fprintf(stderr, "Sending error: %s (%d)\n", REMOTE_ERROR(error), error);

	/* Initialize the packet to 0. */
	memset(&packet, 0, sizeof(dnscat_packet_t));

	/* Set up the easy stuff. */
	packet.signature = settings->signature;
	packet.domain    = settings->domain;

	if(settings->identifier)
	{
		packet.identifier = settings->identifier;
		flags = flags | FLAG_IDENTIFIER;
	}

	if(settings->session)
	{
		packet.session = settings->session;
		flags = flags | FLAG_SESSION;
	}

	if(settings->use_stream)
	{
		packet.seq = session_get_seq(settings->sessions, settings->session);
		flags = flags | FLAG_STREAM;
	}

	if(settings->encoding == ENCODING_HEX)
		flags = flags | FLAG_HEX;

	if(error != REMOTE_ERROR_SUCCESS)
	{
		packet.error_code = error;
		flags = flags | FLAG_RST;
	}

	packet.flags = flags;

	if(error == REMOTE_ERROR_SUCCESS)
	{
		/* Finally, grab just the right amount of data. */
		packet.data_length = ((settings->chunk_size - 1) / 2) * settings->section_count; /* Maximum amount of data. */
		packet.data = session_read(settings->sessions, settings->session, &packet.data_length);

		/* If session_read() failed for some reason, print an error and die. */
		if(packet.data == NULL)
		{
			fprintf(stderr, "An error occurred in session %s, terminating\n", settings->session);
			exit(1);
		}
	}

	/* Convert the request into a dns name. */
	result = packet_to_name(settings, &packet);

	if(packet.data)
		safe_free(packet.data);

	return result;
}

/* Parse an incoming name into a dnscat_packet_t structure. Does its best to do
 * nothing but parse the name, doesn't update state or sanity check or anything
 * like that. The only sanity checks done are to make sure the packet structure
 * is correct, and that the signature matches (packets without a matching
 * signature are considered "wrong").
 *
 * Remember, the data coming into this function may be out of state or an
 * arbitrary (or even potentially malicious) connection, so be careful what you
 * update here.
 *
 * Note that the packet itself may be an "error" packet (an RST), but this
 * function will still return successfully, with the result itself will being an
 * error. */
static local_error_t parse_name(settings_t *settings, char *name_in, dnscat_packet_t **result)
{
	char              *name = safe_strdup(name_in); /* Copy the name to prevent strtok() from modifying the original. */
	buffer_t          *decoded_stream = buffer_create(BO_NETWORK); /* The data is built in here. */
	processing_state_t state = PROCESSING_STATE_SIG; /* Keep track of the state. */
	char              *piece;
#ifdef WIN32
	char              *context;
#endif

	uint32_t           count;
	size_t             i;
	local_error_t      error = LOCAL_ERROR_SUCCESS;
	buffer_t          *domain = NULL;

/*printf("Parsing name: %s\n", name_in);*/

	/* Create the result. */
	*result = (dnscat_packet_t*) safe_malloc(sizeof(dnscat_packet_t));

	/* Initialize the result to blank. */
	memset(*result, 0, sizeof(dnscat_packet_t));

	/* Loop through the name, breaking it up at the periods and updating the state as we go. */
#ifdef WIN32
	for(piece = strtok_s(name, ".", &context); piece && error == LOCAL_ERROR_SUCCESS; piece = strtok_s(NULL, ".", &context))
#else
	for(piece = strtok(name, "."); piece && error == LOCAL_ERROR_SUCCESS; piece = strtok(NULL, "."))
#endif
	{
		switch(state)
		{
			case PROCESSING_STATE_SIG:
				(*result)->signature = safe_strdup(piece);
				if(strcmp((*result)->signature, settings->signature))
					error = LOCAL_ERROR_WRONG_DOMAIN;
				state = PROCESSING_STATE_FLAGS;
			break;

			case PROCESSING_STATE_FLAGS:

				(*result)->flags = strtol(piece, NULL, 16);

				/* If we have an identifier, proceed to the identifier. */
				if((*result)->flags & FLAG_IDENTIFIER)
					state = PROCESSING_STATE_IDENTIFIER;

				/* If we have a session, proceed to the session id. */
				else if((*result)->flags & FLAG_SESSION)
					state = PROCESSING_STATE_SESSION;

				/* If we're in stream mode, go to the sequence number. */
				else if((*result)->flags & FLAG_STREAM)
					state = PROCESSING_STATE_SEQ;

				/* If we have an error, go to the error code. */
				else if((*result)->flags & FLAG_RST)
					state = PROCESSING_STATE_ERROR_CODE;

				/* If nothing else triggers, it's a normal datagram packet. Go to the field count. */
				else
					state = PROCESSING_STATE_COUNT;
			break;

			case PROCESSING_STATE_IDENTIFIER:
				(*result)->identifier = safe_strdup(piece);

				/* If we have a session, proceed to the session id. */
				if((*result)->flags & FLAG_SESSION)
					state = PROCESSING_STATE_SESSION;

				/* If we're in stream mode, go to the sequence number. */
				else if((*result)->flags & FLAG_STREAM)
					state = PROCESSING_STATE_SEQ;

				/* If we have an error, go to the error code. */
				else if((*result)->flags & FLAG_RST)
					state = PROCESSING_STATE_ERROR_CODE;

				/* If nothing else happens, it's a normal datagram packet. Go to the field count. */
				else
					state = PROCESSING_STATE_COUNT;
			break;

			case PROCESSING_STATE_SESSION:
				(*result)->session = safe_strdup(piece);

				/* If we're in stream mode, go to the sequence number. */
				if((*result)->flags & FLAG_STREAM)
					state = PROCESSING_STATE_SEQ;

				/* If we have an error, go to the error code. */
				else if((*result)->flags & FLAG_RST)
					state = PROCESSING_STATE_ERROR_CODE;

				/* If nothing else happens, it's a normal datagram packet. Go to the field count. */
				else
					state = PROCESSING_STATE_COUNT;
			break;

			case PROCESSING_STATE_SEQ:
				/* Simply process the sequence number then move onto the section count. */
				(*result)->seq = strtol(piece, NULL, 16);

				/* If it's an error, go to the error code.
				 * If it's a SYN or ACK, go to garbage.
				 * Otherwise, go to count. */
				if((*result)->flags & FLAG_RST)
					state = PROCESSING_STATE_ERROR_CODE;
				else
					state = PROCESSING_STATE_COUNT;
			break;

			case PROCESSING_STATE_COUNT:
				/* Read the count, and check if it has a value; if it's non-zero, start reading the data. */
				count = strtol(piece, NULL, 16);

				if(count)
					state = PROCESSING_STATE_DATA;
				else
					state = PROCESSING_STATE_GARBAGE;
			break;

			case PROCESSING_STATE_DATA:
				if(strlen(piece) % 2)
				{
					fprintf(stderr, "Data wasn't a multiple of 2\n");
					error = LOCAL_ERROR_INVALID;
				}
				else
				{
					/* Loop through this piece and decode. As the decode happens, add the new characters to a buffer. */
					for(i = 0; i < strlen(piece) / 2 && error == LOCAL_ERROR_SUCCESS; i++)
					{
						uint8_t ch1, ch2;
						uint8_t ch = 0;

						/* Take the next two characters in a non-case-sensitive way. Note: the 'int' typecast is to fix a warning in cygwin. */
						ch1 = tolower((int)piece[(i * 2)]);
						ch2 = tolower((int)piece[(i * 2) + 1]);

						if((*result)->flags & FLAG_HEX)
						{
							if(!isalnum(ch1) || !isalnum(ch2))
							{
								fprintf(stderr, "Invalid data in response (all characters need to be encoded as alphanumeric characters)\n");
								error = LOCAL_ERROR_INVALID;
							}
							else
							{
								ch  = ((ch1 >= 'a') ? (ch1 - 'a' + 10) : (ch1 - '0') << 4);
								ch |= ((ch2 >= 'a') ? (ch2 - 'a' + 10) : (ch2 - '0') << 0);

								buffer_add_int8(decoded_stream, ch);
							}
						}
						else
						{
							if(!isalpha(ch1) || !isalpha(ch2))
							{
								fprintf(stderr, "Invalid data in response (all characters need to be encoded as alphabetic characters)\n");
								error = LOCAL_ERROR_INVALID;
							}
							else
							{
								ch  = (ch1 - 'a') << 4;
								ch |= (ch2 - 'a');
								buffer_add_int8(decoded_stream, ch);
							}
						}
					}
				}

				/* Decrement the section count and move on if we're out of data sections. */
				count--;
				if(count == 0)
					state = PROCESSING_STATE_GARBAGE;
			break;

			case PROCESSING_STATE_ERROR_CODE:
				/* This field is only present in an RST packet. */
				(*result)->error_code = strtol(piece, NULL, 16);
				state = PROCESSING_STATE_GARBAGE;
			break;

			case PROCESSING_STATE_GARBAGE:
				/* Don't care. */
				state = PROCESSING_STATE_DOMAIN;
			break;

			case PROCESSING_STATE_DOMAIN:
				if(domain == NULL)
					domain = buffer_create(BO_NETWORK);
				else
					buffer_add_int8(domain, '.');

				buffer_add_string(domain, piece);
				/* No more state transitions - domain has to be at the end. */
			break;

			default:
				fprintf(stderr, "Entered an unknown processing state: %d\n", state);
				exit(1);
		}
	}
	/* Free the name we copied. */
	safe_free(name);

	/* If there's an error, clean up and get out. */
	if(error != LOCAL_ERROR_SUCCESS)
	{
		buffer_destroy(decoded_stream);
		if(domain)
			buffer_destroy(domain);
		if((*result)->identifier)
			safe_free((*result)->identifier);
		if((*result)->session)
			safe_free((*result)->session);
		if((*result)->signature)
			safe_free((*result)->signature);
		safe_free(*result);

		*result = NULL;
		return error;
	}

	/* Save the domain name. */
	buffer_add_int8(domain, 0);
	(*result)->domain = (char*)buffer_create_string_and_destroy(domain, NULL);

	/* Make sure we have a valid session id. */
	if(!(*result)->session)
		(*result)->session = safe_strdup("");

	/* Make sure the domain is right. */
	if(strcmp(settings->domain, "*") && strcasecmp((*result)->domain, settings->domain))
	{
		fprintf(stderr, "Incorrect domain name used; set the domain name with -d or --domain flag (currently: %s, received %s).\n", settings->domain, (*result)->domain);
		safe_free((*result)->signature);
		safe_free((*result)->domain);
		if((*result)->identifier)
			safe_free((*result)->identifier);
		if((*result)->session)
			safe_free((*result)->session);
		safe_free(*result);
		*result = NULL;
		return LOCAL_ERROR_WRONG_DOMAIN;
	}


	/* If there's a remote error, also don't bother creating the string. */
	if((*result)->flags & FLAG_RST)
	{
		buffer_destroy(decoded_stream);
		return LOCAL_ERROR_SUCCESS;
	}

	/* If life's good, create the string. */
	(*result)->data = buffer_create_string_and_destroy(decoded_stream, &(*result)->data_length);

	return LOCAL_ERROR_SUCCESS;
}

static void dns_send(settings_t *settings, char *name)
{
#if 0
	fprintf(stderr, "Sending request for %s...\n", name); /* TODO: Make this an option. */
#endif

	if(settings->built_in)
	{
		gethostbyname(name);
	}
	else
	{
		uint8_t *packet;
		uint32_t packet_length;

		/* Create the DNS request. */
		dns_t *dns = dns_create();
		dns->trn_id = rand() % 0xFFFF; /* Randomize the transaction id. */
		dns->flags  = 0x0100;

		dns_add_question(dns, name, settings->request_type, 0x0001);

		packet = dns_to_packet(dns, &packet_length);
		dns_destroy(dns);

		udp_send(settings->socket, get_dns(settings), settings->port, packet, packet_length);

		safe_free(packet);
	}
}

/* Sends the next queued request, assuming:
 * - We're a client (servers don't send requests, they respond)
 * - We aren't waiting for acknowledgement of our last request (remember, datagrams never wait)
 *
 * This should be called on a regular basis. Even if no data is waiting to be sent, this will
 * send blank requests to the server, allowing the server to send back data. It also ensures
 * that the server doesn't time out our session. */
static void try_send_queued_data(settings_t *settings, remote_error_t outgoing_error)
{
	char *name = NULL;

	/* Check if we're in the right place. */
	if(settings->is_server)
	{
		fprintf(stderr, "Server entered try_send_queued_data... something's broken!\n");
		exit(1);
	}

	/* Check if our session has gone away, and exit if it has. */
	if(!session_exists(settings->sessions, settings->session))
	{
		fprintf(stderr, "Session has went away, exiting.\n");
		exit(0);
	}

	/* Check if our session has been closed, and exit if it is. */
	if(session_is_closed(settings->sessions, settings->session))
	{
		fprintf(stderr, "Session is closed, exiting.\n");
		exit(0);
	}

	if(outgoing_error != REMOTE_ERROR_SUCCESS)
	{
		name = get_next_request_client(settings, outgoing_error);
	}
	else
	{
		/* If we're in server mode, don't bother. */
	    if(!settings->is_server && (!settings->use_stream || !settings->waiting_for_ack))
		{
			/* Get the next domain name to use, if applicable. */
			name = get_next_request_client(settings, REMOTE_ERROR_SUCCESS);
	
		}
	}

	if(name)
	{
		dns_send(settings, name);
		safe_free(name);

		if(settings->use_stream)
			settings->waiting_for_ack = TRUE;
	}

	/* Since this is a client, if an error was sent out then we're hooped. */
	if(outgoing_error != REMOTE_ERROR_SUCCESS)
		exit(0);
}

static dns_t *stage_get_response(settings_t *settings, dns_t *request)
{
	int offset;
	uint8_t data[STAGE_CHUNK_SIZE];
	size_t size;

	/* Make sure this looks like a valid stage request (the first part of the name is 2 bytes). Note: 'int' typecast is to fix a compiler warning on cygwin. */
	if(!isdigit((int)request->questions[0].name[0]) || !isdigit((int)request->questions[0].name[1]) || request->questions[0].name[2] != '.')
	{
		fprintf(stderr, "Received invalid stage name: %s\n", request->questions[0].name);
		return NULL;
	}

	/* Get the offset from the first two digits in the request name. */
	offset = atoi(request->questions[0].name) * STAGE_CHUNK_SIZE;
	fseek(settings->stage_file, offset, SEEK_SET);

	fprintf(stderr, "Received request for bytes %d - %d\n", offset, offset + STAGE_CHUNK_SIZE);
	/* Read the next chunk of the file. If the file ends, we set the appropriate flag and keep going. */
	size = fread(data, 1, STAGE_CHUNK_SIZE, settings->stage_file);
	if(size == 0)
	{
		/* Let the user know it's done. */
		fprintf(stderr, "Stager complete! Returning NXDOMAIN.\n");

		/* Return a DNS error to let the client know that we're done. */
		return dns_create_error(request->trn_id, request->questions[0]);
	}
	else
	{
		/* Create our response. */
		dns_t *response;

		/* Check if any NULL bytes exist (which will break this). */
		size_t i;
		for(i = 0; i < size; i++)
		{
			if(data[i] == '\0')
			{
				fprintf(stderr, "WARNING: Stage contains at least one NULL byte, this likely won't work if the client is a Microsoft implementation\n");
				break;
			}
		}

		response = dns_create();
		response->trn_id = request->trn_id;
		response->flags = 0x8000;

		/* Add the original question back to the response. */
		dns_add_question(response, request->questions[0].name, request->questions[0].type, request->questions[0].class);

		/* Add those bytes to the request as a TEXT response (note that at the end of the file, this will return some crap. It doesn't matter, though. */
		dns_add_answer_TEXT(response, request->questions[0].name, request->questions[0].class, 0x00000001, data, STAGE_CHUNK_SIZE);

		return response;
	}

}

/* This function is used by servers to get the next outbound request. It gets the next name, re-creates the question,
 * and adds an answer of the appropriate type. */
static dns_t *server_get_response(settings_t *settings, dns_t *request, char *response_name)
{
	dns_t *response;

	/* Start creating a DNS packet. */
	response = dns_create();
	response->trn_id = request->trn_id;
	response->flags = 0x8000;

	/* Add the original question back to the response. */
	dns_add_question(response, request->questions[0].name, request->questions[0].type, request->questions[0].class);

	/* Add an answer appropriate to the request type. */
	if(request->questions[0].type == DNS_TYPE_A)
		dns_add_answer_A(response, request->questions[0].name, request->questions[0].class, 0x00000001, "127.0.0.1");
	else if(request->questions[0].type == DNS_TYPE_NS)
		dns_add_answer_NS(response, request->questions[0].name, request->questions[0].class, 0x00000001, response_name);
	else if(request->questions[0].type == DNS_TYPE_CNAME)
		dns_add_answer_CNAME(response, request->questions[0].name, request->questions[0].class, 0x00000001, response_name);
	else if(request->questions[0].type == DNS_TYPE_MX)
		dns_add_answer_MX(response, request->questions[0].name, request->questions[0].class, 0x00000001, 0x1337, response_name);
	else if(request->questions[0].type == DNS_TYPE_TEXT)
		dns_add_answer_TEXT(response, request->questions[0].name, request->questions[0].class, 0x00000001, (uint8_t*)response_name, (uint8_t)strlen(response_name));
#ifndef WIN32
	else if(request->questions[0].type == DNS_TYPE_AAAA)
		dns_add_answer_AAAA(response, request->questions[0].name, request->questions[0].class, 0x00000001, "::1");
#endif

	return response;

}

/* Retrieves the appropriate name from the DNS packet. If it is a dnscat server, the first
 * 'question' field is used. If it is a dnscat client, the first answer field is used,
 * unless it's an A or AAAA request; in that case, NULL is returned.
 *
 * The string returned is allocated and must be freed. */
static char *get_requested_name(settings_t *settings, dns_t *dns)
{
	char *name;
	if(settings->is_server)
	{
#ifdef WIN32
		/* On Windows, we don't support IPv6 (AAAA), so it's even easier. */
		name = dns->questions[0].name;
#else
		/* Server is easy -- just take the name, unless it's IPv6 (AAAA). */
		if(dns->questions[0].type == DNS_TYPE_AAAA && !settings->AAAA)
			name = NULL;
		else
			name = dns->questions[0].name;
#endif
	}
	else
	{
		/* Client is a bit more tricky.. we have to figure out which type of DNS it is. */
		if(dns->answers[0].type == DNS_TYPE_A)
		{
			/* Do nothing. */
		}
		else if(dns->answers[0].type == DNS_TYPE_NS)
		{
			name = dns->answers[0].answer->NS.name;
		}
		else if(dns->answers[0].type == DNS_TYPE_CNAME)
		{
			name = dns->answers[0].answer->CNAME.name;
		}
		else if(dns->answers[0].type == DNS_TYPE_MX)
		{
			name = dns->answers[0].answer->MX.name;
		}
		else if(dns->answers[0].type == DNS_TYPE_TEXT)
		{
			name = (char*)dns->answers[0].answer->TEXT.text;
		}
#ifndef WIN32
		else if(dns->answers[0].type == DNS_TYPE_AAAA)
		{
			/* Do nothing. */
		}
#endif
	}

	if(name)
		return safe_strdup(name);
	else
		return NULL;
}

void display_remote_error(remote_error_t error_code, char *session)
{
	/* Print out a message for remote errors. */
	switch(error_code)
	{
		case REMOTE_ERROR_SUCCESS:
			fprintf(stderr, "ERROR: Server returned an RST packet with no error code.\n");
		break;

		case REMOTE_ERROR_BUSY:
			fprintf(stderr, "ERROR: Connection already in progress. If you recently closed a connection,\n");
			fprintf(stderr, "you may have to wait for the server to time it out. Otherwise, wait until the\n");
			fprintf(stderr, "server is free.\n");
		break;

		case REMOTE_ERROR_INVALID_IN_STATE:
			fprintf(stderr, "ERROR: Out-of-state packet received. Wait a few seconds, and try again.\n");
		break;

		case REMOTE_ERROR_FIN:
			fprintf(stderr, "Connection closed.\n");
		break;

		case REMOTE_ERROR_BAD_SEQ:
			fprintf(stderr, "ERROR: Packet's sequence number was wrong. A connection may be in progress\n");
			fprintf(stderr, "already. Wait a bit and try again.\n");
		break;

		case REMOTE_ERROR_NOT_IMPL:
			fprintf(stderr, "ERROR: Attempted to use an option that the other side hasn't implemented.\n");
		break;

		case REMOTE_ERROR_TESTING:
			fprintf(stderr, "ERROR: Test error.\n");
		break;

		case REMOTE_ERROR_4:
			fprintf(stderr, "ERROR: 4\n");
		break;
	}
}

void dnscat_feed_session(settings_t *settings, dnscat_packet_t *incoming, remote_error_t *outgoing_error)
{
	/* Check for a RST. */
	if(incoming->flags & FLAG_RST)
	{
		display_remote_error(incoming->error_code, incoming->session);
		if(settings->is_server)
		{
			/* Kill the session. */
			session_delete(settings->sessions, incoming->session);
		}
		else
		{
			/* If it's a client, just exit on a RST. */
			exit(0);
		}
	}
	else
	{
		/* At this point, we have a valid dnscat_packet_t built up. Now we pass the
		 * data down to the session and let it worry about the rest. Note that even if we have
		 * 0 bytes to send, we still want to call this because, if it's a new session, this will
		 * ensure that it's created. */
		if(settings->is_server)
		{
			if(settings->multi)
			{
				if(!session_exists(settings->sessions, incoming->session))
					session_initialize(settings->sessions, incoming->session, incoming->seq);

				session_write(settings->sessions, incoming->session, incoming->data, incoming->data_length);
			}
			else
			{
				if(session_exists(settings->sessions, incoming->session))
				{
					session_write(settings->sessions, incoming->session, incoming->data, incoming->data_length);
				}
				else
				{
					if(session_count(settings->sessions) == 0)
					{
						/* Create session. */
						session_initialize(settings->sessions, incoming->session, incoming->seq);
						session_write(settings->sessions, incoming->session, incoming->data, incoming->data_length);
					}
					else
					{
						/* Display an error. */
						*outgoing_error = REMOTE_ERROR_BUSY;
						fprintf(stderr, "Ignoring an attempted connection with session id %s\n", incoming->session);
					}
				}
			}
		}
		else
		{
			session_write(settings->sessions, settings->session, incoming->data, incoming->data_length);
		}
	}
}

/* This is the function that's called when a DNS request is received, and is really the core of everything. */
static SELECT_RESPONSE_t dns_callback(void *group, int socket, uint8_t *packet, size_t packet_length, char *addr, uint16_t port, void *s)
{
	settings_t *settings = (settings_t*) s;
	dns_t *request; 

	/* Parse the DNS packet. */
	request = dns_create_from_packet(packet, packet_length);

	/* Check if there was an error. */
	if(request->flags & 0x000F)
	{
		char *error;

		switch(request->flags & 0x000F)
		{
			case 1:  error = "format error";    break;
			case 2:  error = "server failure";  break;
			case 3:  error = "no such name";    break;
			case 4:  error = "not implemented"; break;
			case 5:  error = "refused";         break;
			default: error = "unknown";         break;
		}

		if(settings->is_server)
		{
			fprintf(stderr, "Client sent a DNS error: %s (0x%04x) -- ignoring\n", error, request->flags);
		}
		else
		{
			fprintf(stderr, "Server sent a DNS error: %s (0x%04x)\n", error, request->flags);
			exit(1);
		}
	}
	else if(request->question_count != 1)
	{
		fprintf(stderr, "Packet received with incorrect question count (%d instead of 1)\n", request->question_count);
	}
	else
	{
		/* Retrieve the name from the request. */
		char  *name = get_requested_name(settings, request);
		dns_t *response = NULL;

		/* Check if the name was a type we don't handle. */
		if(!name)
		{
			if(settings->is_server)
			{
				response = dns_create_error(request->trn_id, request->questions[0]);
			}
			else
			{
				fprintf(stderr, "Received an unknown response type\n");
				exit(1);
			}
		}
		/* Check if we're currently in stage mode.. if we are, return the next chunk of the file as a TXT record. */
		else if(request->questions[0].type == DNS_TYPE_TEXT)
		{
			if(settings->stage)
				response = stage_get_response(settings, request);
			else
				fprintf(stderr, "Warning: it looks like the client is trying to download a stage, use --stage to provide one\n");
		}
		/* Parse the request. */
		else
		{
			/* The result of parsing the packet. This will be NULL if parse_name() returns an error. */
			dnscat_packet_t *incoming;
			
			/* Parse the packet and store any errors. */
			local_error_t parse_error = parse_name(settings, name, &incoming);

			/* Check if we had any errors parsing the packet. */
			if(parse_error != LOCAL_ERROR_SUCCESS)
			{
				/* Print the error message. */
				fprintf(stderr, "Couldn't parse incoming data due to error %s\n", LOCAL_ERROR(parse_error));
				fprintf(stderr, "Name was: %s\n", name);
				
				if(settings->is_server)
				{
					response = dns_create_error(request->trn_id, request->questions[0]);
				}
				else
				{
					/* Die. */
					exit(1);
				}
			}
			else
			{
				remote_error_t outgoing_error = REMOTE_ERROR_SUCCESS;

				/* Clean up any expired sessions on a server. */
/*				if(settings->is_server)
					sessions_expire(settings->sessions, settings->timeout); */

				/* Check if the session still exists -- if it doesn't, close the connection. */
				if(session_is_closed(settings->sessions, incoming->session))
				{
					outgoing_error = REMOTE_ERROR_FIN;
				}
				else
				{
					/* Validate the sequence number if we're in stream mode. */
					if((!(incoming->flags & FLAG_STREAM)) || session_validate_seq(settings->sessions, incoming->session, incoming->seq, settings->is_server))
					{
						/* Update the session state with the new data. */
						/* Note: If the session doesn't exist, we reach this line. */
						dnscat_feed_session(settings, incoming, &outgoing_error);
	
						/* If we got a RST back, we return a FIN packet. */
						if(incoming->flags & FLAG_RST)
							outgoing_error = REMOTE_ERROR_FIN;
					}
					else
					{
						outgoing_error = REMOTE_ERROR_BAD_SEQ;
					}
				}

				/* If we're in server mode, we now have to queue up a response. */
				if(settings->is_server)
				{
					char *response_name = get_next_request_server(settings, incoming, outgoing_error);
					response = server_get_response(settings, request, response_name);
					safe_free(response_name);
				}
				else
				{
					/* If we're in client mode, we can give the go-ahead to send more data. */
					settings->waiting_for_ack = FALSE;
					if(session_data_waiting(settings->sessions, settings->session))
						try_send_queued_data(settings, outgoing_error);
				}
			}

			/* Clean up. */
			if(incoming)
			{
				if(incoming->signature)
					safe_free(incoming->signature);
				if(incoming->domain)
					safe_free(incoming->domain);
				if(incoming->identifier)
					safe_free(incoming->identifier);
				if(incoming->session)
					safe_free(incoming->session);
				if(incoming->data)
					safe_free(incoming->data);
				safe_free(incoming);
			}
		}

		if(name)
			safe_free(name);

		/* Send the response if it was set. */
		if(response)
		{
			uint8_t *packet;
			uint32_t packet_length;

			if(!settings->is_server)
				fprintf(stderr, "WARNING: trying to send a response in client mode; this doesn't make sense.\n");

			packet = dns_to_packet(response, &packet_length);
			udp_send(socket, addr, port, packet, packet_length);
			safe_free(packet);
			dns_destroy(response);
		}
	}

	/* Clean up the request. */
	dns_destroy(request);

	return SELECT_OK;
}

/* This function is called on the timeout interval, every second by default (I think).
 *
 * All it does is send queued data, if it's able to. */
static SELECT_RESPONSE_t timeout_callback(void *group, int socket, void *s)
{
	settings_t *settings = (settings_t*) s;

	if(!settings->is_server)
	{
		/* Send queued data if we have any. */
		try_send_queued_data(settings, REMOTE_ERROR_SUCCESS);
	}

	return SELECT_OK;
}

/* Set up and loop over a call to select(), forever. */
static void dns_poll(settings_t *s)
{
	int timeout_ms = s->frequency;

	/* Create the select group in 'settings' -- this is so we can free it on a signal. */
	s->select_group = select_group_create();

	/* Add the datagram socket. */
	select_group_add_socket(s->select_group, s->socket, SOCKET_TYPE_DATAGRAM, s);
	select_set_recv(s->select_group, s->socket, dns_callback);

	/* Add the timeout callback. */
	select_set_timeout(s->select_group, s->socket, timeout_callback);

	/* Create the sessions object. */
	s->sessions = sessions_initialize(s->select_group, s->multi, s->timeout);

	/* Attach either a process or stdin. */
	if(s->exec)
		sessions_attach_process(s->sessions, s->exec, !s->is_server);
	else
		sessions_attach_stdin(s->sessions);

	/* Set the exec_no_stderr if necessary. */
	if(s->exec_no_stderr)
		sessions_exec_no_stderr(s->sessions);

	/* Start up logging, if requested. */
	if(s->log_filename)
		sessions_enable_logging(s->sessions, s->log_filename);

	/* Initialize the session if we're in client mode, with a random sequence number. */
	if(!s->is_server)
		session_initialize(s->sessions, s->session, rand());

	while(1)
	{
		select_group_do_select(s->select_group, timeout_ms);
	}

	/* We never get here, but it makes me feel better. */
	select_group_destroy(s->select_group);
}

/* Clean up any allocated memory, close the socket, and send an RST packet to the
 * server if we're operating in client mode. This is the atexit() function. */
static void cleanup(void)
{
	if(global_settings)
	{
		/* If we're in stream mode and client mode, terminate the connection. */
		if(global_settings->use_stream && !global_settings->is_server)
		{
			char *name = get_next_request_client(global_settings, REMOTE_ERROR_FIN);
		
			if(name)
			{
				dns_send(global_settings, name);
				safe_free(name);
			}
		}

		if(global_settings->select_group)
			select_group_destroy(global_settings->select_group);

		if(global_settings->dns_system)
			safe_free(global_settings->dns_system);

		if(global_settings->identifier)
			safe_free(global_settings->identifier);

		if(global_settings->session)
			safe_free(global_settings->session);

		if(global_settings->log_filename)
			sessions_close_log(global_settings->sessions);

		if(global_settings->sessions)
			sessions_delete(global_settings->sessions);


		safe_free(global_settings);
		global_settings = NULL;
	}

	/* Print allocated memory. This will only run if -DTESTMEMORY is given. */
	print_memory();
}

/* Standard interrupt function. Print 'punt!', in the tradition of netcat, and exit. This exit will
 * generally call the atexit() function above, cleanup(). */
static void interrupt(int signal)
{
	fprintf(stderr, "punt!\n");

	exit(0);
}

static void usage(char *program, char *error)
{
	fprintf(stderr, NAME", by Ron Bowes <ron@skullsecurity.net>\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "dnscat is a tool designed to transfer data, similar to the old Netcat program,\n");
	fprintf(stderr, "except instead of a straight connection it uses a recursive DNS query.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Quick start\n");
	fprintf(stderr, "To start a dnscat server:\n");
	fprintf(stderr, " dnscat --listen [options]\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "To start a dnscat client:\n");
	fprintf(stderr, " dnscat --domain example.com [options]\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "For more information, please see: \n");
	fprintf(stderr, " http://www.skullsecurity.org/wiki/index.php/dnscat\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "General options\n");
	fprintf(stderr, " -d --domain <domain>\n");
	fprintf(stderr, "    The domain name to either send to or listen to. By default, servers ignore\n");
	fprintf(stderr, "    the received domain name unless you specifically set one. Clients, however,\n");
	fprintf(stderr, "    require one.\n");
	fprintf(stderr, " -e --exec <cmd>\n");
	fprintf(stderr, "    Run the given program after starting (eg. --exec /bin/sh or --exec cmd.exe).\n");
	fprintf(stderr, " --exec-no-stderr\n");
	fprintf(stderr, "    Ignore the stderr stream on the --exec program.\n");
	fprintf(stderr, " -h --help\n");
	fprintf(stderr, "    Help (this page).\n");
	fprintf(stderr, " -k --keep-root\n");
	fprintf(stderr, "    Don't drop privileges (stay as root) -- potentially dangerous. Useful if\n");
	fprintf(stderr, "    you want to run a root shell, though.\n");
	fprintf(stderr, " -l --listen\n");
	fprintf(stderr, "    Run in server mode.\n");
	fprintf(stderr, " --log <filename>\n");
	fprintf(stderr, "    Log all input/output to the given file.\n");
	fprintf(stderr, " --signature <sig>\n");
	fprintf(stderr, "    Change the dnscat signature -- both client and server require the same\n");
	fprintf(stderr, "    signature to function, meaning it acts a little like a password (or port).\n");
	fprintf(stderr, " -s --source <address>\n");
	fprintf(stderr, "    The local address to bind to. Default: any (0.0.0.0)\n");
	fprintf(stderr, " --test <domain>\n");
	fprintf(stderr, "    Test to see if we have authority for the domain we're using. Simply runs\n");
	fprintf(stderr, "    the dnstest program.\n");
#ifndef WIN32
	fprintf(stderr, " -u --username <name>\n");
	fprintf(stderr, "    If running as root, drop privileges to this user after opening socket\n");
	fprintf(stderr, "    (default: '%s').\n", DEFAULT_USER);
#endif
	fprintf(stderr, " -V --version\n");
	fprintf(stderr, "    Print the version and exit.\n");
	/* TODO: re-implement hex encoding. */
#if 0
	fprintf(stderr, " -x --hex\n");
	fprintf(stderr, "    Print output in hexadecimal format.\n");
#endif
	fprintf(stderr, "\n");
	fprintf(stderr, "Server options (use with --listen)\n");
#ifndef WIN32
	fprintf(stderr, " --AAAA\n");
	fprintf(stderr, "    Don't ignore packets with AAAA records. Creates noise on some client\n");
	fprintf(stderr, "    implementations that use both, such as Web browsers.\n");
#endif
	fprintf(stderr, " -p --port <port>\n");
	fprintf(stderr, "    The local port to listen on. I don't recommend changing this.\n");
	fprintf(stderr, "    default: %d\n", DEFAULT_PORT);
	fprintf(stderr, " --stage <file>\n");
	fprintf(stderr, "    Returns the given file as a series of TXT responses. This\n");
	fprintf(stderr, "    is designed to return shellcode in the simplest possible way.\n");
	fprintf(stderr, " --timeout <sec>\n");
	fprintf(stderr, "    The amount of time, in seconds, before an ongoing stream session is\n");
	fprintf(stderr, "    considered over. Has to be longer than the client's --frequency.\n");
	fprintf(stderr, "    Default: %d\n", DEFAULT_TIMEOUT);
	fprintf(stderr, " --multi\n");
	fprintf(stderr, "    If enabled, a server will accept sessions from multiple simultaneous\n");
	fprintf(stderr, "    clients. The session name will prefix each line, both incoming and\n");
	fprintf(stderr, "    outgoing. \n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Client options (use without --listen)\n");
	fprintf(stderr, " --built-in\n");
	fprintf(stderr, "    Use built-in DNS functions instead of building our packets from scratch.\n");
	fprintf(stderr, "    May bypass certain controls, but only allows one-way communication.\n");
	fprintf(stderr, " --datagram\n");
	fprintf(stderr, "    Operate in datagram mode instead of stream mode (faster and simpler, but\n");
	fprintf(stderr, "    doesn't guarantee order or delivery).\n");
	fprintf(stderr, " --dns <server>\n");
	fprintf(stderr, "    Set the DNS server. Not compatible with --built-in. Default: the system's\n");
	fprintf(stderr, "    first DNS server.\n");
	fprintf(stderr, " --encoding <netbios|hex>\n");
	fprintf(stderr, "    Change the encoding to NetBIOS or Hex (default: NetBIOS). Won't have a\n");
	fprintf(stderr, "    visible affect on output, but changes the traffic.\n");
	fprintf(stderr, " --frequency <ms>\n");
	fprintf(stderr, "    The frequency with which the client polls the server, in milliseconds.\n");
	fprintf(stderr, "    Has to be shorter than the server's --timeout to for stream sessions.\n");
	fprintf(stderr, "    Default: %d.\n", DEFAULT_FREQUENCY);
	fprintf(stderr, " -t --type <NS|CNAME|MX|TEXT|A|AAAA>\n");
	fprintf(stderr, "    The type of DNS request. Supported: NS, CNAME, MX, and TEXT. A and AAAA\n");
	fprintf(stderr, "    can also be used, but require --datagram and are limited to one-way. AAAA\n");
	fprintf(stderr, "    won't work on Windows.\n");
	fprintf(stderr, " -p --port\n");
	fprintf(stderr, "    The port to send the DNS requests to. You'll typically want the\n");
	fprintf(stderr, "    default: %d.\n", DEFAULT_PORT);
	fprintf(stderr, " --session <sessionid>\n");
	fprintf(stderr, "    Force a particular session id. Default: random.\n");
	fprintf(stderr, " --identifier <identifier>\n");
	fprintf(stderr, "    If set, dnscat will include an 'identifier' field, which is a way of telling\n");
	fprintf(stderr, "    a dnscat server where a connection came from (for multiplexing). The official\n");
	fprintf(stderr, "    dnscat server simply ignores this field, but other servers (like Metasploit)\n");
	fprintf(stderr, "    use this id to learn where connections came from.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Advanced options (probably shouldn't fiddle with these)\n");
	fprintf(stderr, " --chunksize <sz>\n");
	fprintf(stderr, "    The size of the data sections in the packet, after encoding. DNS servers\n");
	fprintf(stderr, "    only allow 64 bytes/section, including the terminator.\n");
	fprintf(stderr, "    Default: %d.\n", DEFAULT_CHUNK_SIZE);
	fprintf(stderr, " --sections <num>\n");
	fprintf(stderr, "    The maximum number of data sections in the packet. The size of the\n");
	fprintf(stderr, "    sections is determined by --chunksize. Too many sections and the packet\n");
	fprintf(stderr, "    will be too large and will fail. Default: %d.\n", DEFAULT_SECTION_COUNT);
	fprintf(stderr, " --no-session\n");
	fprintf(stderr, "    Don't generate or include a sessionid in packets. This is designed\n");
	fprintf(stderr, "    for debugging. Client only.");
#if TEST
	fprintf(stderr, "\n");
	fprintf(stderr, "Testing options\n");
	fprintf(stderr, " --test-errors\n");
	fprintf(stderr, "    If set, the server will always return an RST packet with\n");
	fprintf(stderr, "    REMOTE_ERROR_TESTING.\n");
#endif
	fprintf(stderr, "\n");
	if(error)
		fprintf(stderr, "ERROR: %s\n", error);
	fprintf(stderr, "\n");

	exit(1);
}

static void version()
{
	fprintf(stderr, "%s is part of %s\n", NAME, NBTOOL_NAME_VERSION);
	exit(0);
}

int main(int argc, char *argv[])
{
	settings_t *s = safe_malloc(sizeof(settings_t));
	char        c;
	int         option_index;
	const char *option_name;

	/* Build the long-options array for parsing the options. */
	struct option long_options[] =
	{
		/* General options. */
		{"domain",         required_argument, 0, 0}, /* Domain name. */
		{"d",              required_argument, 0, 0},
		{"exec",           required_argument, 0, 0}, /* Execute command. */
		{"exec-no-stderr", no_argument,       0, 0}, /* Execute command has no stderr. */
		{"e",              required_argument, 0, 0},
		{"help",           no_argument,       0, 0}, /* Help. */
		{"h",              no_argument,       0, 0},
		{"H",              no_argument,       0, 0},
		{"keep-root",      no_argument,       0, 0}, /* Keep root. */
		{"k",              no_argument,       0, 0},
		{"listen",         no_argument,       0, 0}, /* Listen. */
		{"l",              no_argument,       0, 0},
		{"log",            required_argument, 0, 0}, /* Log. */
		{"port",           required_argument, 0, 0}, /* Local or remote port. */
		{"p",              required_argument, 0, 0},
		{"signature",      required_argument, 0, 0}, /* Packet signature. */
		{"sig",            required_argument, 0, 0},
		{"source",         required_argument, 0, 0}, /* Local source address */
		{"s",              required_argument, 0, 0},
		{"test",           required_argument, 0, 0}, /* Test if we have domain authority. */
#ifndef WIN32
		{"username",       required_argument, 0, 0}, /* Username (for dropping privileges). */
#endif
		{"version",        no_argument,       0, 0}, /* Version. */
		{"V",              no_argument,       0, 0},
#if 0
		{"hex",            no_argument,       0, 0}, /* Hexadecimal output. */
		{"x",              no_argument,       0, 0},
#endif

		/* Server options. */
#ifndef WIN32
		{"AAAA",      no_argument,       0, 0}, /* Display AAAA responses. */
		{"aaaa",      no_argument,       0, 0},
#endif
		{"multi",     no_argument,       0, 0}, /* Multiple sessions. */
		{"stage",     required_argument, 0, 0}, /* Staged file. */
		{"timeout",   required_argument, 0, 0}, /* Timeout before state resets. */
		{"u",         required_argument, 0, 0},

		/* Client options. */
		{"built-in",  no_argument,       0, 0}, /* Use built-in DNS functions. */
		{"datagram",  no_argument,       0, 0}, /* Datagram. */
		{"dns",       required_argument, 0, 0}, /* DNS server. */
		{"encoding",  required_argument, 0, 0}, /* Encoding. */
		{"frequency", required_argument, 0, 0}, /* Frequency, in milliseconds. */
		{"identifier",required_argument, 0, 0}, /* Identifier. */
		{"session",   required_argument, 0, 0}, /* Session id. */
		{"type",      required_argument, 0, 0}, /* Packet type. */
		{"t",         required_argument, 0, 0},

		/* Advanced options. */
		{"chunksize", required_argument, 0, 0}, /* Chunk size. */
		{"sections",  required_argument, 0, 0}, /* Section count. */
		{"no-session",no_argument,       0, 0}, /* No session. */

#if TEST
		/* Testing options. */
		{"test-errors", no_argument,     0, 0}, /* Test errors. */
#endif

		{0, 0, 0, 0}
	};

	/* Initialize Winsock. */
	winsock_initialize();

	/* Get ready to randomize. */
	srand((int)time(NULL));

	/* Clear the settings. */
	memset(s, sizeof(s), 0);

	/* Set some defaults. */
	s->chunk_size    = DEFAULT_CHUNK_SIZE;
	s->section_count = DEFAULT_SECTION_COUNT;
	s->signature     = DEFAULT_SIGNATURE;
	s->request_type  = DNS_TYPE_CNAME;
	s->use_stream    = DEFAULT_USE_STREAM;
	s->user          = DEFAULT_USER;
	s->domain        = DEFAULT_DOMAIN_NAME;
	s->frequency     = DEFAULT_FREQUENCY;
	s->timeout       = DEFAULT_TIMEOUT;
	s->port          = DEFAULT_PORT;
	s->source        = DEFAULT_SOURCE_ADDR;

	/* Parse the command line options. */
	opterr = 0;
	while((c = getopt_long_only(argc, argv, "", long_options, &option_index)) != EOF)
	{
		switch(c)
		{
			case 0:
				option_name = long_options[option_index].name;

				/* General options. */
				if(!strcmp(option_name, "domain") || !strcmp(option_name, "d"))
				{
					s->domain = optarg;
				}
				else if(!strcmp(option_name, "exec") || !strcmp(option_name, "e"))
				{
					s->exec = optarg;
				}
				else if(!strcmp(option_name, "exec-no-stderr"))
				{
					s->exec_no_stderr = TRUE;
				}
				else if(!strcmp(option_name, "help") || !strcmp(option_name, "h") || !strcmp(option_name, "H"))
				{
					usage(argv[0], NULL);
				}
				else if(!strcmp(option_name, "keep-root") || !strcmp(option_name, "k"))
				{
					s->keep_root = TRUE;
				}
				else if(!strcmp(option_name, "listen") || !strcmp(option_name, "l"))
				{
					s->is_server = TRUE;
				}
				else if(!strcmp(option_name, "log"))
				{
					s->log_filename = optarg;
				}
				else if(!strcmp(option_name, "port") || !strcmp(option_name, "p"))
				{
					s->port = atoi(optarg);
				}
				else if(!strcmp(option_name, "signature") || !strcmp(option_name, "sig"))
				{
					s->signature = optarg;
				}
				else if(!strcmp(option_name, "test"))
				{
					dns_do_test(optarg); /* Doesn't return. */
				}
#ifndef WIN32
				else if(!strcmp(option_name, "username") || !strcmp(option_name, "u"))
				{
					s->user = optarg;
					if(!strcasecmp(optarg, "root"))
						s->keep_root = TRUE;
				}
#endif
				else if(!strcmp(option_name, "version") || !strcmp(option_name, "V"))
				{
					version();
				}
#if 0
				else if(!strcmp(option_name, "hex") || !strcmp(option_name, "x"))
				{
					s->hex = TRUE;
				}
#endif
				/* Server options. */
#ifndef WIN32
				else if(!strcmp(option_name, "aaaa") || !strcmp(option_name, "AAAA"))
				{
					s->AAAA = TRUE;
				}
#endif
				else if(!strcmp(option_name, "multi"))
				{
					s->multi = TRUE;
				}
				else if(!strcmp(option_name, "source") || !strcmp(option_name, "s"))
				{
					s->source = optarg;
				}
				else if(!strcmp(option_name, "stage"))
				{
					s->stage = optarg;
				}
				else if(!strcmp(option_name, "timeout"))
				{
					s->timeout = atoi(optarg);
				}

				/* Client options. */
				else if(!strcmp(option_name, "built-in"))
				{
					s->built_in = TRUE;
				}
				else if(!strcmp(option_name, "datagram"))
				{
					s->use_stream = FALSE;
				}
				else if(!strcmp(option_name, "encoding"))
				{
					if(!strcasecmp(optarg, "netbios"))
						s->encoding = ENCODING_NETBIOS;
					else if(!strcasecmp(optarg, "hex"))
						s->encoding = ENCODING_HEX;
					else
						usage(argv[0], "Invalid encoding type");
				}
				else if(!strcmp(option_name, "frequency"))
				{
					s->frequency = atoi(optarg);
				}
				else if(!strcmp(option_name, "dns"))
				{
					s->dns_user = optarg;
				}
				else if(!strcmp(option_name, "identifier"))
				{
					s->identifier = safe_strdup(optarg);
				}
				else if(!strcmp(option_name, "session"))
				{
					s->session = safe_strdup(optarg);
				}
				else if(!strcmp(option_name, "type") || !strcmp(option_name, "t"))
				{
					if(!strcasecmp(optarg, "A"))           { s->request_type = DNS_TYPE_A; }
					else if(!strcasecmp(optarg, "NS"))     { s->request_type = DNS_TYPE_NS; }
					else if(!strcasecmp(optarg, "CNAME"))  { s->request_type = DNS_TYPE_CNAME; }
					else if(!strcasecmp(optarg, "MX"))     { s->request_type = DNS_TYPE_MX; }
					else if(!strcasecmp(optarg, "TEXT"))   { s->request_type = DNS_TYPE_TEXT; }
#ifndef WIN32
					else if(!strcasecmp(optarg, "AAAA"))   { s->request_type = DNS_TYPE_AAAA; s->AAAA = TRUE; }
#endif
					else
					{
						fprintf(stderr, "Invalid request type: %s\n", optarg);
						usage(argv[0], "Invalid argument for --type");
					}
				}

				/* Advanced options. */
				else if(!strcmp(option_name, "chunksize"))
				{
					s->chunk_size = atoi(optarg);
				}
				else if(!strcmp(option_name, "sections"))
				{
					s->section_count = atoi(optarg);
				}
				else if(!strcmp(option_name, "no-session"))
				{
					s->no_session = TRUE;
				}
#if TEST
				/* Test options. */
				else if(!strcmp(option_name, "test-errors"))
				{
					s->test_errors = TRUE;
				}
#endif
			break;

			case '?':
			default:
				usage(argv[0], "Couldn't parse arguments");
			break;
		}
	}

	/* Sanity checks. */
	if(!s->is_server && !strcmp(s->domain, DEFAULT_DOMAIN_NAME) && s->dns_user == NULL)
		usage(argv[0], "Either --listen (for server mode) or --domain/--dns (for client mode) is required.");

	if(s->is_server && s->built_in)
		usage(argv[0], "--listen and --built-in are not compatible.\n");

	if(!s->is_server && s->stage)
		usage(argv[0], "--stage requires --listen mode.\n");

	if(!s->is_server && s->multi)
		usage(argv[0], "--multi requires --listen mode.\n");

	if(s->is_server && s->request_type != DEFAULT_REQUEST_TYPE)
		usage(argv[0], "--listen and --type are not compatible -- client chooses request type.");

	if(s->is_server && s->session)
		usage(argv[0], "--listen and --session are not compatible.");

	if(s->is_server && s->no_session)
		usage(argv[0], "--listen and --no-session are not compatible.");

	if(s->is_server && s->identifier)
		usage(argv[0], "--listen and --identifier are not compatible.");

	if(!s->use_stream && s->is_server)
		usage(argv[0], "--listen and --datagram are not compatible -- client chooses the request type.");

#ifdef WIN32
	if(s->use_stream && s->request_type == DNS_TYPE_A)
		usage(argv[0], "A requests can only be used with --datagram, they aren't capable of stream connections.");
#else
	if(s->use_stream && (s->request_type == DNS_TYPE_A || s->request_type == DNS_TYPE_AAAA))
		usage(argv[0], "A and AAAA requests can only be used with --datagram, they aren't capable of stream connections.");
#endif

	if(s->use_stream && s->built_in)
		usage(argv[0], "--built-in can only be used with --datagram, they aren't capable of stream connections.");

	if(s->dns_user && s->built_in)
		usage(argv[0], "--build-in and --dns are incompatible; --built-in has to use the system DNS servers.");

	if(s->timeout != DEFAULT_TIMEOUT && !s->is_server)
		usage(argv[0], "--timeout can only be used on servers.");

#if 0
	if(s->hex && s->exec)
		usage(argv[0], "--hex and --exec are not compatible.");
#endif

	if(!s->exec && s->exec_no_stderr)
		usage(argv[0], "--exec-no-stderr doesn't make sense without --exec.");

#ifndef WIN32
	/* Check for the root user. */
	if(s->is_server && getuid() != 0)
		fprintf(stderr, "WARNING: If the bind() fails, please re-run as root (privileges will be dropped as soon as the socket is created).\n");
#endif

	/* If it's a server, listen on port 53; otherwise, we don't care which port. */
	if(s->is_server)
		s->socket = udp_create_socket(s->port, s->source);
	else
		s->socket = udp_create_socket(0, s->source);

#ifndef WIN32
	/* Drop privileges if we have them. */
	if(getuid() == 0)
	{
		if(s->keep_root)
			fprintf(stderr, "Keeping root privileges.\n");
		else
			drop_privileges(s->user);
	}
#endif

	/* Set the global settings -- this lets us clean up when a signal is caught. */
	global_settings = s;

	/* If we're a client, set up the DNS server. */
	if(!s->is_server && !s->dns_user)
		s->dns_system = dns_get_system();

	/* Make sure we have a dns server of some sort. */
	if(!s->is_server && get_dns(s) == NULL)
	{
		fprintf(stderr, "ERROR: Couldn't find any DNS servers to use; please specify one with --dns\n");
		exit(1);
	}

	/* Do any special client setup. */
	if(!s->is_server)
	{
		/* On clients, we don't want to time out ever. */
		s->timeout = 0xFFFFFFFF;

		/* If the user didn't want a session, we're going to pick a name anyways (just a blank one). */
		if(s->no_session)
			s->session = safe_strdup("");

		/* Only generate a session id if the user hasn't already set one. */
		if(!s->session)
		{
			uint32_t i;
			buffer_t *session = buffer_create(BO_NETWORK);

			for(i = 0; i < 8; i++)
				buffer_add_int8(session, 'a' + (rand() % 26));
			buffer_add_int8(session, 0); /* Null termination. */
			s->session = (char*)buffer_create_string_and_destroy(session, NULL);
		}
	}

	/* If the user provided a DNS server but not a name, use a static name. */
	if(s->dns_user && !strcmp(s->domain, DEFAULT_DOMAIN_NAME))
		s->domain = "directdns";

	/* Open the stage file. */
	if(s->stage)
	{
#ifdef WIN32
		if(fopen_s(&s->stage_file, s->stage, "rb"))
			nbdie("dnscat: couldn't open the stage file for reading");
#else
		if(!(s->stage_file = fopen(s->stage, "rb")))
			nbdie("Couldn't open the stage file for reading");
#endif
	}

	/* Print a start-up message. */
	if(s->is_server)
		fprintf(stderr, "Waiting for DNS requests for domain '%s' on %s:%d...\n", s->domain, s->source, s->port);
	else
		fprintf(stderr, "Starting DNS requests to domain '%s' %s:%d...\n", s->domain, get_dns(s), s->port);

	/* Catch SIGINT. Note that we don't set up signal/exit handlers till we're finished the startup. */
	signal(SIGINT, interrupt);

	/* Set the atexit() function. */
	atexit(cleanup);

	dns_poll(s);

	return 0;
}
