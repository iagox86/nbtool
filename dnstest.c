/* dnstest.c
 * By Ron Bowes
 * Created January, 2010
 *
 * (See LICENSE.txt)
 *
 *==Intro==
 * This program simply checks whether or not you have the authoritative
 * nameserver for a given domain. It is implicitly called by the other
 * dns* programs I've written, all it does is look up a random subdomain
 * and see if the response comes back.
 *
 *==Usage==
 *<pre>
 * ./dnstest --domain <domain>
 * 
 *  -h --help
 *     Help (this page).
 *  -d --domain <domain>
 *     The domain name to check. The lookup will be for [random].domain.
 *  --dns <server>
 *     Set the DNS server. Default: the system's first DNS server.
 *  -s --source <address>
 *     The local address to bind to. Default: any (0.0.0.0)
 *  -p --port <port>
 *     The local port to listen on. I don't recommend changing this.
 *     default: 53.
 *  --rport <port>
 *     The port to send the request to. Default: 53.
 *  -u --username
 *     Drop privileges to this user after opening socket (default: 'nobody')
 *  -V --version
 *     Print the version and exit
 *</pre>
 *
 *==Example==
 * There isn't really much to this program, but here's how it looks
 * running on my laptop (which is the authoritative server for 
 * skullseclabs.org):
 *<pre>
 * $ sudo ./dnstest --domain skullseclabs.org
 * Listening for requests on 0.0.0.0:53
 * Sending request to 208.81.7.10:53
 * Trying to look up domain: avobwnjlopakgmdt.skullseclabs.org
 * Received a response: avobwnjlopakgmdt.skullseclabs.org
 * Contgratulations, you have the proper DNS server for this domain!
 *</pre>
 */

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef WIN32
#include <winsock2.h>
#else
#include <netdb.h>
#include <strings.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#endif

#include "buffer.h"
#include "dns.h"
#include "memory.h"
#include "my_getopt.h"
#include "select_group.h"
#include "tcp.h"
#include "types.h"
#include "udp.h"

#define NAME "dnstest"

typedef struct
{
	int client_socket;
	int server_socket;
	select_group_t *select_group;
	char *user;
	char *test_name;
	char *domain_name;
	char *source;
	int   port;
	int   rport;

	/* The DNS server. */
	char *dns_system;
	char *dns_user;
} settings_t;

/* We need this for catching signals. */
settings_t *global_settings = NULL;

static SELECT_RESPONSE_t dns_callback(void *group, int socket, uint8_t *packet, size_t packet_length, char *addr, uint16_t port, void *s)
{
	NBBOOL     done = FALSE;
	settings_t *settings = (settings_t*) s;
	uint8_t    *response_packet;
	uint32_t    response_packet_length;

	/* Parse the DNS packet. */
	dns_t *request  = dns_create_from_packet(packet, packet_length);

	if(request->question_count == 1)
	{
		fprintf(stderr, "Received a response: %s\n", request->questions[0].name);

		if(!strcmp(request->questions[0].name, settings->test_name))
		{
			printf("Contgratulations, you have the proper DNS server for this domain!\n");
			done = TRUE;
		}
	}

	/* Send back the response. */
	response_packet = dns_create_error_string(request->trn_id, request->questions[0], &response_packet_length);
	udp_send(socket, addr, port, response_packet, response_packet_length);

	/* Delete the response. */
	safe_free(response_packet);

	/* Delete the request. */
	dns_destroy(request);

	/* If we're finished, exit. */
	if(done)
		exit(0);

	return SELECT_OK;
}

static SELECT_RESPONSE_t timeout_callback(void *group, int socket, void *s)
{
	settings_t *settings = (settings_t *) s;
	printf("You don't appear to be the authority for the domain: %s\n", settings->domain_name);

	exit(0);

	return SELECT_OK;
}

static void dns_poll(settings_t *s)
{
	/* Create the select group in 'settings' -- this is so we can free it on a signal. */
	s->select_group = select_group_create();

	/* Add the server socket. */
	select_group_add_socket(s->select_group, s->server_socket, SOCKET_TYPE_DATAGRAM, s);
	select_set_recv(s->select_group, s->server_socket, dns_callback);

	/* After a certain amount of time, we're going to give up. */
	select_set_timeout(s->select_group, s->server_socket, timeout_callback);

	while(1)
		select_group_do_select(s->select_group, 5000); /* 5-second timeout. */

	select_group_destroy(s->select_group); /* Note: we don't get here. */
}

static char *create_test_domain(char *domain)
{
	buffer_t *buffer = buffer_create(BO_NETWORK);
	int i;

	for(i = 0; i < 16; i++)
		buffer_add_int8(buffer, 'a' + (char)(rand() % 26));
	buffer_add_int8(buffer, '.');
	buffer_add_ntstring(buffer, domain);

	return (char*)buffer_create_string_and_destroy(buffer, NULL);
}

static char *get_dns(settings_t *settings)
{
	if(settings->dns_user)
		return settings->dns_user;
	return settings->dns_system;
}

static void send_test_request(settings_t *settings)
{
	uint8_t *packet;
	uint32_t packet_length;

	/* Create the DNS request. */
	dns_t *dns = dns_create();
	dns->trn_id = 0x1234;
	dns->flags  = 0x0100;

	dns_add_question(dns, settings->test_name, DNS_TYPE_CNAME, 0x0001);

	packet = dns_to_packet(dns, &packet_length);
	dns_destroy(dns);

	udp_send(settings->client_socket, get_dns(settings), settings->rport, packet, packet_length);

	safe_free(packet);
}

void cleanup(void)
{
	if(global_settings)
	{
		/* Free memory. */
		if(global_settings->select_group)
			select_group_destroy(global_settings->select_group);

		if(global_settings->test_name)
			safe_free(global_settings->test_name);

		if(global_settings->dns_system)
			safe_free(global_settings->dns_system);

		safe_free(global_settings);
	}

	/* Print allocated memory. This will only run if -DTESTMEMORY is given. */
	print_memory();
}

void interrupt(int signal)
{
	/* Note: exiting like this will call the atexit() function, cleanup(). */
	fprintf(stderr, "punt!\n");
	exit(0);
}


static void usage(char *program, char *message)
{
	fprintf(stderr, NAME", by Ron Bowes <ron@skullsecurity.net>\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "%s --domain <domain>\n", program);
	fprintf(stderr, "\n");
	fprintf(stderr, " -h --help\n");
	fprintf(stderr, "    Help (this page).\n");
	fprintf(stderr, " -d --domain <domain>\n");
	fprintf(stderr, "    The domain name to check. The lookup will be for [random].domain.\n");
	fprintf(stderr, " --dns <server>\n");
	fprintf(stderr, "    Set the DNS server. Default: the system's first DNS server.\n");
	fprintf(stderr, " -s --source <address>\n");
	fprintf(stderr, "    The local address to bind to. Default: any (0.0.0.0)\n");
	fprintf(stderr, " -p --port <port>\n");
	fprintf(stderr, "    The local port to listen on. I don't recommend changing this.\n");
	fprintf(stderr, "    default: 53.\n");
	fprintf(stderr, " --rport <port>\n");
	fprintf(stderr, "    The port to send the request to. Default: 53.\n");
	fprintf(stderr, " -u --username\n");
	fprintf(stderr, "    Drop privileges to this user after opening socket (default: 'nobody')\n");
	fprintf(stderr, " -V --version\n");
	fprintf(stderr, "    Print the version and exit\n");
	fprintf(stderr, "\n");
	if(message)
	{
		fprintf(stderr, "%s\n", message);
	}

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
		{"domain",    required_argument, 0, 0}, /* Domain name. */
		{"d",         required_argument, 0, 0},
		{"dns",       required_argument, 0, 0}, /* DNS server. */
		{"help",      no_argument,       0, 0}, /* Help. */
		{"h",         no_argument,       0, 0},
		{"H",         no_argument,       0, 0},
		{"port",      required_argument, 0, 0}, /* Local port. */
		{"p",         required_argument, 0, 0},
		{"rport",     required_argument, 0, 0}, /* Remote port. */
		{"source",    required_argument, 0, 0}, /* Source. */
		{"s",         required_argument, 0, 0},
		{"username",  required_argument, 0, 0}, /* Username (for dropping privileges). */
		{"u",         required_argument, 0, 0},
		{"version",   no_argument,       0, 0}, /* Version. */
		{"V",         no_argument,       0, 0},

		{0, 0, 0, 0}
	};

	/* Initialize Winsock. */
	winsock_initialize();

	/* Get ready to randomize. */
	srand((unsigned int)time(NULL));

	/* Clear the settings. */
	memset(s, sizeof(s), 0);

	/* Set some defaults. */
	s->user          = "nobody";
	s->port          = 53;
	s->rport         = 53;
	s->source        = "0.0.0.0";

	/* Catch SIGINT. */
	signal(SIGINT, interrupt);

	/* Catch all exit events. */
	atexit(cleanup);

	/* Parse the commandline options. */
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
					s->domain_name = optarg;
				}
				else if(!strcmp(option_name, "dns"))
				{
					s->dns_user = optarg;
				}
				else if(!strcmp(option_name, "help") || !strcmp(option_name, "h") || !strcmp(option_name, "H"))
				{
					usage(argv[0], NULL);
				}
				else if(!strcmp(option_name, "port") || !strcmp(option_name, "p"))
				{
					s->port = atoi(optarg);
				}
				else if(!strcmp(option_name, "rport"))
				{
					s->rport = atoi(optarg);
				}
				else if(!strcmp(option_name, "source") || !strcmp(option_name, "s"))
				{
					s->source = optarg;
				}
				else if(!strcmp(option_name, "username") || !strcmp(option_name, "u"))
				{
					s->user = optarg;
				}
				else if(!strcmp(option_name, "version") || !strcmp(option_name, "V"))
				{
					version();
				}
			break;

			case '?':
			default:
				fprintf(stderr, "Couldn't parse arguments\n\n");
				usage(argv[0], NULL);
			break;
		}
	}

	if(!s->domain_name)
	{
		usage(argv[0], "--domain is a required parameter");
	}

#ifndef WIN32
	/* Check for the root user. */
	if(getuid() != 0)
	{
		fprintf(stderr, "WARNING: If the bind() fails, please re-run as root (privileges will be dropped as soon as the socket is created).\n");
	}
#endif

	/* Create a socket. */
	s->client_socket = udp_create_socket(0, s->source);
	s->server_socket = udp_create_socket(s->port, s->source);

	/* Drop privileges. */
	drop_privileges(s->user);

	/* If we're a client, set up the DNS server. */
	if(!s->dns_user)
		s->dns_system = dns_get_system();

	/* Display what we're doing. */
	fprintf(stderr, "Listening for requests on %s:%d\n", s->source, s->port);
	fprintf(stderr, "Sending request to %s:%d\n", get_dns(s), s->rport);

	/* Set the global settings -- this lets us clean up when a signal is caught. */
	global_settings = s;

	/* Create the request. */
	s->test_name = create_test_domain(s->domain_name);
	fprintf(stderr, "Trying to look up domain: %s\n", s->test_name);

	/* Send the request. */
	send_test_request(s);

	/* Poll until we get the response. */
	dns_poll(s);

	return 0;
}

