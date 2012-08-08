/* smbtest.c
 * By Ron
 * Created September 1, 2008
 *
 * (See LICENSE.txt)
 *
 * Test out the SMB interface.
 */

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "select_group.h"
#include "smbclient.h"
#include "types.h"

typedef struct
{
	char       *host;
	uint16_t    port;
	char       *netbios_name;

	SMB_LOGONTYPE_t logon;
	char       *domain;
	char       *username;
	char       *password;
	char       *hash;
	int         check_signature;
} SETTINGS_t;



static SETTINGS_t settings;
static select_group_t *sg;

/*#define SAMR_TEST*/
#define SRVSVC_TEST
SMBCLIENT_RESULT_t event_callback(void *client, SMBCLIENT_EVENT_t event, void *extra)
{
	size_t i;

	switch(event)
	{
		case SMBCLIENT_CONNECTED:

			/* Remember the port that was used. */
			settings.port = (uint32_t)extra;

			printf("Connection to %s:%d established!\n", settings.host, settings.port);

			if(((int)extra) == 139)
			{
				if(settings.netbios_name)
				{
					printf("* Attempting to start NetBIOS session on port 139...\n");
					smbclient_netbios_start_session((SMBCLIENT_t*)client, settings.netbios_name);
				}
				else
				{
					fprintf(stderr, "Tried to connect on port 139 without the NetBIOS name!\n"); /* TODO: Get it. */
					exit(1);
				}
			}
			else
			{
				printf("* Negotiating protocol version...\n");
				smbclient_negotiate_protocol((SMBCLIENT_t*)client);
			}

		break;

		case SMBCLIENT_NETBIOS_SESSION_SET_UP:
			printf("NetBIOS session set up.\n");
			printf("* Negotiating protocol version...\n");
			smbclient_negotiate_protocol((SMBCLIENT_t*)client);
		break;

		case SMBCLIENT_PROTOCOL_NEGOTIATED:
			printf("Protocol successfully negotiated!\n");
			printf("* Attempting to establish SMB session as %s\\%s...\n", settings.domain, settings.username);

			smbclient_logon((SMBCLIENT_t*)client, settings.domain, settings.username, settings.password, settings.hash, settings.logon);
		break;

		case SMBCLIENT_SESSION_SET_UP:
			printf("Session created successfully as %s\\%s\n", settings.domain, settings.username);
			printf("* Attempting to connect to IPC$ share...\n");
			smbclient_tree_connect((SMBCLIENT_t*)client, "\\\\192.168.241.128\\IPC$");
		break;

		case SMBCLIENT_SESSION_SET_UP_GUEST:
			printf("Account %s\\%s wasn't found, logged in as GUEST instead\n", settings.domain, settings.username);
			printf("* Attempting to connect to IPC$ share...\n");
			smbclient_tree_connect((SMBCLIENT_t*)client, "\\\\192.168.241.128\\IPC$");
		break;

		case SMBCLIENT_TREE_CONNECTED:
			printf("Tree successfully connected\n");
			printf("* Attempting to create file.\n");
#ifdef SAMR_TEST
			smbclient_nt_create((SMBCLIENT_t*)client, SAMR_PATH);
#endif
#ifdef SRVSVC_TEST
			smbclient_nt_create((SMBCLIENT_t*)client, SRVSVC_PATH);
#endif
		break;

		case SMBCLIENT_TREE_DISCONNECTED:
			printf("Tree successfully disconnected\n");
			printf("* Attempting to log off\n");
			smbclient_logoff((SMBCLIENT_t*)client);
		break;

		case SMBCLIENT_FILE_CREATED:
			printf("File created\n");
#ifdef SAMR_TEST
			smbclient_msrpc_bind((SMBCLIENT_t*)client, SAMR_UUID, SAMR_VERSION, NULL);
#endif
#ifdef SRVSVC_TEST
			smbclient_msrpc_bind((SMBCLIENT_t*)client, SRVSVC_UUID, SRVSVC_VERSION, NULL);
#endif
		break;

		case SMBCLIENT_MSRPC_BIND_ACK:
			printf("Bound to MSRPC service: %s\n", ((SMBCLIENT_t*)client)->service);
#ifdef SAMR_TEST
			printf("* Sending connect4() call\n");
			smbclient_send_samr_connect4((SMBCLIENT_t*)client);
#endif
#ifdef SRVSVC_TEST
			printf("* Sending netshareenumall() call\n");
			smbclient_send_srvsvc_netshareenumall((SMBCLIENT_t*)client);
#endif
		break;

		case SMBCLIENT_MSRPC_BIND_FAILED:
			printf("Failed to bind to MSRPC service: %s\n", ((SMBCLIENT_t*)client)->service);
		break;

		case SMBCLIENT_MSRPC_NETSHAREENUMALL:
			printf("Received netshareenumall() response: ");
			for(i = 0; i < ((NETSHAREENUMALL_t*)extra)->name_count; i++)
				printf("%s, ", ((NETSHAREENUMALL_t*)extra)->names[i]);
			printf("\n");
		break;

		case SMBCLIENT_MSRPC_CONNECT4:
			printf("Received connect4() response; connect_handle = ");
			for(i = 0; i < 0x14; i++)
				printf("%02x", ((CONNECT4_t*)extra)->connect_handle[i]);
			printf("\n");

			printf("* Sending enumdomains() request\n");
			smbclient_send_samr_enumdomains((SMBCLIENT_t*)client);
		break;

		case SMBCLIENT_MSRPC_ENUMDOMAINS:
			printf("Received enumdomains() response: ");
			for(i = 0; i < ((ENUMDOMAINS_t*)extra)->name_count; i++)
				printf("%s, ", ((ENUMDOMAINS_t*)extra)->names[i]);
			printf("\n");

			printf("* Sending lookupdomain(\"%s\")\n", ((ENUMDOMAINS_t*)extra)->names[0]);
			smbclient_send_samr_lookupdomain((SMBCLIENT_t*)client, ((ENUMDOMAINS_t*)extra)->names[0]);
		break;

		case SMBCLIENT_MSRPC_LOOKUPDOMAIN:
		{
			LOOKUPDOMAIN_t *lookupdomain = (LOOKUPDOMAIN_t*) extra;

			printf("Received lookupdomain() response: S-%u-%u", lookupdomain->revision, lookupdomain->authority);
			for(i = 0; i < lookupdomain->count; i++)
				printf("-%u", lookupdomain->subauthority[i]);
			printf("\n");

			printf("* Sending opendomain()\n");
			smbclient_send_samr_opendomain((SMBCLIENT_t*)client);
		}
		break;

		case SMBCLIENT_MSRPC_OPENDOMAIN:
		{
			OPENDOMAIN_t *opendomain = (OPENDOMAIN_t*) extra;

			printf("Received opendomain() response; domain_handle = ");
			for(i = 0; i < 0x14; i++)
				printf("%02x", opendomain->domain_handle[i]);
			printf("\n");

			printf("* Sending querydisplayinfo()\n");
			smbclient_send_samr_querydisplayinfo((SMBCLIENT_t*)client, 0);
		}
		break;

		case SMBCLIENT_MSRPC_QUERYDISPLAYINFO:
		{
			QUERYDISPLAYINFO_t *querydisplayinfo = (QUERYDISPLAYINFO_t*)extra;

			printf("Received querydisplayinfo() response:\n");
			for(i = 0; i < querydisplayinfo->count; i++)
			{
				if(querydisplayinfo->elements[i].name)
					printf("Name: %s\n", querydisplayinfo->elements[i].name);
				if(querydisplayinfo->elements[i].fullname)
					printf("Full name: %s\n", querydisplayinfo->elements[i].fullname);
				if(querydisplayinfo->elements[i].description)
					printf("Description: %s\n", querydisplayinfo->elements[i].description);
				printf("\n");
			}

			printf("* Sending querydomaininfo2()\n");
			smbclient_send_samr_querydomaininfo2((SMBCLIENT_t*)client, 1);
		}
		break;

		case SMBCLIENT_MSRPC_QUERYDOMAININFO2:
		{
			QUERYDOMAININFO2_t *querydomaininfo2 = (QUERYDOMAININFO2_t*)extra;

			printf("Received querydomaininfo2() response:\n");
			printf("Min password length: %d\n", querydomaininfo2->min_password_length);
			printf("Password history length: %d\n", querydomaininfo2->password_history_length);
			printf("Password properties: %08x\n", querydomaininfo2->password_properties);
			printf("Max password age: %08x%08x\n", querydomaininfo2->max_password_age_high, querydomaininfo2->max_password_age_low);
			printf("Min password age: %08x%08x\n", querydomaininfo2->min_password_age_high, querydomaininfo2->min_password_age_low);

			printf("Domain create time: %08x%08x\n", querydomaininfo2->create_time_high, querydomaininfo2->create_time_low);

			printf("Lockout duration: %08x%08x\n", querydomaininfo2->lockout_duration_high, querydomaininfo2->lockout_duration_low);
			printf("Lockout window: %08x%08x\n", querydomaininfo2->lockout_window_high, querydomaininfo2->lockout_window_low);
			printf("Lockout threshold: %d\n", querydomaininfo2->lockout_threshold);

		}
		break;

		case SMBCLIENT_MSRPC_UNKNOWN:
			printf("Received unknown/invalid MSRPC response: 0x%02x\n", *((uint16_t*)extra));
		break;

		case SMBCLIENT_MSRPC_ERROR:
			switch(*((uint32_t*)extra))
			{
				case 0x1c010003:

					printf("MSRPC error: 0x%08x\n", *((uint32_t*)extra));
				break;
			}
		break;

		case SMBCLIENT_SESSION_LOGOFF:
			printf("Successfully logged off\n");
			exit(1);
		break;

		case SMBCLIENT_UNKNOWN_COMMAND:
			printf("Received an unknown command: %d (0x%02x)\n", (size_t)extra, (size_t)extra); /* TODO: make this better. */
		break;

		default:
			printf("Received an unknown event: %d\n", event);
	}
	return SMBCLIENT_OK;
}

SMBCLIENT_RESULT_t protocol_error_callback(void *client, uint32_t error, char *strerror)
{
	switch(error)
	{
		case -1:
			fprintf(stderr, "Error: %s\n", strerror);
		break;

		case NT_STATUS_ACCESS_DENIED:
			fprintf(stderr, "Error %s [0x%08x]\n", strerror, error);
			fprintf(stderr, "(note: this could be caused by sending incorrect signatures to a server that enforces them.)\n");
		break;

		default:
			fprintf(stderr, "Error %s [0x%08x]\n", strerror, error);
		break;
	}

	select_group_remove_and_close_socket(sg, ((SMBCLIENT_t*) client)->s);

	if(select_group_get_active_count(sg) == 0)
	{
		fprintf(stderr, "No connections left, bye!\n\n");
		exit(1);
	}

	return SMBCLIENT_OK;
}

SMBCLIENT_RESULT_t connection_error_callback(void *client, int err, char *strerror)
{
	printf("Connection error: %s [0x%08x]\n", strerror, err);

	select_group_remove_and_close_socket(sg, ((SMBCLIENT_t*) client)->s);

	if(select_group_get_active_count(sg) == 0)
	{
		fprintf(stderr, "No connections left, bye!\n\n");
		exit(1);
	}

	return SMBCLIENT_OK;
}

void usage(char *program)
{
	printf("Usage: %s [-v] [-s] [-t type] [-d domain] [-u username] [-p password|-P hash] <host> [port]\n", program);
	printf("\n");
	printf("-s requires the server to sign its packets (note enabled by default on Windows).\n");
	printf("-P sends either a single hash or a pair of colon separated lanman:ntlm hashes.\n");
	printf("   See below for which is required for each logon type.\n");
	printf("\n");
	printf("Valid logon types are:\n");
	printf(" 'default'	 Sends LM and NTLM	  (hash: both)\n");
	printf(" 'lm'		  Sends LM only		  (hash: LM)\n");
	printf(" 'ntlm'		Sends NTLM only		(hash: NTLM)\n");
	printf(" 'v2'		  Sends LMv2 and NTLMv2  (hash: NTLM)\n");
	printf(" 'lmv2'		Sends LMv2 only		(hash: NTLM)\n");
	printf(" 'anonymous'   Uses a NULL session	(hash: n/a)\n");
	printf("(NTLMv2 can't be sent alone, due to protocol quirks; however, 'v2' and 'lmv2' both use the NTLM hash,\n");
	printf(" so it isn't strictly necessary.)\n");
	printf("\n");
	printf("\n");

	exit(1);
}


int main(int argc, char *argv[])
{
	size_t i;
	int ch;

	SMBCLIENT_t *smbclient = smbclient_create();

	sg = select_group_create();

	/* Default values. */
	memset(&settings, 0, sizeof(SETTINGS_t));
	settings.port = 445;

	smbclient_set_event_callback(smbclient, event_callback);
	smbclient_set_protocol_error_callback(smbclient, protocol_error_callback);
	smbclient_set_connection_error_callback(smbclient, connection_error_callback);

	opterr = 0;

	while((ch = getopt(argc, argv, "hd:u:p:n:P:t:vs")) != -1)
	{
		switch(ch)
		{
			case 'h':
				usage(argv[0]);
				break;

			case 'd':
				settings.domain   = optarg;
				break;

			case 'u':
				settings.username = optarg;
				break;

			case 'p':
				settings.password = optarg;
				break;

			case 'P':
				settings.hash = optarg;
				break;

			case 'n':
				settings.netbios_name = optarg;
				break;

			case 't':
				if(!strcmp(optarg, "default"))
					settings.logon = LOGONTYPE_DEFAULT;
				else if(!strcmp(optarg, "lm"))
					settings.logon = LOGONTYPE_LM;
				else if(!strcmp(optarg, "ntlm"))
					settings.logon = LOGONTYPE_NTLM;
				else if(!strcmp(optarg, "v2"))
					settings.logon = LOGONTYPE_DEFAULTv2;
				else if(!strcmp(optarg, "lmv2"))
					settings.logon = LOGONTYPE_LMv2;
				else if(!strcmp(optarg, "anonymous"))
					settings.logon = LOGONTYPE_ANONYMOUS;
				else
				{
					fprintf(stderr, "Error: unknown logon type (%s)\n\n", optarg);
					usage(argv[0]);
				}
				break;

			case 'v':
				smbclient_raise_verbose(smbclient);
				break;

			case 's':
				smbclient_raise_check_signature(smbclient);
				settings.check_signature++;
				break;

			case '?':
			default:
				fprintf(stderr, "Unknown switch: %c\n\n", ch);
				usage(argv[0]);
		}
	}

	/* The host has to be given */
	if(optind >= argc)
	{
		fprintf(stderr, "Host not given!\n\n");
		usage(argv[0]);
	}

	/* Create the socket. */
	if(optind < argc)
		settings.host = argv[optind++];
	if(optind < argc)
		settings.port = atoi(argv[optind++]);

	/* Sanity checks. */
	if(settings.port == 139 && settings.netbios_name == NULL)
	{
		/* TODO: Do a probe for the NetBIOS name. */
		fprintf(stderr, "To use port 139, you have to specify the NetBIOS (server) name of the server (using ./nbquery -t NBSTAT to get it). Specify it with -n.\n\n");
		exit(1);
	}
	if(settings.password && settings.hash)
	{
		fprintf(stderr, "-p and -P cannot be used together.\n\n");
		exit(1);
	}
	if((settings.logon == LOGONTYPE_ANONYMOUS) && (settings.username || settings.password || settings.hash))
	{
		fprintf(stderr, "Anonymous logons can't have a domain/username/password/hash.\n\n");
		exit(1);
	}
	if(settings.logon == LOGONTYPE_ANONYMOUS && settings.check_signature)
	{
		fprintf(stderr, "Can't check signatuers on anonymous logons.\n\n");
		exit(1);
	}
	if((settings.logon == LOGONTYPE_DEFAULTv2 || settings.logon == LOGONTYPE_LMv2) && settings.check_signature)
	{
		fprintf(stderr, "Can't currently check signatures on v2 and LMv2 logons.\n\n");
		exit(1);
	}

	/* Domain has to be present (even if blank) and uppercase. */
	if(!settings.domain)
		settings.domain = "";
	else
	{
		for(i = 0; i < strlen(settings.domain); i++)
			settings.domain[i] = toupper(settings.domain[i]);
	}

	/* We're ready to connect! */
	smbclient_connect(smbclient, settings.host, settings.port, TRUE, sg);

	while(1)
	{
		select_group_do_select(sg, -1, -1);
	}

	return 0;
}

