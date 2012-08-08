/* nbquery.c
 * By Ron
 * Created August, 2008
 *
 * (See LICENSE.txt)
 *
 *==Intro==
 * [[nbquery]] is capable of sending out any type of NetBIOS request. These 
 * request types include:
 * * NB
 * * NBSTAT
 * * Register
 * * Refresh
 * * Release
 * * Conflict
 * * Demand
 *
 * More on what each of them do below.
 *
 * One thing worth noting about the NetBIOS protocol is that it is nearly
 * identical to DNS. In fact, it's close enough that this script uses the DNS
 * library to * build requests. The primary differences between NetBIOS and DNS
 * are:
 * * How names are encoded (NetBIOS names are encoded before being sent),
 * * How the flags are used (NetBIOS has a different set of flags), and
 * * How requests are sent (NetBIOS is capable of broadcasting requests
 *
 * The 'dns' library I wrote can easily deal with these differences, so it is
 * used for building dns queries. 
 *
 *==Usage==
 *<pre>
 * Usage: ./nbquery [options] <action>
 *  -h --help
 *     Help (this screen).
 *  -t --target <targetip>
 *     The address to send the request. For simple NB requests to the local
 *     network, the default (broadcast; '255.255.255.255') works. If you want to
 *     get full information (-t NBSTAT) or get information for a non-local network, 
 *     this should be set to the target address. 
 *  -s --source <sourceip>
 *  -p --port <port>
 *     Choose a port besides the default (137). Not generally useful, since Windows
 *     runs NetBIOS Name Service on UDP/137.
 *  -w --wait <ms>
 *     The amount of time, in milliseconds, to wait for repsonses. Default: 500ms.
 *  -V --version
 *     Print version and exit.
 * Actions (must choose exactly one):
 *  --nb [name[:<suffix>]]
 *     Query for a NetBIOS name. Queries for any name by default ('*'). If you're
 *     looking for a specific server, say, 'TEST01', set the name to that to that
 *     name. You can optionally add the one-byte suffix after the name, such as
 *     'TEST01:03', but that isn't too common
 *  --nbstat [name[:<suffix>]]
 *     Query for a NetBIOS status. Format is the same as --nb.
 *  --register <name>
 *     Send out a notice that you're going to be using the given name.
 *     If any systems are already using the name, they will respond with a
 *     conflict.
 *  --refresh <name>
 *     Send out a notice that you're refreshing your use of a name. I haven't seen
 *     this provoke a response before, so it might be useless.
 *  --release <name>
 *     Send a notice that you're done using a name. If somebody else owns that
 *     name, they will generally return an error.
 *  --conflict <name>
 *     Sent immediately after somebody else registers, this informs the system
 *     that they aren't the rightful owner of a name and they should not use it.
 *     To automate this, see the 'nbsniff' tool with --poison.
 *  --demand <name>
 *     Demands that another system releases the name. Typically isn't implemented
 *     for security reasons. Again, see 'nbsniff --poison'.
 *</pre>
 * 
 *==NB==
 * A standard NB (NetBIOS) query, sent when --nb is passed can do several
 * things:
 * # Ask who owns a particular name
 * # Ask who is on the local segment (doesn't work against all hosts)
 * # Ask if a particular system has a name
 *
 * The first two points require a broadcast -- by default, we broadcast to the
 * global broadcast address, 255.255.255.255, but I noticed that that doesn't
 * always work, so you may need to pass your local broadcast address, 
 * "-t x.x.x.255" (where "x.x.x" is the start of your address).
 *
 * Asking who owns a particular name is a technique used by Windows when it
 * fails to find a host in DNS. This allows it to find hosts on the local
 * network with a given name. Broadcasting for a name is obviously a bad idea;
 * more on that in [[nbsniff]].
 *
 * Here's how it looks on nbquery:
 *<pre>
 * $ ./nbquery --nb=WINDOWSXP
 * Creating a UDP socket.
 * Sending query.
 * ANSWER query: (NB:WINDOWSXP      <00|workstation>): success, IP: 192.168.1.106, TTL: 300000s
 *
 * $ ./nbquery --nb=VISTA -t 192.168.1.255
 * Creating a UDP socket.
 * Sending query.
 * ANSWER query: (NB:VISTA          <00|workstation>): success, IP: 192.168.1.102, TTL: 300000s
 *</pre>
 *
 * ('WINDOWSXP' and 'VISTA' are what I named my test systems)
 *
 * The second use is asking who is on a local network. I've found that this only
 * works against certain systems; mostly Windows 2000. But here's how it's
 * done: 
 *<pre>
 * $ ./nbquery --nb
 * Creating a UDP socket.
 * Sending query.
 * ANSWER query: (NB:*<00|workstation>): success, IP: 192.168.1.109, TTL: 300000s
 *</pre> 
 *
 * Finally, asking if somebody owns a name is silly, but it can be done using
 * the -t argument:
 *<pre>
 * $ ./nbquery --nb=WINDOWSXP -t 192.168.1.106
 * Creating a UDP socket.
 * Sending query.
 * ANSWER query: (NB:WINDOWSXP      <00|workstation>): success, IP: 192.168.1.106, TTL: 300000s
 *</pre>
 *
 *==NBSTAT==
 * NBSTAT goes further than NetBIOS. It is targeted against a specific host
 * and asks that host for a list of all names it thinks it owns. The Windows
 * program nbtstat does this, as well as the opensource nbtscan program.
 *
 * This usage is pretty simple:
 *<pre>
 * $ ./nbquery --nbstat -t 192.168.1.106
 * Creating a UDP socket.
 * Sending query.
 * NBSTAT response: Received 4 names; success (MAC: 00:0c:29:07:69:b0)
 * ANSWER: (NBSTAT:*<00|workstation>): WINDOWSXP<00> <unique><active> (0x0400)
 * ANSWER: (NBSTAT:*<00|workstation>): WINDOWSXP<20> <unique><active> (0x0400)
 * ANSWER: (NBSTAT:*<00|workstation>): WORKGROUP<00> <group><active> (0x8400)
 * ANSWER: (NBSTAT:*<00|workstation>): WORKGROUP<1e> <group><active> (0x8400)
 *
 * ron@ankh:~/tools/nbtool$ ./nbquery --nbstat -t 192.168.1.109
 * Creating a UDP socket.
 * Sending query.
 * NBSTAT response: Received 6 names; success (MAC: 00:0c:29:f5:81:bd)
 * ANSWER: (NBSTAT:*<00|workstation>): WINDOWS2000<00> <unique><active> (0x0400)
 * ANSWER: (NBSTAT:*<00|workstation>): WINDOWS2000<03> <unique><active> (0x0400)
 * ANSWER: (NBSTAT:*<00|workstation>): SKULLSECURITY<00> <group><active> (0x8400)
 * ANSWER: (NBSTAT:*<00|workstation>): RON<03> <unique><active> (0x0400)
 * ANSWER: (NBSTAT:*<00|workstation>): SKULLSECURITY<1e> <group><active> (0x8400)
 *</pre>
 *
 *==Register, Renew, Release==
 * The register, renew, and release queries are all very similar -- they're
 * designed to emulate the actions that Windows itself takes while booting
 * and shutting down. 
 * 
 * When a Windows computer boots, the first thing it does is send out a
 * 'register' request for its own name. It does this to let the other systems
 * know that it intends to use that name. If another system already has that
 * name, it sends back a conflict and the new system will give it up until
 * the next boot. More on conflicts in [[nbsniff]]. 
 *
 * The register and release commands (activated by --register and --release)
 * will generally provoke a response if a system is already using a name,
 * whereas renew, in my experience, has never provokes a response. 
 *
 * Here is an example of the three of them, in the typical order that Windows
 * would send them:
 *<pre>
 * $ ./nbquery --register=WINDOWS2000
 * Creating a UDP socket.
 * Sending query.
 * ANSWER query: (NB:WINDOWS2000    <00|workstation>): error: active, IP: 192.168.1.109, TTL: 0s
 *
 * ron@ankh:~/tools/nbtool$ ./nbquery --refresh=WINDOWSXP
 * Creating a UDP socket.
 * Sending query.
 * Wait time has elapsed.
 *
 * ron@ankh:~/tools/nbtool$ ./nbquery --release=VISTA
 * Creating a UDP socket.
 * Sending query.
 * ANSWER query: (NB:VISTA          <00|workstation>): error: name not found, IP: 0.0.0.0, TTL: 0s
 *</pre>
 *
 * Note that the --register provoked "error: active", whereas --release
 * provoked "error: name not found". 
 *
 * As before, WINDOWS2000, WINDOWSXP, and VISTA are the namef of my test
 * systems. 
 *
 * One of those best uses of these programs is to test [[nbsniff]].
 *
 *==Conflict, Demand==
 * Conflict and demand (activated with --conflict and --demand) are ways of
 * asking hosts to relinquish their name. Neither are supported by any modern
 * NetBIOS implementation, though; I added them for completeness. 
 *
 * --demand is actually the same as --release, except that --demand expects
 * to be unicast and --release expects to be broadcast. 
 */

#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef WIN32
#include <winsock2.h>
#else
#include <strings.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#endif

#include "buffer.h"
#include "dns.h"
#include "netbios_types.h"
#include "memory.h"
#include "my_getopt.h"
#include "select_group.h"
#include "types.h"
#include "udp.h"

#define NAME "nbquery"

typedef enum
{
	TYPE_NONE = 0,
	TYPE_CONFLICT,
	TYPE_DEMAND,
	TYPE_QUERY_NB,
	TYPE_QUERY_NBSTAT,
	TYPE_REFRESH,
	TYPE_REGISTER,
	TYPE_RELEASE,
} query_type_t;

typedef struct
{
	char        *source;
	char        *target;

	char        *name;
    uint8_t      name_type;
	int          socket;
	int          wait;
	uint16_t     port; /* Will probably be 137. */

	query_type_t query_type;

	/* So we can free it later. */
	select_group_t *group;
} settings_t;

settings_t *global_settings;

static SELECT_RESPONSE_t nb_recv_callback(void *group, int s, uint8_t *data, size_t length, char *addr, uint16_t port, void *param)
{
	uint16_t i;

	dns_t *dns = dns_create_from_packet(data, length);

	for(i = 0; i < dns->answer_count; i++)
	{
		if(dns->answers[i].type == DNS_TYPE_NB)
		{
			NB_print_answer(dns->answers[i], dns->flags);
		}
		else if(dns->answers[i].type == DNS_TYPE_NBSTAT)
		{
			NBSTAT_print_answer(dns->answers[i], dns->flags);
		}
		else
		{
			fprintf(stderr, "Unknown NetBIOS answer: 0x%04x\n", dns->answers[i].type);
		}
	}

	dns_destroy(dns);

	return SELECT_OK;
}

static SELECT_RESPONSE_t nb_timeout(void *group, int socket, void *s)
{
	fprintf(stderr, "Wait time has elapsed.\n");
	exit(0);
	return SELECT_OK;
}

static void nb_poll(settings_t *settings)
{
	settings->group = select_group_create();
	select_group_add_socket(settings->group, settings->socket, SOCKET_TYPE_DATAGRAM, settings);
	select_set_recv(settings->group, settings->socket, nb_recv_callback);

	select_set_timeout(settings->group, settings->socket, nb_timeout);

	while(1)
		select_group_do_select(settings->group, settings->wait);

	select_group_destroy(settings->group);
}

static void query_send(settings_t *settings)
{
    dns_t      *dns;
    uint8_t    *packet;
    uint32_t    packet_length;

	/* Create the DNS object. */
    dns = dns_create();
    dns->flags  = FLAGS_R_REQUEST | FLAGS_OPCODE_QUERY | FLAGS_NM_B;
	dns->trn_id = 0x1337;

	/* Add the question. */
    dns_add_netbios_question(dns, settings->name, settings->name_type, NULL, settings->query_type == TYPE_QUERY_NB ? DNS_TYPE_NB : DNS_TYPE_NBSTAT, 0x0001);

	/* Convert the DNS object to a packet. */
    packet = dns_to_packet(dns, &packet_length);
    dns_destroy(dns);

	/* Put it on the wire. */
	fprintf(stderr, "Sending query.\n");
    udp_send(settings->socket, settings->target, settings->port, packet, packet_length);
    safe_free(packet);
}

static void register_send(settings_t *settings)
{
    dns_t      *dns;
    uint8_t    *packet;
    uint32_t    packet_length;

	/* Create the DNS object. */
    dns = dns_create();
	dns->flags = FLAGS_R_REQUEST | FLAGS_NM_RD | FLAGS_NM_B;

	if(settings->query_type == TYPE_REGISTER)
	    dns->flags  = FLAGS_OPCODE_NAME_REGISTRATION;
	else if(settings->query_type == TYPE_REFRESH)
	    dns->flags  = FLAGS_OPCODE_NAME_REFRESH;
	else if(settings->query_type == TYPE_RELEASE)
	    dns->flags  = FLAGS_OPCODE_NAME_RELEASE;
	else
		fprintf(stderr, "Unknown query type made it into register_send() -- %d\n", settings->query_type);

	dns->trn_id = 0x1337;

	/* Add the question/additional. */
    dns_add_netbios_question(dns, settings->name, settings->name_type, NULL, DNS_TYPE_NB, 0x0001);
	dns_add_additional_NB(dns, settings->name, settings->name_type, NULL, 0x0001, 0, 0x0000, settings->source);

	/* Convert the DNS object to a packet. */
    packet = dns_to_packet(dns, &packet_length);
    dns_destroy(dns);

	/* Put it on the wire. */
	fprintf(stderr, "Sending query.\n");
    udp_send(settings->socket, settings->target, settings->port, packet, packet_length);
    safe_free(packet);
}

static void conflict_send(settings_t *settings)
{
    dns_t      *dns;
    uint8_t    *packet;
    uint32_t    packet_length;

	/* Create the DNS object. */
    dns = dns_create();
	dns->flags = FLAGS_R_RESPONSE | FLAGS_OPCODE_NAME_REGISTRATION | FLAGS_NM_AA | FLAGS_NM_RD | FLAGS_NM_RA | FLAGS_RCODE_CFT_ERR;
	dns->trn_id = 0x1337;

	/* Add the Answer. */
    dns_add_answer_NB(dns, settings->name, settings->name_type, NULL, 0x0001, 0, 0x0000, settings->source);

	/* Convert the DNS object to a packet. */
    packet = dns_to_packet(dns, &packet_length);
    dns_destroy(dns);

	/* Put it on the wire. */
	fprintf(stderr, "Sending query.\n");
    udp_send(settings->socket, settings->target, settings->port, packet, packet_length);
    safe_free(packet);
}

static void demand_send(settings_t *settings)
{
    dns_t      *dns;
    uint8_t    *packet;
    uint32_t    packet_length;

	/* Create the DNS object. */
    dns = dns_create();
	dns->flags = FLAGS_OPCODE_NAME_RELEASE;
	dns->trn_id = 0x1337;

	/* Add the question/additional. */
    dns_add_netbios_question(dns, settings->name, settings->name_type, NULL, DNS_TYPE_NB, 0x0001);
	dns_add_additional_NB(dns, settings->name, settings->name_type, NULL, 0x0001, 0, 0x0000, settings->source);

	/* Convert the DNS object to a packet. */
    packet = dns_to_packet(dns, &packet_length);
    dns_destroy(dns);

	/* Put it on the wire. */
	fprintf(stderr, "Sending query.\n");
    udp_send(settings->socket, settings->target, settings->port, packet, packet_length);
    safe_free(packet);
}

static void cleanup(void)
{
	printf("Cleaning up...\n");

	if(global_settings)
	{
		if(global_settings->group)
			select_group_destroy(global_settings->group);
		safe_free(global_settings);
	}

	/* Print allocated memory. This will only run if -DTESTMEMORY is given. */
	print_memory();
}

static void interrupt(int signal)
{
	/* Note: exiting like this will call the atexit() function, cleanup(). */
	fprintf(stderr, "punt!\n");
	exit(0);
}


static void usage(char *program, char *error)
{

	fprintf(stderr, "Usage: %s [options] <action>\n", program);
	fprintf(stderr, " -h --help\n");
	fprintf(stderr, "    Help (this screen).\n");
	fprintf(stderr, " -t --target <targetip>\n");
	fprintf(stderr, "    The address to send the request. For simple NB requests to the local\n");
	fprintf(stderr, "    network, the default (broadcast; '255.255.255.255') works. If you want to\n");
	fprintf(stderr, "    get full information (-t NBSTAT) or get information for a non-local network, \n");
	fprintf(stderr, "    this should be set to the target address. \n");
	fprintf(stderr, " -s --source <sourceip>\n");
	fprintf(stderr, " -p --port <port>\n");
	fprintf(stderr, "    Choose a port besides the default (137). Not generally useful, since Windows\n");
	fprintf(stderr, "    runs NetBIOS Name Service on UDP/137.\n");
	fprintf(stderr, " -w --wait <ms>\n");
	fprintf(stderr, "    The amount of time, in milliseconds, to wait for repsonses. Default: 500ms.\n");
	fprintf(stderr, " -V --version\n");
	fprintf(stderr, "    Print version and exit.");
	fprintf(stderr, "\n");
	fprintf(stderr, "Actions (must choose exactly one):\n");
	fprintf(stderr, " --nb [name[:<suffix>]]\n");
	fprintf(stderr, "    Query for a NetBIOS name. Queries for any name by default ('*'). If you're\n");
	fprintf(stderr, "    looking for a specific server, say, 'TEST01', set the name to that to that\n");
	fprintf(stderr, "    name. You can optionally add the one-byte suffix after the name, such as\n");
	fprintf(stderr, "    'TEST01:03', but that isn't too common\n");
	fprintf(stderr, " --nbstat [name[:<suffix>]]\n");
	fprintf(stderr, "    Query for a NetBIOS status. Format is the same as --nb.\n");
	fprintf(stderr, " --register <name>\n");
	fprintf(stderr, "    Send out a notice that you're going to be using the given name.\n");
	fprintf(stderr, "    If any systems are already using the name, they will respond with a\n");
	fprintf(stderr, "    conflict.\n");
	fprintf(stderr, " --refresh <name>\n");
	fprintf(stderr, "    Send out a notice that you're refreshing your use of a name. I haven't seen\n");
	fprintf(stderr, "    this provoke a response before, so it might be useless.\n");
	fprintf(stderr, " --release <name>\n");
	fprintf(stderr, "    Send a notice that you're done using a name. If somebody else owns that\n");
	fprintf(stderr, "    name, they will generally return an error.\n");
	fprintf(stderr, " --conflict <name>\n");
	fprintf(stderr, "    Sent immediately after somebody else registers, this informs the system\n");
	fprintf(stderr, "    that they aren't the rightful owner of a name and they should not use it.\n");
	fprintf(stderr, "    To automate this, see the 'nbsniff' tool with --poison.\n");
	fprintf(stderr, " --demand <name>\n");
	fprintf(stderr, "    Demands that another system releases the name. Typically isn't implemented\n");
	fprintf(stderr, "    for security reasons. Again, see 'nbsniff --poison'.\n");
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
		{"help",        no_argument,       0, 0}, /* Help. */
		{"h",           no_argument,       0, 0},
		{"H",           no_argument,       0, 0},
		{"port",        required_argument, 0, 0}, /* Port. */
		{"p",           required_argument, 0, 0},
		{"source",      required_argument, 0, 0}, /* Source. */
		{"s",           required_argument, 0, 0},
		{"target",      required_argument, 0, 0}, /* Target. */
		{"t",           required_argument, 0, 0},
		{"version",     no_argument,       0, 0}, /* Version. */
		{"V",           no_argument,       0, 0},
		{"wait",        required_argument, 0, 0}, /* Wait time. */
		{"w",           required_argument, 0, 0},

		/* Actions (exactly one has to be selected). */
		{"conflict",    required_argument, 0, 1}, /* Send a conflict. */
		{"demand",      required_argument, 0, 1}, /* Demand another host releases their name. */
		{"nb",          optional_argument, 0, 1}, /* Query a NB name. */
		{"nbstat",      optional_argument, 0, 1}, /* Query a NBSTAT name. */
		{"refresh",     required_argument, 0, 1}, /* Refresh a name. */
		{"register",    required_argument, 0, 1}, /* Register a name. */
		{"release",     required_argument, 0, 1}, /* Release a name. */

		{0, 0, 0, 0}
	};

	/* Initialize Winsock (if we're on Windows). */
	winsock_initialize();

	/* Get ready to randomize. */
	srand((unsigned int)time(NULL));

	/* Clear the settings. */
	memset(s, sizeof(s), 0);

	/* Set some defaults. */
	s->name          = NULL;
	s->name_type     = 0x00;
	s->port          = 137;
	s->source        = "1.2.3.4";
	s->target        = "255.255.255.255";
	s->wait          = 5000;
	s->query_type    = TYPE_NONE;

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
				if(!strcmp(option_name, "help") || !strcmp(option_name, "h") || !strcmp(option_name, "H"))
				{
					usage(argv[0], NULL);
				}
				else if(!strcmp(option_name, "port") || !strcmp(option_name, "p"))
				{
					s->port = atoi(optarg);
				}
				else if(!strcmp(option_name, "source") || !strcmp(option_name, "s"))
				{
					s->target = optarg;
				}
				else if(!strcmp(option_name, "target") || !strcmp(option_name, "t"))
				{
					s->target = optarg;
				}
				else if(!strcmp(option_name, "version") || !strcmp(option_name, "V"))
				{
					version();
				}
				else if(!strcmp(option_name, "wait") || !strcmp(option_name, "w"))
				{
					s->wait = atoi(optarg);
				}
			break;

			case 1:
			{
				char *tmp;

				/* Set up the option name. */
				option_name = long_options[option_index].name;

				/* Make sure we don't already have one set. */
				if(s->query_type != TYPE_NONE)
					usage(argv[0], "--conflict, --demand, --nb, --nbstat, --refresh, --register, and --release are mutually exclusive.");

				/* Parse the name. */
				if(optarg)
				{
					s->name = optarg;

					/* tmp will be set if the string contains a ':' */
					tmp = strrchr(s->name, ':');
					if(tmp)
					{
						*tmp = '\0';
						tmp++;
						s->name_type = (uint8_t)strtol(tmp, NULL, 16);
					}
				}
				else
				{
					s->name = "*";
				}

				/* Figure out which request type we're settings. */
				if(!strcmp(option_name, "conflict"))
					s->query_type = TYPE_CONFLICT;
				else if(!strcmp(option_name, "demand"))
					s->query_type = TYPE_DEMAND;
				else if(!strcmp(option_name, "nb"))
					s->query_type = TYPE_QUERY_NB;
				else if(!strcmp(option_name, "nbstat"))
					s->query_type = TYPE_QUERY_NBSTAT;
				else if(!strcmp(option_name, "refresh"))
					s->query_type = TYPE_REFRESH;
				else if(!strcmp(option_name, "register"))
					s->query_type = TYPE_REGISTER;
				else if(!strcmp(option_name, "release"))
					s->query_type = TYPE_RELEASE;
				else
					usage(argv[0], "Invalid request type.");
			}
			break;

			case '?':
			default:
				usage(argv[0], "Couldn't parse arguments");
			break;
		}
	}

	if(s->query_type == TYPE_NONE)
		usage(argv[0], "Please choose one of --nb, --nbstat, --register, --refresh, --release, --conflict, or --demand. Try --help for more information.");

	if(s->query_type == DNS_TYPE_NBSTAT && !strcmp(s->target, "255.255.255.255"))
		usage(argv[0], "--nbstat require a specific target (-t or --target).");

#ifndef WIN32
	/* Check for the root user. */
/*	if(getuid() != 0)
		fprintf(stderr, "WARNING: If the bind() fails, please re-run as root (privileges will be dropped as soon as the socket is created).\n");*/
#endif

	/* Create a socket */
	fprintf(stderr, "Creating a UDP socket.\n");
	s->socket = udp_create_socket(0, "0.0.0.0");

	if(s->query_type == TYPE_QUERY_NB || s->query_type == TYPE_QUERY_NBSTAT)
	{
		/* Send the query. */
		query_send(s);
	}
	else if(s->query_type == TYPE_REGISTER || s->query_type == TYPE_REFRESH || s->query_type == TYPE_RELEASE)
	{
		/* Send registration. */
		register_send(s);
	}
	else if(s->query_type == TYPE_CONFLICT)
	{
		conflict_send(s);
	}
	else if(s->query_type == TYPE_DEMAND)
	{
		demand_send(s);
	}
	else
	{
		fprintf(stderr, "Query type isn't implemented yet!\n");
		exit(1);
	}

	/* Drop privileges, if they're running as root. */
/*	drop_privileges(s->user);*/

	/* Set the global settings -- this lets us clean up when a signal is caught. */
	global_settings = s;

	/* Poll for data. */
	nb_poll(s);

	return 0;
}

