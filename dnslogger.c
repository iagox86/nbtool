/* dnslogger.c
 * By Ron Bowes
 * Created January, 2010
 *
 * (See LICENSE.txt)
 *
 *==Intro==
 * [[dnslogger]] has two primary functions:
 * # Print all received DNS requests
 * # Reply to them with an error or a static ip address (IPv4 or IPv6)
 *
 * This is obviously very simple, but is also powerful. 
 *
 *==Usage==
 *<pre>
 *  -h --help
 *     Help (this page)
 *  --test <domain>
 *     Test to see if we are the authoritative nameserver for the given domain.
 *  -s --source <address>
 *     The local address to bind to. Default: any (0.0.0.0)
 *  -p --port <port>
 *     The local port to listen on. I don't recommend changing this.
 *     default: 53
 *  -A <address>
 *     The A record to return when a record is requested. Default: NXDOMAIN.
 *  --AAAA <address>
 *     The AAAA record to return when a record is requested. Default: NXDOMAIN.
 *  --TTL <time>
 *     The time-to-live value to send back, in seconds. Default: 1 second.
 *  -u --username
 *     Drop privileges to this user after opening socket (default: 'nobody')
 *  -V --version
 *     Print the version and exit
 *</pre>
 *
 *==Printing requests==
 * Printing DNS requests has a lot of uses. Essentially, it'll tell you if
 * a program tried to connect to your site, without the program ever
 * attempting the connection. There are a great number of possible uses for
 * that:
 * * Finding open proxies without making an actual connection through it
 * * Finding open mail relays without sending an email through it
 * * Finding errors in mail-handling code on a site
 * * Finding shell injection on a Web application without outbound traffic or delays
 * * Checking if a user visited a certain page
 *
 * In every one of those cases, the server will try to look up the domain name
 * to perform some action, and fails. For example, to find an open proxy you
 * can connect to the potential proxy and send it "CONNECT <yourdomain>". If
 * the proxy server is indeed open, it'll do a lookup on <yourdomain> and
 * you'll see the request. Then, by default, an error is returned, so the proxy
 * server gives up on attempting the connection and it's never logged. That's
 * really the key -- the connection attempt never gets logged. 
 * 
 * Likewise, shell injection. If you're testing an application for shell 
 * injection, you can send it the payload 'ping <yourdomain>' to run. a
 * vulnerable server will attempt to ping the domain and perform a DNS lookup.
 * By default, the DNS lookup will fail, and the server won't perform the ping.
 * It'll look like this:
 *<pre>
 * $ ping www.skullseclabs.org
 * ping: unknown host www.skullseclabs.org
 *</pre>
 *
 * dnslogger, however, will have seen the request and we therefore know that
 * the application is vulnerable. This is far more reliable than the classic
 * 'ping localhost 4 times and see if it takes 3 seconds' approach to finding
 * shell injection. 
 *
 * One final note is discovering Web applications that handle email incorrectly.
 * A classic vulnerability when sending email, besides shell injection, is
 * letting the user terminate the email with a "." on its own line, then start
 * a new email. Something like this:
 *<pre>
 * This is my email, hello!
 * .
 * mail from: test@test.com
 * rcpt to: test@<yourdomain>
 * data
 * This email won't get sent!
 *</pre>
 *
 * So the first email was terminated on the second line, with a period. A new
 * email is composed to test@<yourdomain>. If the application is vulnerable
 * to this type of attack, it will attempt to look up <yourdomain> so it can
 * send an email there. We'll see the request, respond with an error, and the
 * request will never be sent. 
 * 
 *==Controlling the response==
 * In addition to logging requests, dnslogger can also respond with arbitrary
 * A or AAAA records to any incoming request. A long time ago, at work, I used
 * a Visual Basic program I found somewhere called "FakeDNS" that accomplished
 * a similar task, but I've since lost it and decided to implement it myself.
 * Some potential uses of this program are:
 * * Investigating malware that connects to a remote host
 * * Redirecting users if you control their DNS server
 * * Redirecting a legitimate program to your own server
 * 
 * The first use is actually the one I created this for -- investigating
 * malware. One of the most common types of malware I'm asked to investigate
 * at work is a classic downloader, which reaches out to the Internet and
 * downloads its payload. Almost always, it uses a DNS server to find the
 * malware. By setting the system's dns to the dnslogger DNS server, all DNS
 * lookups will be seen (for later investigation), and you can control which
 * server it tries to connect to to download the files. 
 * 
 * Another potential use, and somewhat malicious, is, if you control the DHCP
 * server on a victim's computer, you can point their DNS to a malicious host,
 * perhaps one running a password-stealer or Metasploit payload, and do what
 * you want. 
 *
 * One final use, which takes me back to the old days of Battle.net programming,
 * is redirecting a legitimate program with a hardcoded domain. For example, 
 * Battle.net used to default to useast.battle.net, uswest.battle.net, etc. 
 * Although you could change these servers in the registry, another option is
 * to point your system DNS to dnslogger and let it redirect the requests for
 * you. 
 * 
 *==Authoritative DNS server==
 * Many functions of this tool require you to be the authoritative nameserver
 * for a domain. This typically costs money, but is fairly cheap and has a lot
 * of benefits. If you aren't sure whether or not you're the authority, you
 * can use the --test argument to this program, or you can directly run the
 * [[dnstest]] program, also included. 
 */

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef WIN32
#include <winsock2.h>
#else
#include <unistd.h>
#endif

#include "buffer.h"
#include "dns.h"
#include "memory.h"
#include "my_getopt.h"
#include "select_group.h"
#include "types.h"
#include "udp.h"

#define NAME "dnslogger"

typedef struct
{
	int server_socket;
	select_group_t *select_group;
	char *user;
	char *source;
	int   port;
	char *A;
#ifndef WIN32
	char *AAAA;
#endif
	int TTL;
} settings_t;

/* We need this for catching signals. */
settings_t *global_settings = NULL;

static SELECT_RESPONSE_t dns_callback(void *group, int socket, uint8_t *packet, size_t packet_length, char *addr, uint16_t port, void *s)
{
	settings_t *settings = (settings_t*) s;
	dns_t      *response;
	uint8_t    *response_packet;
	uint32_t    response_packet_length;

	/* Parse the DNS packet. */
	dns_t *request  = dns_create_from_packet(packet, packet_length);

	/* Create the response packet. */
	response = dns_create();
	response->trn_id = request->trn_id;
	response->flags = 0x8000;

	if(request->question_count > 0)
	{
		int i;

		/* Display the questions. */
		for(i = 0; i < request->question_count; i++)
		{
			/* Grab the question and display it. */
			question_t this_question = request->questions[i];
			fprintf(stderr, "Question %d: %s (0x%04x 0x%04x)\n", i, this_question.name, this_question.type, this_question.class);

			/* Add an answer, if appropriate. */
			dns_add_question(response, this_question.name, this_question.type, this_question.class);
			if(settings->A && (this_question.type == DNS_TYPE_A || this_question.type == DNS_TYPE_ANY))
			{
				fprintf(stderr, "(Responding with %s)\n", settings->A);
				dns_add_answer_A(response, this_question.name, 0x0001, settings->TTL, settings->A);
			}
#ifndef WIN32
			else if(settings->AAAA && this_question.type == DNS_TYPE_AAAA)
			{
				fprintf(stderr, "(Responding with %s)\n", settings->AAAA);
				dns_add_answer_AAAA(response, this_question.name, 0x0001, settings->TTL, settings->AAAA);
			}
#endif

		}

		/* If we have any answers, send back our packet. */
		if(response->answer_count > 0)
		{
			/* Send the packet. */
			response_packet = dns_to_packet(response, &response_packet_length);
			udp_send(socket, addr, port, response_packet, response_packet_length);
		}
		else
		{
			/* Send back an error. */
			response_packet = dns_create_error_string(request->trn_id, request->questions[0], &response_packet_length);
			udp_send(socket, addr, port, response_packet, response_packet_length);
		}

		/* Delete the response. */
		safe_free(response_packet);
		dns_destroy(response);

		/* Delete the request. */
		dns_destroy(request);
	}

	return SELECT_OK;
}

static void dns_poll(settings_t *s)
{
	/* Create the select group in 'settings' -- this is so we can free it on a signal. */
	s->select_group = select_group_create();

	/* Add the server socket. */
	select_group_add_socket(s->select_group, s->server_socket, SOCKET_TYPE_DATAGRAM, s);
	select_set_recv(s->select_group, s->server_socket, dns_callback);

	while(1)
		select_group_do_select(s->select_group, -1);

	select_group_destroy(s->select_group); /* Note: we don't get here. */
}

void cleanup(void)
{
	if(global_settings)
	{
		/* Free memory. */
		if(global_settings->select_group)
			select_group_destroy(global_settings->select_group);

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

static void usage(char *program)
{
	fprintf(stderr, NAME", by Ron Bowes <ron@skullsecurity.net>\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "%s [options]\n", program);
	fprintf(stderr, "\n");
	fprintf(stderr, " -h --help\n");
	fprintf(stderr, "    Help (this page)\n");
	fprintf(stderr, " --test <domain>\n");
	fprintf(stderr, "    Test to see if we are the authoritative nameserver for the given domain.\n");
	fprintf(stderr, " -s --source <address>\n");
	fprintf(stderr, "    The local address to bind to. Default: any (0.0.0.0)\n");
	fprintf(stderr, " -p --port <port>\n");
	fprintf(stderr, "    The local port to listen on. I don't recommend changing this.\n");
	fprintf(stderr, "    default: 53\n");
	fprintf(stderr, " -A <address>\n");
	fprintf(stderr, "    The A record to return when a record is requested. Default: NXDOMAIN.\n");
#ifndef WIN32
	fprintf(stderr, " --AAAA <address>\n");
	fprintf(stderr, "    The AAAA record to return when a record is requested. Default: NXDOMAIN.\n");
#endif
	fprintf(stderr, " --TTL <time>\n");
	fprintf(stderr, "    The time-to-live value to send back, in seconds. Default: 1 second.\n");
	fprintf(stderr, " -u --username\n");
	fprintf(stderr, "    Drop privileges to this user after opening socket (default: 'nobody')\n");
	fprintf(stderr, " -V --version\n");
	fprintf(stderr, "    Print the version and exit\n");
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
		{"A",         required_argument, 0, 0}, /* A record. */
#ifndef WIN32
		{"AAAA",      required_argument, 0, 0}, /* A record. */
#endif
		{"help",      no_argument,       0, 0}, /* Help. */
		{"h",         no_argument,       0, 0},
		{"H",         no_argument,       0, 0},
		{"port",      required_argument, 0, 0}, /* Local port. */
		{"p",         required_argument, 0, 0},
		{"source",    required_argument, 0, 0}, /* Source. */
		{"s",         required_argument, 0, 0},
		{"test",      required_argument, 0, 0}, /* Test the DNS authority. */
		{"TTL",       required_argument, 0, 0}, /* Time to live */
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
	s->source        = "0.0.0.0";
	s->TTL           = 1;

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
				if(!strcmp(option_name, "A"))
				{
					s->A = optarg;
				}
#ifndef WIN32
				else if(!strcmp(option_name, "AAAA"))
				{
					s->AAAA = optarg;
				}
#endif
				else if(!strcmp(option_name, "help") || !strcmp(option_name, "h") || !strcmp(option_name, "H"))
				{
					usage(argv[0]);
				}
				else if(!strcmp(option_name, "port") || !strcmp(option_name, "p"))
				{
					s->port = atoi(optarg);
				}
				else if(!strcmp(option_name, "source") || !strcmp(option_name, "s"))
				{
					s->source = optarg;
				}
				else if(!strcmp(option_name, "test"))
				{
					dns_do_test(optarg); /* Doesn't return. */
				}
				else if(!strcmp(option_name, "TTL"))
				{
					s->TTL = atoi(optarg);
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
				usage(argv[0]);
			break;
		}
	}

#ifndef WIN32
	/* Check for the root user. */
	if(getuid() != 0)
		fprintf(stderr, "WARNING: If the bind() fails, please re-run as root (privileges will be dropped as soon as the socket is created).\n");
#endif

	/* Create a socket for the server. */
	s->server_socket = udp_create_socket(s->port, s->source);

	/* Display what we're doing. */
	fprintf(stderr, "Listening for requests on %s:%d\n", s->source, s->port);
	if(s->A)
		fprintf(stderr, "Will respond to A requests with %s\n", s->A);
#ifndef WIN32
	if(s->AAAA)
		fprintf(stderr, "Will respond to AAAA requests with %s\n", s->AAAA);
#endif

	/* Drop privileges. */
	drop_privileges(s->user);

	/* Set the global settings -- this lets us clean up when a signal is caught. */
	global_settings = s;

	/* Poll for data. */
	dns_poll(s);

	return 0;
}

