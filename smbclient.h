/* smbclient.h
 * By Ron
 * Created August 26, 2008
 *
 * (See LICENSE.txt)
 *
 * Tasks related to SMB clients.
 *
 * Not currently being used.
 */

#ifndef __SMBCLIENT_H__
#define __SMBCLIENT_H__

#include "smb.h"
#include "types.h"

typedef enum
{
	LOGONTYPE_DEFAULT,   /* Sends both LM and NTLMv1. */
	LOGONTYPE_LM,        /* Sends only LM, NTLM field is blank. */
	LOGONTYPE_NTLM,      /* Sends only NTLM, both LM and NTLM fields contain it. */
	LOGONTYPE_DEFAULTv2, /* Sends both LMv2 and NTLMv2. */
	LOGONTYPE_LMv2,      /* Sends only LMv2. */
	LOGONTYPE_ANONYMOUS, /* Log in anonymously (ie, null session). */
} SMB_LOGONTYPE_t;

typedef enum
{
	/* Starting state, before anything is sent. */
	RECV_STATE_START,
	/* Initial "session request" */
	RECV_STATE_SESSION_REQUEST,
	/* 4-byte header */
	RECV_STATE_HEADER,
	/* current_length-byte body. */
	RECV_STATE_BODY,
	/* Testing. */
	RECV_STATE_TESTING
} RECV_STATE_t;

typedef enum
{
/* TODO: Make these do something. */
	SMBCLIENT_OK,    /* Everything's good. */
	SMBCLIENT_CLOSE, /* Kill the connection and clean up. */
} SMBCLIENT_RESULT_t;

typedef enum
{
	SMBCLIENT_CONNECTED,
	SMBCLIENT_NETBIOS_SESSION_SET_UP,
	SMBCLIENT_PROTOCOL_NEGOTIATED,
	SMBCLIENT_SESSION_SET_UP,
	SMBCLIENT_SESSION_SET_UP_GUEST,
	SMBCLIENT_SESSION_LOGOFF,
	SMBCLIENT_TREE_CONNECTED,
	SMBCLIENT_TREE_DISCONNECTED,
	SMBCLIENT_FILE_CREATED,
	SMBCLIENT_MSRPC_BIND_ACK,
	SMBCLIENT_MSRPC_BIND_FAILED,
	SMBCLIENT_MSRPC_NETSHAREENUMALL,
	SMBCLIENT_MSRPC_CONNECT4,
	SMBCLIENT_MSRPC_ENUMDOMAINS,
	SMBCLIENT_MSRPC_LOOKUPDOMAIN,
	SMBCLIENT_MSRPC_OPENDOMAIN,
	SMBCLIENT_MSRPC_QUERYDISPLAYINFO,
	SMBCLIENT_MSRPC_QUERYDOMAININFO2,

	SMBCLIENT_WINREG_OPENHKU,
	SMBCLIENT_WINREG_ENUMKEY,

	SMBCLIENT_MSRPC_UNKNOWN,
	SMBCLIENT_MSRPC_ERROR,
	SMBCLIENT_UNKNOWN_COMMAND /* "extra" field is the command's ID. */
} SMBCLIENT_EVENT_t;

typedef enum
{
	MSRPC_NULL = 0,
	MSRPC_SENT_NETSHAREENUMALL,
	MSRPC_SENT_CONNECT4,
	MSRPC_SENT_ENUMDOMAINS,
	MSRPC_SENT_LOOKUPDOMAIN,
	MSRPC_SENT_OPENDOMAIN,
	MSRPC_SENT_QUERYDISPLAYINFO,
	MSRPC_SENT_QUERYDOMAININFO2,
} SMBCLIENT_MSRPC_STATE_t;

/* The parameters sent back for the calls we've implemented. */
typedef struct
{
	char **names;
	uint32_t name_count;
} NETSHAREENUMALL_t;

typedef struct
{
	uint8_t connect_handle[0x14];
} CONNECT4_t;

typedef struct
{
	char **names;
	uint32_t name_count;
} ENUMDOMAINS_t;

typedef struct
{
	uint32_t  count;
	uint8_t   revision;
	uint16_t  authority_high;
	uint32_t  authority;
	uint32_t *subauthority;
} LOOKUPDOMAIN_t;
typedef struct
{
	uint8_t domain_handle[0x14];
} OPENDOMAIN_t;

typedef struct
{
	uint32_t rid;
	uint32_t flags;

	char   *name;
	char   *fullname;
	char   *description;
} QUERYDISPLAYINFO_ELEMENT_t;

typedef struct
{
	size_t count;
	QUERYDISPLAYINFO_ELEMENT_t *elements;
} QUERYDISPLAYINFO_t;

typedef struct
{
	uint16_t min_password_length;
	uint16_t password_history_length;
	uint32_t password_properties;
	uint32_t max_password_age_high;
	uint32_t max_password_age_low;
	uint32_t min_password_age_high;
	uint32_t min_password_age_low;

	uint32_t create_time_high;
	uint32_t create_time_low;

	uint32_t lockout_duration_high;
	uint32_t lockout_duration_low;
	uint32_t lockout_window_high;
	uint32_t lockout_window_low;

	uint16_t lockout_threshold;
} QUERYDOMAININFO2_t;


typedef SMBCLIENT_RESULT_t(smbclient_event)(void *client, SMBCLIENT_EVENT_t event, void *extra);
typedef SMBCLIENT_RESULT_t(smbclient_protocol_error)(void *client,    uint32_t error, char *strerror);
typedef SMBCLIENT_RESULT_t(smbclient_connection_error)(void *client,  int err, char *strerror);

typedef struct
{
	/* The socket. */
	int s;

	/* Sequence number and session_key (used for message signing). */
	uint32_t sequence;
	uint8_t  mac_key[40];

	/* The protocol state we're in. */
	RECV_STATE_t   state;

	/* The number of bytes we're currently waiting for. */
	size_t         current_length;

	/* Are we authenticated? */
	NBBOOL        authenticated;

	/* Callbacks. */
	smbclient_event            *event_callback;
	smbclient_protocol_error   *protocol_error_callback;
	smbclient_connection_error *connection_error_callback;

	/* Received from the server. */
	uint8_t     encryption_key[8];
	uint8_t     encryption_key_length;
	char        domain_name[256];
	char        server_name[256];
	uint64_t    system_time;
	uint32_t    system_time_unix;
	uint16_t    system_timezone;
	uint16_t    uid;
	uint16_t    tid;
	SMB_CAPABILITIES_t server_capabilities;
	uint32_t    server_session_key;
	uint16_t    fid;

	/* Negotiated settings. */
	NBBOOL     extended_security;
	NBBOOL     error_nt;
	NBBOOL     unicode;

	/* Set by the user. */
	int     verbose;
	int     check_signature;

	/* MSRPC State. */
	SMBCLIENT_MSRPC_STATE_t msrpc_state;

	/* MSRPC Data. */
	uint16_t service_length;
	uint8_t *service;

	NBBOOL bound;
	uint8_t service_uuid[16];
	uint8_t send_syntax[16];
	uint8_t receive_syntax[16];

	/* Returned MSRPC packets (since we often have to look back during the protocol. */
	NETSHAREENUMALL_t  netshareenumall;
	CONNECT4_t         connect4;
	ENUMDOMAINS_t      enumdomains;
	LOOKUPDOMAIN_t     lookupdomain;
	OPENDOMAIN_t       opendomain;
	QUERYDISPLAYINFO_t querydisplayinfo;
	QUERYDOMAININFO2_t querydomaininfo2;

} SMBCLIENT_t;

/* MSRPC Services. */
#define SAMR_PATH      ("\\samr")
#define SAMR_UUID      ((uint8_t*)"\x78\x57\x34\x12\x34\x12\xcd\xab\xef\x00\x01\x23\x45\x67\x89\xac")
#define SAMR_VERSION   ((uint16_t)0x01)

#define SRVSVC_PATH    ("\\srvsvc")
#define SRVSVC_UUID    ((uint8_t*)"\xc8\x4f\x32\x4b\x70\x16\xd3\x01\x12\x78\x5a\x47\xbf\x6e\xe1\x88")
#define SRVSVC_VERSION ((uint16_t)0x03)

#define TRANSFER_SYNTAX ((uint8_t*)"\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60")

/* MSRPC Response types. */
typedef enum
{
	MSRPC_RESPONSE = 0x02,
	MSRPC_FAULT    = 0x03,
	MSRPC_BIND_ACK = 0x0c,
} MSRPC_TYPE_t;

SMBCLIENT_t *smbclient_create();

/* The functions below set up callbacks. When either of the error callbacks are made, nothing more will be done with the socket
 * until select() is entered again; in other words, functions are free to close the socket and remove it from the select_group. */
void smbclient_set_event_callback(SMBCLIENT_t *smbclient, smbclient_event *event_callback);
void smbclient_set_protocol_error_callback(SMBCLIENT_t *smbclient, smbclient_protocol_error *protocol_error_callback);
void smbclient_set_connection_error_callback(SMBCLIENT_t *smbclient, smbclient_connection_error *connection_error_callback);

/* These functions are for direct interaction with the server. */
void smbclient_connect(SMBCLIENT_t *smbclient, char *host, uint16_t port, NBBOOL try_other_ports, select_group_t *sg);
void smbclient_netbios_start_session(SMBCLIENT_t *smbclient, char *netbios_name);
void smbclient_negotiate_protocol(SMBCLIENT_t *smbclient);
void smbclient_logon(SMBCLIENT_t *smbclient, char *domain, char *username, char *password, char *hash, SMB_LOGONTYPE_t logontype);
void smbclient_logoff(SMBCLIENT_t *smbclient);
void smbclient_tree_connect(SMBCLIENT_t *smbclient, char *path);
void smbclient_tree_disconnect(SMBCLIENT_t *smbclient);
void smbclient_nt_create(SMBCLIENT_t *smbclient, char *path);

void smbclient_msrpc_bind(SMBCLIENT_t *smbclient, uint8_t *interface, uint16_t interface_version, uint8_t *transfer_syntax);
void smbclient_msrpc_call_function(SMBCLIENT_t *smbclient, uint16_t opnum, buffer_t *arguments);
void smbclient_send_srvsvc_netshareenumall(SMBCLIENT_t *smbclient);
void smbclient_send_samr_connect4(SMBCLIENT_t *smbclient);
void smbclient_send_samr_enumdomains(SMBCLIENT_t *smbclient);
void smbclient_send_samr_lookupdomain(SMBCLIENT_t *smbclient, char *domain);
void smbclient_send_samr_opendomain(SMBCLIENT_t *smbclient);
void smbclient_send_samr_querydisplayinfo(SMBCLIENT_t *smbclient, uint32_t index);
void smbclient_send_samr_querydomaininfo2(SMBCLIENT_t *smbclient, uint16_t level);

/* Miscellaneous functions. */
void smbclient_raise_verbose(SMBCLIENT_t *smbclient);
void smbclient_raise_check_signature(SMBCLIENT_t *smbclient);

#endif
