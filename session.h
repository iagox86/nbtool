/* dns.c
 * By Ron Bowes
 * Created April 22, 2010
 *
 * (See LICENSE.txt)
 *
 * This module is designed to be a general session class for any *cat program.
 * Although originally intended to be used for dnscat, there is no linkage
 * to DNS. Data goes in, and data comes out. The interface can be linked to
 * stdin, a process, a socket, etc. Logging, output to stdout, and more
 * also happen at this layer. 
 *
 * An instance of sessions_t is created using sessions_initialize(), which
 * can be used for storing one or more sessions. More documentation will
 * be written once the interface has settled down more. 
 *
 */

#ifndef __SESSION_TUNNEL__
#define __SESSION_TUNNEL__

#include "buffer.h"
#include "select_group.h"
#include "time.h"
#include "types.h"

/** This structure stores the state of a session. */
typedef struct
{
	struct session_t *next_session;
	char *name; /* The session that we're a part of (client only). */
	buffer_t *buffer; /* The buffer of data waiting to be sent. Cleared every time we catch up. */
	uint32_t seq; /* Keep track of the sequence number (in stream mode). */
	time_t last_seen; /* The last time a request was seen. Used for keeping track of streams. */

#ifdef WIN32
	HANDLE exec_stdin[2];  /* The stdin handle. */
	HANDLE exec_stdout[2]; /* The stdout handle. */
	DWORD  pid; /* Process id. */
	HANDLE exec_handle; /* Handle to the executing process. */
	int    socket_id; /* An arbitrary number that identifies the socket. */
#else
	int   exec_stdin[2];  /* The stdin handle. */
	int   exec_stdout[2]; /* The stdout handle. */
	pid_t pid; /* Process id. */
#endif
	NBBOOL is_eof;
} session_t;

typedef struct
{
	select_group_t *select_group;

	session_t      *first_session;
	buffer_t       *buffer_data;
	NBBOOL          multi;
	char           *exec;
	NBBOOL          exec_exit_on_close;
	NBBOOL          is_eof;
	uint32_t        timeout;
	char           *log_filename;
	FILE           *log;
	NBBOOL exec_no_stderr;
#ifdef WIN32
	int             current_socket_id; /* Starts at 0, decrements. */
#endif
} sessions_t;

/* This struct is only used for callbacks, where both the session and session list are required. */
typedef struct
{
	session_t *session;
	sessions_t *sessions;
} session_group_t;

/* Returns TRUE if there is data queued up for the given session. */
NBBOOL session_data_waiting(sessions_t *sessions, char *session_name);

/* Create and return a sessions table. This is used whenever sessions are
 * used, and should be the first function run. */
sessions_t *sessions_initialize(select_group_t *select_group, NBBOOL multi, uint32_t timeout);

/* Delete a sessions list and all close all sessions running in it. */
void sessions_delete(sessions_t *sessions);

/* Either sessions_attach_stdin() or sessions_attach_process() should be called
 * after creating the sessions object. sessions_attach_stdin() will open
 * a handle to stdin and data will be fed in/out through that. */
void sessions_attach_stdin(sessions_t *sessions);

/* Attach a process to the sessions list. A new process is started whenever
 * a session is created, and it's stopped when the session ends. */
void sessions_attach_process(sessions_t *sessions, char *exec, NBBOOL exit_on_close);

/* Turn off stderr on executed processes. */
void sessions_exec_no_stderr(sessions_t *sessions);

/* Enable logging for sessions. The log will output the same way as the output
 * to the screen. */
void sessions_enable_logging(sessions_t *sessions, char *filename);

/* Turn off logging and close the logfile. */
void sessions_close_log(sessions_t *sessions);

/* Count the number of active sessions (including closed sessions that haven't
 * finished clearing their buffers yet. */
uint32_t session_count(sessions_t *sessions);

/* Close and delete a single session. */
NBBOOL session_delete(sessions_t *sessions, char *name);

/* Create a new session and add it to the list of sessions. */
void session_initialize(sessions_t *sessions, char *session_name, uint32_t seq);

/* Check whether or not the given session exists. */
NBBOOL session_exists(sessions_t *sessions, char *name);

/* Check whether or not the given session is finished but hasn't been
 * deleted yet. This should be done before reading or writing. */
NBBOOL session_is_closed(sessions_t *sessions, char *session_name);

/* Write data to the session. Any data that comes in from the pipe, whatever
 * that pipe is, should be directed here. */
NBBOOL session_write(sessions_t *sessions, char *session_name, uint8_t *write_data, uint32_t write_length);

/* Read data that will be sent back out across the pipe. */
uint8_t *session_read(sessions_t *sessions, char *session_name, uint32_t *read_length);

/* Buffer data that should go out, but not across any particular session.
 * The data will be sent out on the first session, if it exists; otherwise,
 * it will be sent on the first session that exists. */
void session_buffer_data(sessions_t *sessions, uint8_t *data, uint32_t length);

/* Check if the given sequence number is valid. Increment the expected
 * sequence number if do_increment is TRUE. */
NBBOOL session_validate_seq(sessions_t *sessions, char *name, uint32_t seq, NBBOOL do_increment);

/* Get the next sequence number (and increment it). */
uint32_t session_get_seq(sessions_t *sessions, char *session_name);

/* Display the list of sessions (for debugging). */
void sessions_print(sessions_t *sessions);

#endif
