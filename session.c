/* session.c
 * Created April 22, 2010
 * By Ron Bowes
 *
 * (See LICENSE.txt)
 *
 * Implements a session table for dnscat and, potentially, other tunnels. 
 */

#define _POSIX_SOURCE /* For kill(). */

#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#else
#include <netdb.h>
#include <signal.h>
#include <strings.h>
#include <unistd.h>
#include <sys/types.h>
#endif

#include "buffer.h"
#include "memory.h"
#include "select_group.h"
#include "types.h"

#include "session.h"

/* Make pipes easier to work with. */
#define PIPE_READ  0
#define PIPE_WRITE 1

void sessions_expire(sessions_t *sessions)
{
	/* Start at the first session. */
	session_t *session = sessions->first_session;

	while(session)
	{
		/* Check if the session has timed out. */
		if((time(NULL) - session->last_seen) > sessions->timeout)
		{
			/* If it has, delete the session and start over (we don't want to be in the middle of
			 * walking a list when we delete something from it). */
			fprintf(stderr, "Session timed out: %s\n", session->name);
			session_delete(sessions, session->name);
			session = sessions->first_session;
		}
		else
		{
			session = (session_t*)session->next_session;
		}
	}
}

/* Check if ANY sessions have data waiting. */
static NBBOOL sessions_data_waiting(sessions_t *sessions)
{
	session_t *session = sessions->first_session;

	/* Check if there is any buffered data waiting to go out. */
	if(buffer_can_read_int8(sessions->buffer_data))
	{
fprintf(stderr, "buffer_data has data waiting!\n");
		return TRUE;
	}

	while(session)
	{
		if(session_data_waiting(sessions, session->name))
		{
			/* fprintf(stderr, "Data is still waiting for session: %s\n", session->name); */
			return TRUE;
		}

		session = (session_t*)session->next_session;
	}

fprintf(stderr, "no data is waiting\n");
	return FALSE;
}

void sessions_do_events(sessions_t *sessions)
{
	static NBBOOL recursion = FALSE;
/*	sessions_print(sessions); */

	if(recursion)
	{
		/*fprintf(stderr, "Skipping do_events to prevent infinite recursion.\n");*/
		return;
	}

	/* Make sure this won't infinitely recurse. */
	recursion = TRUE;

	/* See if any sessions have timed out. */
	sessions_expire(sessions);

	/* Check for EOF. */
	if(sessions->is_eof && !sessions_data_waiting(sessions))
	{
		fprintf(stderr, "EOF detected and buffers are empty; terminating.\n");
		exit(0);
	}

	/* If we're in 'exec' mode, do housekeeping. */
	if(sessions->exec)
	{
		/* Check if any terminated processes are finished. */
		session_t *session = sessions->first_session;

		while(session)
		{
			if(session->is_eof && !session_data_waiting(sessions, session->name))
			{
				fprintf(stderr, "Process is finished and data has been sent; closing session\n");
				session_delete(sessions, session->name);
				session = sessions->first_session;
			}
			else
			{
				session = (session_t*)session->next_session;
			}
		}
	}

	/* Infinite recursion is no longer an issue. */
	recursion = FALSE;
}

/* Returns the session object, or NULL if it wasn't found. If no name is passed
 * (name = NULL), it'll return the first session. */
static session_t *session_get(sessions_t *sessions, char *name)
{
	session_t *session;

	/* Do any cleanup, expires, etc. */
	sessions_do_events(sessions);

	session = sessions->first_session;

	while(session)
	{
		if(!strcasecmp(session->name, name))
			return session;

		session = (session_t*)session->next_session;
	}

	return NULL;
}

/* This is the "front door" for data coming into the session through
 * stdin. When data arrives on stdin, the data should be passed to this
 * function. If the session is actually using stdin for input, this will
 * be read and, more then likely, come back out a session_read() call.
 */
static void session_feed(sessions_t *sessions, char *name, uint8_t *data, uint32_t length)
{
	session_t *session = session_get(sessions, name);

	if(!session)
	{
		fprintf(stderr, "Session not found: %s\n", name);
		return;
	}

	buffer_add_bytes(session->buffer, data, length);
}

/* Check if we have data waiting. */
NBBOOL session_data_waiting(sessions_t *sessions, char *session_name)
{
	session_t *session = session_get(sessions, session_name);
	if(!session)
		return FALSE;

	return buffer_can_read_int8(session->buffer) || buffer_can_read_int8(sessions->buffer_data);
}

/* This is the callback function for STDIN traffic. It is also used for incoming exec data. Simply buffer the
 * data and return. The process of buffering the data will also trigger a send, as long as sending is possible. */
static SELECT_RESPONSE_t stdin_callback(void *group, int socket, uint8_t *data, size_t length, char *addr, uint16_t port, void *s)
{
	sessions_t *sessions = ((sessions_t*)s);

	/* If 'multi' is set, a lot more processing is done. The message is
	 * required to be "session: data". */
	if(sessions->multi)
	{
		char *session_name;
		uint8_t *session_data;

		session_name = (char*)data;
		session_data = (uint8_t*)strstr((char*)data, ": ");
		if(!session_data)
		{
			fprintf(stderr, "Format: <session>: <data>\n");
		}
		else
		{
			session_data[0] = '\0';
			session_data += 2;
			length = length - strlen(session_name) - 2;

			session_feed(sessions, session_name, session_data, length);
		}
	}
	else
	{
		if(!sessions->first_session)
			session_buffer_data(sessions, data, length);
		else
			session_feed(sessions, sessions->first_session->name, data, length);
	}

	return SELECT_OK;
}

/* This fires when the stdin socket closes. */
static SELECT_RESPONSE_t stdin_closed_callback(void *group, int socket, void *s)
{ 
	sessions_t *sessions = ((sessions_t*)s);

	if(sessions_data_waiting(sessions))
	{
		fprintf(stderr, "EOF detected, waiting to send queued data...\n");
		sessions->is_eof = TRUE;
	}
	else
	{
		fprintf(stderr, "EOF detected, terminating.\n");
		exit(0);
	}

	/* Remove the socket from the select() to prevent continual bouncing. */
	return SELECT_CLOSE_REMOVE;
}

/* This fires when the exec socket closes. */
static SELECT_RESPONSE_t exec_closed_callback(void *group, int socket, void *s)
{
	session_group_t *session_group = ((session_group_t*)s);
	session_t *session   = session_group->session;

	fprintf(stderr, "Process terminated, emptying buffers and closing session...\n");
	session->is_eof = TRUE;

	/* Remove the socket from the select() to prevent continual bouncing. */
	return SELECT_CLOSE_REMOVE;
}

void sessions_attach_stdin(sessions_t *sessions)
{
#ifdef WIN32
	/* On Windows, the stdin_handle is quire complicated, and involves a sub-thread. */
	HANDLE stdin_handle = get_stdin_handle();
	select_group_add_pipe(sessions->select_group, -1, stdin_handle, sessions);
	select_set_recv(sessions->select_group, -1, stdin_callback);
	select_set_closed(sessions->select_group, -1, stdin_closed_callback);
#else
	/* On Linux, the stdin_handle is easy. */
	int stdin_handle = STDIN_FILENO;
	select_group_add_socket(sessions->select_group, stdin_handle, SOCKET_TYPE_STREAM, sessions);
	select_set_recv(sessions->select_group, stdin_handle, stdin_callback);
	select_set_closed(sessions->select_group, stdin_handle, stdin_closed_callback);
#endif
}

void sessions_attach_process(sessions_t *sessions, char *exec, NBBOOL exit_on_close)
{
	sessions->exec = exec;
	sessions->exec_exit_on_close = exit_on_close;
}

void sessions_exec_no_stderr(sessions_t *sessions)
{
	sessions->exec_no_stderr = TRUE;
}

void sessions_enable_logging(sessions_t *sessions, char *filename)
{
	sessions->log_filename = filename;
#ifdef WIN32
	fopen_s(&sessions->log, filename, "a");
#else
	sessions->log = fopen(filename, "a");
#endif
	if(!sessions->log)
		nbdie("Failed to open logfile");
	fprintf(stderr, "Opened logfile: %s\n", sessions->log_filename);
}

void sessions_close_log(sessions_t *sessions)
{
	if(sessions->log)
	{
		fclose(sessions->log);
		sessions->log = NULL;
		sessions->log_filename = NULL;
		fprintf(stderr, "Closed logfile.\n");
	}
}

sessions_t *sessions_initialize(select_group_t *select_group, NBBOOL multi, uint32_t timeout)
{
	sessions_t *new_sessions = (sessions_t*) safe_malloc(sizeof(sessions_t));
	memset(new_sessions, 0, sizeof(sessions_t));

	new_sessions->select_group = select_group;
	new_sessions->multi = multi;
	new_sessions->buffer_data = buffer_create(BO_NETWORK);
	new_sessions->timeout = timeout;

	return new_sessions;
}

static session_t *session_create(sessions_t *sessions, char *name, uint32_t seq)
{
	/* Create and initialize a new session. */
	session_t *new_session = (session_t*) safe_malloc(sizeof(session_t));
	new_session->next_session = NULL;
	new_session->name         = safe_strdup(name);
	new_session->buffer       = buffer_create(BO_NETWORK);
	new_session->seq          = seq;
	new_session->last_seen    = time(NULL);

	/* Check if it's the first one. */
	if(sessions->first_session == NULL)
	{
		sessions->first_session = new_session;
	}
	else
	{
		/* Find the last session. */
		session_t *session = sessions->first_session;
		while(session->next_session)
			session = (session_t *)session->next_session;

		/* Add it to the end. */
		session->next_session = (struct session_t*)new_session;
	}

	/* Done! */
	return new_session;
}

/* Returns the number of sessions. */
uint32_t session_count(sessions_t *sessions)
{
	uint32_t count = 0;
	session_t *session = sessions->first_session;

	while(session)
	{
		session = (session_t *)session->next_session;
		count++;
	}

	return count;
}

static void session_free(sessions_t *sessions, session_t *session)
{
	fprintf(stderr, "Killling session: %s\n", session->name);

	if(sessions->exec)
	{
		if(session->pid > 0)
		{
			fprintf(stderr, "Killing process %d\n", session->pid);
#ifdef WIN32
			select_group_remove_socket(sessions->select_group, session->socket_id);
			CloseHandle(session->exec_stdin[PIPE_WRITE]);
			CloseHandle(session->exec_stdout[PIPE_READ]);
			/*kill(session->pid, SIGINT);*/
			TerminateProcess(session->exec_handle, 0);

#else
			select_group_remove_socket(sessions->select_group, session->exec_stdout[PIPE_READ]);
			close(session->exec_stdin[PIPE_WRITE]);
			close(session->exec_stdout[PIPE_READ]);
			kill(session->pid, SIGINT);
#endif
		}
	}

	safe_free(session->name);
	session->name = NULL;

	buffer_destroy(session->buffer);
	session->buffer = NULL;

	safe_free(session);
}

NBBOOL session_delete(sessions_t *sessions, char *name)
{
	session_t *session = sessions->first_session;
	session_t *next_session;

	/* Check if we have any sessions. */
	if(!session)
	{
		fprintf(stderr, "There are no sessions to delete\n");
		return FALSE;
	}

	/* Check if the first session is the one we're deleting. */
	if(!strcasecmp(sessions->first_session->name, name))
	{
		fprintf(stderr, "Found session to delete: %s\n", name);
		session = (session_t*)sessions->first_session->next_session;
		session_free(sessions, sessions->first_session);
		sessions->first_session = session;

		return TRUE;
	}

	/* Check if any of the other sessions match. */
	while((next_session = (session_t *)session->next_session) != NULL)
	{
		if(!strcasecmp(next_session->name, name))
		{
			fprintf(stderr, "Found session to delete: %s\n", name);
			session->next_session = next_session->next_session;
			session_free(sessions, next_session);

			return TRUE;
		}

		session = next_session;
	}

	return FALSE;
}

void sessions_delete(sessions_t *sessions)
{
	session_t *session = sessions->first_session;
	session_t *next_session;

	sessions_close_log(sessions);

	while(session)
	{
		next_session = (session_t*)session->next_session;
		session_free(sessions, session);
		session = (session_t*)next_session;
	}

	buffer_destroy(sessions->buffer_data);

	sessions->first_session = NULL;
	safe_free(sessions);
}

static SELECT_RESPONSE_t exec_callback(void *group, int socket, uint8_t *data, size_t length, char *addr, uint16_t port, void *s)
{
	session_group_t *session_group = ((session_group_t*)s);

	session_feed(session_group->sessions, session_group->session->name, data, length);

	return SELECT_OK;
}

static NBBOOL session_attach_process(sessions_t *sessions, session_t *session, char *process)
{
#ifdef WIN32
	STARTUPINFOA         startupInfo;
	PROCESS_INFORMATION  processInformation;
	SECURITY_ATTRIBUTES  sa;
	session_group_t *session_group = (session_group_t*) safe_malloc(sizeof(session_group_t));
	session_group->session  = session;
	session_group->sessions = sessions;

	/* Create a security attributes structure. This is required to inherit handles. */
	ZeroMemory(&sa, sizeof(SECURITY_ATTRIBUTES));
	sa.nLength              = sizeof(SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = NULL;
	sa.bInheritHandle       = TRUE;

	/* Create the anonymous pipes. */
	if(!CreatePipe(&session->exec_stdin[PIPE_READ], &session->exec_stdin[PIPE_WRITE], &sa, 0))
		nbdie("exec: Couldn't create pipe for stdin");
	if(!CreatePipe(&session->exec_stdout[PIPE_READ], &session->exec_stdout[PIPE_WRITE], &sa, 0))
		nbdie("exec: Couldn't create pipe for stdout");

	fprintf(stderr, "Attempting to load the program: %s\n", process);

	/* Initialize the STARTUPINFO structure. */
	ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
	startupInfo.cb         = sizeof(STARTUPINFO);
	startupInfo.dwFlags    = STARTF_USESTDHANDLES;
	startupInfo.hStdInput  = session->exec_stdin[PIPE_READ];
	startupInfo.hStdOutput = session->exec_stdout[PIPE_WRITE];
	if(!sessions->exec_no_stderr)
		startupInfo.hStdError = session->exec_stdout[PIPE_WRITE];

	/* Initialize the PROCESS_INFORMATION structure. */
	ZeroMemory(&processInformation, sizeof(PROCESS_INFORMATION));

	/* Create the actual process with an overly-complicated CreateProcess function. */
	if(!CreateProcessA(NULL, process, 0, &sa, TRUE, CREATE_NO_WINDOW, 0, NULL, &startupInfo, &processInformation))
	{
		fprintf(stderr, "Failed to create the process");
		exit(1);
	}

	/* Save the process id and the handle. */
	session->pid = processInformation.dwProcessId;
	session->exec_handle = processInformation.hProcess;
	session->socket_id = --sessions->current_socket_id;

	/* Close the duplicate pipes we created -- this lets us detect the proicess termination. */
	CloseHandle(session->exec_stdin[PIPE_READ]);
	CloseHandle(session->exec_stdout[PIPE_WRITE]);
	if(!sessions->exec_no_stderr)
		CloseHandle(session->exec_stdout[PIPE_WRITE]);

	fprintf(stderr, "Successfully created the process!\n\n");

	/* On Windows, add the sub-process's stdout as a pipe. */
	select_group_add_pipe(sessions->select_group, session->socket_id, session->exec_stdout[PIPE_READ], session_group);
	select_set_recv(sessions->select_group, session->socket_id, exec_callback);
	select_set_closed(sessions->select_group, session->socket_id, exec_closed_callback);
#else
	session_group_t *session_group = (session_group_t*) safe_malloc(sizeof(session_group_t));
	session_group->session  = session;
	session_group->sessions = sessions;

	fprintf(stderr, "Attempting to start process '%s' for session %s\n", process, session->name);

	/* Create communication channels. */
	if(pipe(session->exec_stdin) == -1)
		nbdie("exec: couldn't create pipe for STDIN");

	if(pipe(session->exec_stdout) == -1)
		nbdie("exec: couldn't create pipe for STDOUT");

	session->pid = fork();

	if(session->pid == -1)
		nbdie("exec: couldn't create process");

	if(session->pid == 0)
	{
		/* Copy the pipes. */
		if(dup2(session->exec_stdin[PIPE_READ], STDIN_FILENO) == -1)
			nbdie("exec: couldn't duplicate STDIN handle");
		if(dup2(session->exec_stdout[PIPE_WRITE], STDOUT_FILENO) == -1)
			nbdie("exec: couldn't duplicate STDOUT handle");
		if(sessions->exec_no_stderr)
		{
			session->exec_stdout[PIPE_WRITE] = 0;
		}
		else
		{
			if(dup2(session->exec_stdout[PIPE_WRITE], STDERR_FILENO) == -1)
				nbdie("exec: couldn't duplicate STDERR handle");
		}

		/* Execute the new process. */
		execlp("/bin/sh", "sh", "-c", process, (char*) NULL);

		/* If execlp returns, bad stuff happened. */
		fprintf(stderr, "exec: execlp failed");
		return FALSE;
	}

	fprintf(stderr, "Started: %s (pid: %d)\n", process, session->pid);
	close(session->exec_stdin[PIPE_READ]);
	close(session->exec_stdout[PIPE_WRITE]);

	/* On Linux, add the sub-process's stdout as a socket. */
	select_group_add_socket(sessions->select_group, session->exec_stdout[PIPE_READ], SOCKET_TYPE_STREAM, session_group);
	select_set_recv(sessions->select_group, session->exec_stdout[PIPE_READ], exec_callback);
	select_set_closed(sessions->select_group, session->exec_stdout[PIPE_READ], exec_closed_callback);
#endif

	return TRUE;
}

/* TODO: Look into this error:
 ./dnscat --domain skullseclabs.org --dns localhost --exec "./test"
Starting DNS requests to localhost:53...
Creating new session yllwulcp with sequence number 286781387
Attempting to start process './test' for session yllwulcp
Started: ./test (pid: 3603)
Process terminated, emptying buffers and closing session...
Skipping do_events to prevent infinite recursion.
Skipping do_events to prevent infinite recursion.
Skipping do_events to prevent infinite recursion.
Skipping do_events to prevent infinite recursion.
Skipping do_events to prevent infinite recursion.
Skipping do_events to prevent infinite recursion.
Skipping do_events to prevent infinite recursion.
Skipping do_events to prevent infinite recursion.
Process is finished and data has been sent; closing session
Found session to delete: yllwulcp
Killling session: yllwulcp
Killing process 3603
Session yllwulcp doesn't exist; accepting sequence number 286781388 <----------
Session has went away, exiting.
Sending error: ERROR_FIN (3)
*/

void session_initialize(sessions_t *sessions, char *session_name, uint32_t seq)
{
	if(!session_get(sessions, session_name))
	{
		session_t *session;
		fprintf(stderr, "Creating new session %s with sequence number %d\n", session_name, seq);
		session = session_create(sessions, session_name, seq);

		/* If we're in exec mode, attach the process. */
		/* TODO: This is likely where I'll bind it to a socket. */
		if(sessions->exec)
		{
			session_attach_process(sessions, session, sessions->exec);
		}
	}
}

NBBOOL session_exists(sessions_t *sessions, char *name)
{
	return (session_get(sessions, name) != NULL);
}

NBBOOL session_is_closed(sessions_t *sessions, char *session_name)
{
	session_t *session;

	session = session_get(sessions, session_name);

	if(!session)
		return FALSE;

	if(session->is_eof && !session_data_waiting(sessions, session_name))
		return TRUE;

	return FALSE;
}

/* Send data into the given session. This should be data that comes in off the
 * network, which will be passed onto wherever the session is sending data
 * (stdout, sub-process, etc). 
 */
NBBOOL session_write(sessions_t *sessions, char *session_name, uint8_t *write_data, uint32_t write_length)
{
	uint32_t i;

	session_t *session;

	session = session_get(sessions, session_name);

	if(!session)
		return FALSE;

	if(session_is_closed(sessions, session_name))
		return FALSE;

	/* Update the last_seen time. */
	session->last_seen = time(NULL);

	/* For now, we simply prepend the session name and write the data to the console. */
	if(write_length > 0)
	{
		if(session->pid)
		{
#ifdef WIN32
			DWORD written;
			WriteFile(session->exec_stdin[PIPE_WRITE], write_data, write_length, &written, NULL);
#else
			write(session->exec_stdin[PIPE_WRITE], write_data, write_length);
			fflush(NULL);
#endif
		}
		else
		{
			if(sessions->multi)
			{
				printf("%s: ", session->name);
				if(sessions->log)
					fprintf(sessions->log, "%s: ", session->name);

				for(i = 0; i < write_length; i++)
				{
					putchar(write_data[i]);
					if(sessions->log)
						fputc(write_data[i], sessions->log);

					if(write_data[i] == '\n')
					{
						printf("%s: ", session->name);
						if(sessions->log)
							fprintf(sessions->log, "%s: ", session->name);
					}
				}
				printf("\n");
				if(sessions->log)
					fprintf(sessions->log, "\n");
			}
			else
			{
				for(i = 0; i < write_length; i++)
				{
					putchar(write_data[i]);
					if(sessions->log)
						fputc(write_data[i], sessions->log);
					fflush(NULL);
				}
			}
		}
	}

	return TRUE;
}

/* Read data from the session that will be sent out across the network. This
 * will return up to read_length bytes (and will return the number of bytes
 * read in read_length as well). The memory returned has to be freed. 
 *
 * If the session isn't found, NULL is returned. If no data is waiting, the
 * empty string is returned and read_length is set to 0. 
 */
uint8_t *session_read(sessions_t *sessions, char *session_name, uint32_t *read_length)
{
	uint32_t i = 0;

	buffer_t *incoming;
	buffer_t *response;
	session_t *session;

	session = session_get(sessions, session_name);
	if(!session)
		return NULL;

	if(session_is_closed(sessions, session_name))
		return NULL;

	if(buffer_can_read_int8(sessions->buffer_data))
	{
		incoming = sessions->buffer_data;
	}
	else
	{
		if(!session)
			return NULL;
		incoming = session->buffer;
	}

	response = buffer_create(BO_NETWORK);
	while(buffer_can_read_int8(incoming) && i < *read_length)
	{
		if(sessions->log)
			fputc(buffer_peek_next_int8(incoming), sessions->log);
		buffer_add_int8(response, buffer_read_next_int8(incoming));
		i++;
	}

	/* Clear whichever buffer we're using if we're at the end. */
	if(!buffer_can_read_int8(incoming))
		buffer_clear(incoming);

	return buffer_create_string_and_destroy(response, read_length);
}


/* This is another "front door" for data coming into the session. The
 * difference between this and session_feed() is that this one doesn't
 * require a session name, and data sent into here will jump the queue
 * (ie, come out first). The primary reason for this function is for
 * buffering data when no sessions are connected. */
void session_buffer_data(sessions_t *sessions, uint8_t *data, uint32_t length)
{
	buffer_add_bytes(sessions->buffer_data, data, length);
}

NBBOOL session_validate_seq(sessions_t *sessions, char *name, uint32_t seq, NBBOOL do_increment)
{
	session_t *session = session_get(sessions, name);
	if(!session)
	{
		fprintf(stderr, "Session %s doesn't exist; accepting sequence number %d\n", name, seq);
		return TRUE;
	}

	/* Note: we have to validate against the next sequence number. */
	if(seq != session->seq + (do_increment ? 1 : 0))
	{
		fprintf(stderr, "Failed to validate sequence number for session %s (sequence should be %d, was %d)\n", name, session->seq + (do_increment ? 1 : 0), seq);
		return FALSE;
	}

	if(do_increment)
		session->seq = session->seq + 1;

	return TRUE;
}

uint32_t session_get_seq(sessions_t *sessions, char *session_name)
{
	session_t *session = session_get(sessions, session_name);
	if(!session)
		return -1;

	session->seq = session->seq + 1;

	return session->seq;
}

void sessions_print(sessions_t *sessions)
{
	session_t *session = sessions->first_session;

	while(session)
	{
		fprintf(stderr, "%s: %d bytes waiting\n", session->name, buffer_get_length(session->buffer));
		session = (session_t*)session->next_session;
	}
	if(buffer_can_read_int8(sessions->buffer_data))
		fprintf(stderr, "%d bytes buffered\n", buffer_get_length(sessions->buffer_data));
}

