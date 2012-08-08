/* smbserver.c
 * By Ron Bowes
 * Created August 26, 2008
 *
 * (See LICENSE.txt)
 */

#include <stdio.h>
#include <string.h>

#include "buffer.h"
#include "crypto.h"
#include "memory.h"
#include "nameservice.h"
#include "select_group.h"
#include "smbsession.h"
#include "smb.h"
#include "tcp.h"
#include "time.h"

typedef enum
{
	/* 4-byte header */
	RECV_STATE_HEADER,
	/* current_length-byte body. */
	RECV_STATE_BODY,
} RECV_STATE_t;

static RECV_STATE_t   state;
static size_t         current_length;
/* Settings for this connection. */
/*static SMB_SETTINGS_t settings; */

void parse_SMB_COM_NEGOTIATE(int s, SMB_t *smb)
{
	uint16_t choice;
	char dialects[256];
	SMB_t *response = smb_create_response(SMB_COM_NEGOTIATE, 1, smb);

	choice = 0;
	while(buffer_can_read_ntstring(smb->data[0].buffer))
	{
		buffer_read_next_ntstring(smb->data[0].buffer, dialects, 256);
		printf("Offered dialect: %s\n", dialects);
		choice++;
	}

	/* Parameters. */
	buffer_add_int16(response->parameters[0].buffer, choice); /* Dialect index. */
	buffer_add_int8(response->parameters[0].buffer,  0x03); /* Security mode. */
	buffer_add_int16(response->parameters[0].buffer, 0x01); /* Max Mpx. */
	buffer_add_int16(response->parameters[0].buffer, 0x01); /* Max VCs. */
	buffer_add_int32(response->parameters[0].buffer, 4356); /* Buffer size. */
	buffer_add_int32(response->parameters[0].buffer, 65535); /* Max raw. */
	buffer_add_int32(response->parameters[0].buffer, 0); /* Session key. */
	buffer_add_int32(response->parameters[0].buffer, 0x8000e3fd); /* TODO: testing. CAP_STATUS32 | CAP_NT_SMBS);  Capabilities. */
	buffer_add_int32(response->parameters[0].buffer, 0x8789e1f4); /* System time. */
	buffer_add_int32(response->parameters[0].buffer, 0x01c8fedb); /* System time. */
	buffer_add_int16(response->parameters[0].buffer, 360); /* Timezone offset. */
	buffer_add_int8(response->parameters[0].buffer,  8); /* Key length. */

	/* Data. */
	buffer_add_bytes(response->data[0].buffer,    "AAAAAAAA", 8); /* Encryption key. */
	buffer_add_unicode(response->data[0].buffer, "name"); /* Server name. */
	buffer_add_unicode(response->data[0].buffer, "domain"); /* Server domain. */

	smb_send(response, s, -1, NULL); /* TODO: Fix. */
}

SELECT_RESPONSE_t incoming(void *group, int s, uint8_t *data, size_t length, char *addr, uint16_t port, void *param)
{
	buffer_t *buffer;

	switch(state)
	{
		case RECV_STATE_HEADER:
		{
			/* Sanity check -- this should never happen with select_group. */
			if(length != 4)
				DIE("Received incorrect number of bytes for NetBIOS header (likely a problem with select_group).");

			/* The header is 24-bytes in network byte order. */
			buffer = buffer_create_with_data(BO_NETWORK, data, 4);
			current_length = (buffer_read_next_int32(buffer) & 0x00FFFFFF);
			buffer_destroy(buffer);
			/* Enter body-receiving mode. */
			select_group_wait_for_bytes((select_group_t*)group, s, current_length);
			state = RECV_STATE_BODY;

			break;
		}
		case RECV_STATE_BODY:
		{
			SMB_t *smb;

			/* Sanity check -- this should never happen with select_group. */
			if(length != current_length)
				DIE("Received incorrect number of bytes for SMB (likely a problem with select_group).");

			smb = smb_create_from_data(data, length, -1, NULL); /* TODO: Fix. */

			switch(smb->header.command)
			{
				case SMB_COM_NEGOTIATE:
					parse_SMB_COM_NEGOTIATE(s, smb);
					break;
				case SMB_COM_SESSION_SETUP_ANDX:
					break;
				default:
					fprintf(stderr, "Don't know how to handle 0x%02x yet!\n", smb->header.command);
			}

			smb_destroy(smb);

			/* Return to header state. */
			select_group_wait_for_bytes((select_group_t*)group, s, 4);
			state = RECV_STATE_HEADER;

			break;
		}
		default:
			DIE("Entered an unknown state.");
	}

	return SELECT_OK;
}

SELECT_RESPONSE_t timeout(void *group, int s, void *param)
{
	DIE("SMB client didn't respond to our query.");
}

SELECT_RESPONSE_t listener(void *group, int s, struct sockaddr_in addr, void *param)
{
	int new_socket = tcp_accept(s, NULL);

	select_group_add_socket((select_group_t*)group, new_socket, SOCKET_TYPE_STREAM, NULL);
	select_set_recv((select_group_t*)group, new_socket, incoming);
	select_set_timeout((select_group_t*)group, new_socket, timeout);
	select_group_wait_for_bytes((select_group_t*)group, new_socket, 4);

	return SELECT_CLOSE_REMOVE;
}

int main(int argc, char *argv[])
{
	int s = tcp_listen("0.0.0.0", 445);
	select_group_t *sg = select_group_create();

	if(s < 0)
		return 0;

	select_group_add_socket(sg, s, SOCKET_TYPE_LISTEN, NULL);
	select_set_listen(sg, s, listener);

	/* We start by receiving a header. */
	state = RECV_STATE_HEADER;

	while(1)
	{
		select_group_do_select(sg, 3, 0);
	}
#if 0
	/* Do 'session setup' */
	length = smb_get_length(smb);
	data = safe_malloc(length);
	smb_get(smb, data, length);
	tcp_send(s, data, length);


	while(1)
	{
		select_group_do_select(sg, -1, -1);
	}

	select_group_destroy(sg);
#endif
	return 0;
}

