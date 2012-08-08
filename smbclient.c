/* smbclient.c
 * By Ron
 * Created August 26, 2008
 *
 * (See LICENSE.txt)
 */

#include <getopt.h>
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

#include "smbclient.h"

/* Grabbed the list of protocols from Windows 2000. */
/*static char          *protocols[] = {"PC NETWORK PROGRAM 1.0", "LANMAN1.0", "Windows for Workgroups 3.1a", "LM1.2X002", "LANMAN2.1", "NT LM 0.12", (char*)0};*/
static char          *protocols[] = {"NT LM 0.12", (char*)0};

/* Local function prototypes. */
static uint32_t smbclient_msrpc_parse(SMBCLIENT_t *smbclient, SMB_t *smb, size_t parameter_position, uint16_t parameter_size, size_t data_position, uint16_t data_size);

static uint32_t smbclient_parse_srvsvc_netshareenumall(buffer_t *data, NETSHAREENUMALL_t *result);
static uint32_t smbclient_parse_samr_connect4(buffer_t *data, CONNECT4_t *result);
static uint32_t smbclient_parse_samr_enumdomains(buffer_t *data, ENUMDOMAINS_t *result);
static uint32_t smbclient_parse_samr_lookupdomain(buffer_t *data, LOOKUPDOMAIN_t *result);
static uint32_t smbclient_parse_samr_opendomain(buffer_t *data, OPENDOMAIN_t *result);
static uint32_t smbclient_parse_samr_querydisplayinfo(buffer_t *data, QUERYDISPLAYINFO_t *result, SMBCLIENT_t *smbclient);
static uint32_t smbclient_parse_samr_querydomaininfo2(buffer_t *data, QUERYDOMAININFO2_t *result, SMBCLIENT_t *smbclient);

void parse_SMB_COM_TRANSACTION(SMBCLIENT_t *smbclient, SMB_t *smb)
{
	if(smb_is_error(smb))
	{
		smbclient->protocol_error_callback(smbclient, smb->header.status, smb_get_error_nt(smb));
	}
	else
	{
		uint16_t parameter_count, parameter_offset;
		uint16_t data_count, data_offset;

		uint32_t result;

		buffer_read_next_int16(smb->parameters[0].buffer); /* Total word count. */
		buffer_read_next_int16(smb->parameters[0].buffer); /* Total data count. */
		buffer_read_next_int16(smb->parameters[0].buffer); /* Reserved. */
		parameter_count  = buffer_read_next_int16(smb->parameters[0].buffer); /* Parameter count. */
		parameter_offset = buffer_read_next_int16(smb->parameters[0].buffer); /* Parameter offset. */
		buffer_read_next_int16(smb->parameters[0].buffer); /* Parameter displacement. */
		data_count  = buffer_read_next_int16(smb->parameters[0].buffer); /* Data count. */
		data_offset = buffer_read_next_int16(smb->parameters[0].buffer); /* Data offset. */
		buffer_read_next_int16(smb->parameters[0].buffer); /* Data displacement. */
		buffer_read_next_int8(smb->parameters[0].buffer);  /* Setup count. */
		buffer_read_next_int8(smb->parameters[0].buffer);  /* Reserved. */

		/* Convert the parameter offset to the actual parameter offset. */
		/* - 0x20 for the header, - 0x01 for the length. */
		/* TODO: This isn't right. */
		parameter_offset = parameter_offset - 0x20 - 0x01;
		/* - 0x20 for the header, - 0x01 for parameter length, the parameter length, and - 0x02 for the data length. */
		data_offset = data_offset - 0x20 - 0x01 - buffer_get_length(smb->parameters[0].buffer) - 0x02;

		result = smbclient_msrpc_parse(smbclient, smb, parameter_offset, parameter_count, data_offset, data_count);

		if(result)
		{
			smbclient->event_callback(smbclient, SMBCLIENT_MSRPC_ERROR, &result);
		}
	}
}

void send_SMB_COM_TRANSACTION(SMBCLIENT_t *smbclient, uint16_t function, buffer_t *parameters, buffer_t  *data)
{
	uint16_t parameter_offset;
	uint16_t data_offset;
	SMB_t *smb = smb_create(SMB_COM_TRANSACTION, 1, smbclient->uid, smbclient->tid, smbclient->check_signature);

	buffer_add_int16(smb->parameters[0].buffer, 0x0000); /* Total parameter count -- the total bytes of parameters. */
	buffer_add_int16(smb->parameters[0].buffer, buffer_get_length(data)); /* Total data count -- the total bytes of data. */
	buffer_add_int16(smb->parameters[0].buffer, 0x0000); /* Max parameter count. */
	buffer_add_int16(smb->parameters[0].buffer, 0x0400); /* Max data count. */
	buffer_add_int8(smb->parameters[0].buffer,  0x00); /* Max setup count. */
	buffer_add_int8(smb->parameters[0].buffer,  0x00); /* Reserved. */
	buffer_add_int16(smb->parameters[0].buffer, 0x0000); /* Flags -- 0 = 2-way transaction, don't disconnect TID. */

	buffer_add_int32(smb->parameters[0].buffer, 0x00000000); /* Timeout -- 0 = return immediately. */
	buffer_add_int16(smb->parameters[0].buffer, 0x0000); /* Reserved. */
	buffer_add_int16(smb->parameters[0].buffer, parameters ? buffer_get_length(parameters) : 0); /* Parameter count -- bytes of 'parameters'. */

	/* Save the current location so we can set it when we know the offset. */
	parameter_offset = buffer_get_length(smb->parameters[0].buffer);
	buffer_add_int16(smb->parameters[0].buffer, 0xFFFF); /* Parameter offset -- distance from start of the packet (set this to a fake value for now). */
	buffer_add_int16(smb->parameters[0].buffer, buffer_get_length(data)); /* Data count -- bytes of 'data'. */

	/* Save the current location so we can set it when we know the offset. */
	data_offset = buffer_get_length(smb->parameters[0].buffer);
	buffer_add_int16(smb->parameters[0].buffer, 0xFFFF); /* Data offset -- distance from start of packet (set this to a fake value for now). */
	buffer_add_int8(smb->parameters[0].buffer, 0x02); /* Setup count -- The number of "setup words" coming up. */
	buffer_add_int8(smb->parameters[0].buffer, 0x00); /* Reserved. */

	/* These are the "setup words". */
	buffer_add_int16(smb->parameters[0].buffer, function); /* Function */
	buffer_add_int16(smb->parameters[0].buffer, smbclient->fid); /* FID. */

	/* Add the transaction name. In my experience, '\PIPE\' was the only thing I saw. */
	if(smbclient->unicode)
		buffer_add_unicode(smb->data[0].buffer, "\\PIPE\\");
	else
		buffer_add_ntstring(smb->data[0].buffer, "\\PIPE\\");

	/* Set the parameter location. We subtract 4 due to the 4-byte NetBIOS header. */
	buffer_add_int16_at(smb->parameters[0].buffer, smb_get_length(smb) - 4, parameter_offset);

	/* Add the parameters, if there are any. */
	if(parameters)
		buffer_add_buffer(smb->data[0].buffer, parameters);

	/* Set the data location. */
	buffer_add_int16_at(smb->parameters[0].buffer, smb_get_length(smb) - 4, data_offset);

	/* Add the data buffer. */
	buffer_add_buffer(smb->data[0].buffer, data);

	smb_send(smb, smbclient->s, &smbclient->sequence, smbclient->mac_key);
	smb_destroy(smb);
}

void parse_SMB_COM_NT_CREATE_ANDX(SMBCLIENT_t *smbclient, SMB_t *smb, int index)
{
	if(smb_is_error(smb))
	{
		smbclient->protocol_error_callback(smbclient, smb->header.status, smb_get_error_nt(smb));
	}
	else
	{
		uint16_t test;

		/* Parameters. */
		buffer_read_next_int8(smb->parameters[index].buffer); /* andx command. */
		buffer_read_next_int8(smb->parameters[index].buffer); /* andx reserved. */
		buffer_read_next_int16(smb->parameters[index].buffer); /* andx offset. */

		buffer_read_next_int8(smb->parameters[index].buffer); /* Oplock level. */
		smbclient->fid = buffer_read_next_int16(smb->parameters[index].buffer); /* FID. */
		buffer_read_next_int32(smb->parameters[index].buffer); /* Create action. */
		buffer_read_next_int32(smb->parameters[index].buffer); /* Created (high). */
		buffer_read_next_int32(smb->parameters[index].buffer); /* Created (low). */
		buffer_read_next_int32(smb->parameters[index].buffer); /* Last access (high). */
		buffer_read_next_int32(smb->parameters[index].buffer); /* Last access (low). */
		buffer_read_next_int32(smb->parameters[index].buffer); /* Last write (high). */
		buffer_read_next_int32(smb->parameters[index].buffer); /* Last write (low). */
		buffer_read_next_int32(smb->parameters[index].buffer); /* Change (high). */
		buffer_read_next_int32(smb->parameters[index].buffer); /* Change (low). */
		buffer_read_next_int32(smb->parameters[index].buffer); /* File attributes. */
		buffer_read_next_int32(smb->parameters[index].buffer); /* Allocation size (high). */
		buffer_read_next_int32(smb->parameters[index].buffer); /* Allocation size (low). */
		buffer_read_next_int32(smb->parameters[index].buffer); /* End of file (high). */
		buffer_read_next_int32(smb->parameters[index].buffer); /* End of file (low). */
		buffer_read_next_int16(smb->parameters[index].buffer); /* File type. */
		test = buffer_read_next_int16(smb->parameters[index].buffer); /* IPC State. */
		buffer_read_next_int8(smb->parameters[index].buffer); /* is_directory. */

		smbclient->event_callback(smbclient, SMBCLIENT_FILE_CREATED, NULL);
	}
}

void send_SMB_COM_NT_CREATE_ANDX(SMBCLIENT_t *smbclient, char *path)
{
	SMB_t *smb = smb_create(SMB_COM_NT_CREATE_ANDX, 1, smbclient->uid, smbclient->tid, smbclient->check_signature);

	/* Generic ANDX stuff */
	buffer_add_int8(smb->parameters[0].buffer,  SMB_NO_FURTHER_COMMANDS); /* ANDX: Next command. */
	buffer_add_int8(smb->parameters[0].buffer,  0); /* ANDX: Reserved. */
	buffer_add_int16(smb->parameters[0].buffer, 0); /* ANDX: Next offset. */

	buffer_add_int8(smb->parameters[0].buffer, 0x00);          /* Reserved. */
	if(smbclient->unicode)
		buffer_add_int16(smb->parameters[0].buffer, strlen(path) * 2); /* Length of path. */
	else
		buffer_add_int16(smb->parameters[0].buffer, strlen(path)); /* Length of path. */
	buffer_add_int32(smb->parameters[0].buffer, 0x00000016);   /* Create flags. */
	buffer_add_int32(smb->parameters[0].buffer, 0x00000000);   /* Root FID. */
	buffer_add_int32(smb->parameters[0].buffer, 0x0002019f);   /* Access mask. */
	buffer_add_int32(smb->parameters[0].buffer, 0x00000000);   /* Allocation size (high). */
	buffer_add_int32(smb->parameters[0].buffer, 0x00000000);   /* Allocation size (low). */
	buffer_add_int32(smb->parameters[0].buffer, 0x00000000);   /* File attributes. */
	buffer_add_int32(smb->parameters[0].buffer, 0x00000003);   /* Share attributes. */
	buffer_add_int32(smb->parameters[0].buffer, 0x00000001);   /* Disposition. */
	buffer_add_int32(smb->parameters[0].buffer, 0x00400040);   /* Create options. */
	buffer_add_int32(smb->parameters[0].buffer, 0x00000002);   /* Impersonation. */
	buffer_add_int8(smb->parameters[0].buffer, 0x01);          /* Security flags. */

	if(smbclient->unicode)
	{
		buffer_add_int8(smb->data[0].buffer, 0x00); /* Padding. */
		buffer_add_unicode(smb->data[0].buffer, path);    /* File name. */
	}
	else
	{
		buffer_add_ntstring(smb->data[0].buffer, path); /* File name. */
	}

	smb_send(smb, smbclient->s, &smbclient->sequence, smbclient->mac_key);
	smb_destroy(smb);
}

void parse_SMB_COM_LOGOFF_ANDX(SMBCLIENT_t *smbclient, SMB_t *smb)
{
	if(smb_is_error(smb))
	{
		smbclient->protocol_error_callback(smbclient, smb->header.status, smb_get_error_nt(smb));
	}
	else
	{
		smbclient->event_callback(smbclient, SMBCLIENT_SESSION_LOGOFF, NULL);
	}
}

void send_SMB_COM_LOGOFF_ANDX(SMBCLIENT_t *smbclient)
{
	SMB_t *smb = smb_create(SMB_COM_LOGOFF_ANDX, 1, smbclient->uid, smbclient->tid, smbclient->check_signature);

	/* Default ANDX stuff. */
	buffer_add_int8(smb->parameters[0].buffer,  SMB_NO_FURTHER_COMMANDS); /* ANDX: Next command. */
	buffer_add_int8(smb->parameters[0].buffer,  0); /* ANDX: Reserved. */
	buffer_add_int16(smb->parameters[0].buffer, 0); /* ANDX: Next offset. */

	smb_send(smb, smbclient->s, &smbclient->sequence, smbclient->mac_key);
	smb_destroy(smb);
}

void parse_SMB_COM_TREE_DISCONNECT(SMBCLIENT_t *smbclient, SMB_t *smb)
{
	if(smb_is_error(smb))
	{
		smbclient->protocol_error_callback(smbclient, smb->header.status, smb_get_error_nt(smb));
	}
	else
	{
		smbclient->event_callback(smbclient, SMBCLIENT_TREE_DISCONNECTED, NULL);
	}
}

void send_SMB_COM_TREE_DISCONNECT(SMBCLIENT_t *smbclient)
{
	SMB_t *smb = smb_create(SMB_COM_TREE_DISCONNECT, 1, smbclient->uid, smbclient->tid, smbclient->check_signature);

	/* Has no parameters or data */

	smb_send(smb, smbclient->s, &smbclient->sequence, smbclient->mac_key);
	smb_destroy(smb);
}

void parse_SMB_COM_TREE_CONNECT_ANDX(SMBCLIENT_t *smbclient, SMB_t *smb)
{
	char type[16];

	if(smb_is_error(smb))
	{
		smbclient->protocol_error_callback(smbclient, smb->header.status, smb_get_error_nt(smb));
	}
	else
	{
		if(smbclient->unicode)
			buffer_read_next_unicode(smb->data[0].buffer, type, 16);
		else
			buffer_read_next_ntstring(smb->data[0].buffer, type, 16);

		smbclient->tid = smb->header.tid;
		smbclient->event_callback(smbclient, SMBCLIENT_TREE_CONNECTED, type);
	}
}

void send_SMB_COM_TREE_CONNECT_ANDX(SMBCLIENT_t *smbclient, char *path)
{
	SMB_t *smb = smb_create(SMB_COM_TREE_CONNECT_ANDX, 1, smbclient->uid, smbclient->tid, smbclient->check_signature);

	/* Default ANDX stuff. */
	buffer_add_int8(smb->parameters[0].buffer,  SMB_NO_FURTHER_COMMANDS); /* ANDX: Next command. */
	buffer_add_int8(smb->parameters[0].buffer,  0); /* ANDX: Reserved. */
	buffer_add_int16(smb->parameters[0].buffer, 0); /* ANDX: Next offset. */

	buffer_add_int16(smb->parameters[0].buffer, 0); /* Flags. */
	buffer_add_int16(smb->parameters[0].buffer, 0); /* Password length (for share-level security). */

	/* Data. */
	buffer_add_bytes(smb->data[0].buffer, "", 0); /* Password (for share-level security). */
	if(smbclient->unicode)
	{
		buffer_add_int8(smb->data[0].buffer, 0x00); /* Padding. */
		buffer_add_unicode(smb->data[0].buffer, path); /* Path. */
		buffer_add_ntstring(smb->data[0].buffer, "?????"); /* Type. */
	}
	else
	{
		buffer_add_ntstring(smb->data[0].buffer, path); /* Path. */
		buffer_add_ntstring(smb->data[0].buffer, "?????"); /* Type. */
	}

	smb_send(smb, smbclient->s, &smbclient->sequence, smbclient->mac_key);
	smb_destroy(smb);
}

void parse_SMB_COM_ECHO(SMBCLIENT_t *smbclient, SMB_t *smb)
{
	if(smb_is_error(smb))
	{
		smbclient->protocol_error_callback(smbclient, smb->header.status, smb_get_error_nt(smb));
	}
	else
	{
		printf("SMB Echo returned [%d bytes of data]\n", buffer_get_length(smb->data[0].buffer));
	}
}

void send_SMB_COM_ECHO(SMBCLIENT_t *smbclient, uint8_t *data, size_t length, size_t count)
{
	SMB_t *smb = smb_create(SMB_COM_ECHO, 1, smbclient->uid, smbclient->tid, smbclient->check_signature);

	buffer_add_int16(smb->parameters[0].buffer, count);
	buffer_add_bytes(smb->data[0].buffer, data, length);

	smb_send(smb, smbclient->s, &smbclient->sequence, smbclient->mac_key);
	smb_destroy(smb);
}

/* lm_length and ntlm_length are in/out parameters -- they specify the length of the buffer (should be at least 24 bytes, or 96 for v2), then the actual length is returned in them. */
static void get_logon_hashes_from_password(SMB_LOGONTYPE_t logon, char *password, char *username, char *domain, uint8_t *challenge, uint8_t *lm, uint8_t *ntlm, uint8_t *lm_length, uint8_t *ntlm_length, uint8_t mac_key[40])
{
	uint8_t lanman_hash[16];
	uint8_t ntlm_hash[16];

	/* Verify buffer lengths. */
	if(*lm_length < 24 || *ntlm_length < 24)
		DIE("Buffers need to be 24-bytes or longer.");

	lm_create_hash(password, lanman_hash);
	ntlm_create_hash(password, ntlm_hash);

	switch(logon)
	{
		case LOGONTYPE_ANONYMOUS:
			*lm_length   = 0;
			*ntlm_length = 0;
		break;

		case LOGONTYPE_DEFAULT:
			lm_create_response(lanman_hash, challenge, lm);
			ntlm_create_response(ntlm_hash, challenge, ntlm);

			*lm_length   = 24;
			*ntlm_length = 24;

			/* For default, use the ntlm key (since it's the highest). */
			ntlm_create_session_key(ntlm_hash, mac_key);
			memcpy(mac_key + 16, ntlm, 24);
		break;

		case LOGONTYPE_LM:
			lm_create_response(lanman_hash, challenge, lm);
			*lm_length   = 24;
			*ntlm_length = 0;

			/* For lanman, use the lanman key. */
			lm_create_session_key(lanman_hash, mac_key);
			memcpy(mac_key + 16, lm, 24);
		break;

		case  LOGONTYPE_NTLM:
			ntlm_create_response(ntlm_hash, challenge, lm);
			ntlm_create_response(ntlm_hash, challenge, ntlm);
			*lm_length   = 24;
			*ntlm_length = 24;

			/* For ntlm, obviously use the ntlm key */
			ntlm_create_session_key(ntlm_hash, mac_key);
			memcpy(mac_key + 16, ntlm, 24);
		break;

		case LOGONTYPE_DEFAULTv2:
			lmv2_create_response(ntlm_hash, username, domain, challenge, lm, lm_length);
			ntlmv2_create_response(ntlm_hash, username, domain, challenge, ntlm, ntlm_length);

/*          This function doesn't work, so we use a broken key. */
/*			ntlmv2_create_session_key(ntlm_hash, username, domain, ntlm, mac_key);
			memcpy(mac_key + 16, ntlm, 24); */
		break;

		case LOGONTYPE_LMv2:
			lmv2_create_response(ntlm_hash, username, domain, challenge, lm, lm_length);
			*ntlm_length = 0;

/*          This function doesn't work, so we use a broken key. */
/*			lmv2_create_session_key(ntlm_hash, username, domain, lm, mac_key);
			memcpy(mac_key + 16, lm, 24); */

		break;

		default:
			fprintf(stderr, "Sorry, don't know how to do that logon type!\n\n");
			exit(1);
	}
}

static void get_logon_hashes_from_hash(SMB_LOGONTYPE_t logon, char *hash, char *username, char *domain, uint8_t *challenge, uint8_t lm[16], uint8_t ntlm[16], uint8_t *lm_length, uint8_t *ntlm_length, uint8_t mac_key[40])
{
	uint8_t hash1[16];
	uint8_t hash2[16];

	int count = string_to_hash(hash, hash1, hash2);

	switch(logon)
	{
		case LOGONTYPE_ANONYMOUS:
			*lm_length   = 0;
			*ntlm_length = 0;
		break;

		case LOGONTYPE_DEFAULT:
			if(count == 0)
			{
				fprintf(stderr, "Error: invalid hash given, '%s'\n\n", hash);
				exit(1);
			}
			else if(count == 1)
			{
				fprintf(stderr, "Error: both LM and NTLM hashes are required for 'default' logon type.\n\n");
				exit(1);
			}

			lm_create_response(hash1, challenge, lm);
			ntlm_create_response(hash2, challenge, ntlm);

			*lm_length   = 24;
			*ntlm_length = 24;

			/* For default, use the ntlm key (since it's the highest). */
			ntlm_create_session_key(hash2, mac_key);
			memcpy(mac_key + 16, ntlm, 24);
		break;

		case LOGONTYPE_LM:
			if(count == 0)
			{
				fprintf(stderr, "Error: invalid hash given, '%s'\n\n", hash);
				exit(1);
			}
			else if(count == 2)
			{
				fprintf(stderr, "Warning: two hashes given, ignoring second for LM login.\n");
			}

			lm_create_response(hash1, challenge, lm);

			*lm_length   = 24;
			*ntlm_length = 0;

			/* For lanman, use the lanman key. */
			lm_create_session_key(hash1, mac_key);
			memcpy(mac_key + 16, lm, 24);
		break;

		case LOGONTYPE_NTLM:
			if(count == 0)
			{
				fprintf(stderr, "Error: invalid hash given, '%s'\n\n", hash);
				exit(1);
			}
			else if(count == 2)
			{
				fprintf(stderr, "Warning: two hashes given, ignoring first for NTLM login.\n");
				memcpy(hash1, hash2, 16);
			}

			ntlm_create_response(hash1, challenge, lm);
			ntlm_create_response(hash1, challenge, ntlm);

			*lm_length   = 24;
			*ntlm_length = 24;

			/* For ntlm, obviously use the ntlm key */
			ntlm_create_session_key(hash1, mac_key);
			memcpy(mac_key + 16, ntlm, 24);
		break;

		case LOGONTYPE_DEFAULTv2:
			if(count == 0)
			{
				fprintf(stderr, "Error: invalid hash given, '%s'\n\n", hash);
				exit(1);
			}
			else if(count == 2)
			{
				fprintf(stderr, "Warning: two hashes given, ignoring first for v2 login.\n");
				memcpy(hash1, hash2, 16);
			}

			lmv2_create_response(hash1, username, domain, challenge,   lm,   lm_length);
			ntlmv2_create_response(hash1, username, domain, challenge, ntlm, ntlm_length);

/*          This function doesn't work, so we use a broken key. */
/*			ntlmv2_create_session_key(hash1, username, domain, ntlm, mac_key);
			memcpy(mac_key + 16, ntlm, 24); */
		break;

		case LOGONTYPE_LMv2:
			if(count == 0)
			{
				fprintf(stderr, "Error: invalid hash given, '%s'\n\n", hash);
				exit(1);
			}
			else if(count == 2)
			{
				fprintf(stderr, "Warning: two hashes given, ignoring first for v2 login.\n");
				memcpy(hash1, hash2, 16);
			}

			lmv2_create_response(hash1,   username, domain, challenge,   lm,   lm_length);
			*ntlm_length = 0;

/*          This function doesn't work, so we use a broken key. */
/*			lmv2_create_session_key(hash1, username, domain, ntlm, mac_key);
			memcpy(mac_key + 16, lm, 24); */
		break;

		default:
			fprintf(stderr, "Sorry, don't know how to do that logon type yet!\n\n");
			exit(1);
	}
}


void send_SMB_COM_SESSION_SETUP_ANDX(SMBCLIENT_t *smbclient, char *domain, char *username, char *password, char *hash, SMB_LOGONTYPE_t logon)
{
	SMB_t  *smb = smb_create(SMB_COM_SESSION_SETUP_ANDX, 1, smbclient->uid, smbclient->tid, smbclient->check_signature);

	uint8_t lanman[24];
	uint8_t ntlm[96];

	/* The hash lengths will be determined by the user-chosen logon type. */
	uint8_t lanman_length = 24;
	uint8_t ntlm_length = 96;

	/* Set the sequence number to 0 since the session key will shortly be calculated. */
	smbclient->sequence = 0;

	if(logon == LOGONTYPE_ANONYMOUS)
	{
		lanman_length = 0;
		ntlm_length   = 0;
	}
	else if(hash)
	{
		get_logon_hashes_from_hash(logon, hash, username, domain, smbclient->encryption_key, lanman, ntlm, &lanman_length, &ntlm_length, smbclient->mac_key);
	}
	else if(password)
	{
		get_logon_hashes_from_password(logon, password, username, domain, smbclient->encryption_key, lanman, ntlm, &lanman_length, &ntlm_length, smbclient->mac_key);
	}
	else
	{
		fprintf(stderr, "Please set a password with -p or -P!\n\n");
		exit(1);
	}

	/* Parameter section. */
	buffer_add_int8(smb_get_parameters(smb, 0), SMB_NO_FURTHER_COMMANDS);
	buffer_add_int8(smb_get_parameters(smb, 0), 0); /* Reserved. */
	buffer_add_int16(smb_get_parameters(smb, 0), 0); /* AndXOffset. */
	buffer_add_int16(smb_get_parameters(smb, 0), 4096); /* Max buffer. */
	buffer_add_int16(smb_get_parameters(smb, 0), 1); /* Max Mpx Count. */
	buffer_add_int16(smb_get_parameters(smb, 0), 0); /* VC Number. */
	buffer_add_int32(smb_get_parameters(smb, 0), smbclient->server_session_key); /* Session key. */

	buffer_add_int16(smb_get_parameters(smb, 0), lanman_length); /* ANSI Password Length (LM). */
	buffer_add_int16(smb_get_parameters(smb, 0), ntlm_length); /* Unicode Password Length (NTLM). */
	buffer_add_int32(smb_get_parameters(smb, 0), 0); /* Reserved. */

	buffer_add_int32(smb_get_parameters(smb, 0), smbclient->server_capabilities & (CAP_STATUS32 | CAP_NT_SMBS)); /* Capabilities. */


	/* Data section. */
	buffer_add_bytes(smb_get_data(smb, 0), lanman, lanman_length);
	buffer_add_bytes(smb_get_data(smb, 0), ntlm,   ntlm_length);

	if(smbclient->unicode)
	{
		if(logon == LOGONTYPE_ANONYMOUS)
		{
			buffer_add_int8(smb_get_data(smb, 0), 0x00); /* Padding. */
			buffer_add_unicode(smb_get_data(smb, 0), ""); /* Account. */
			buffer_add_unicode(smb_get_data(smb, 0), ""); /* Primary Domain. */
		}
		else
		{
			buffer_add_unicode(smb_get_data(smb, 0), username); /* Account. */
			buffer_add_unicode(smb_get_data(smb, 0), domain); /* Primary Domain. */
		}
		buffer_add_unicode(smb_get_data(smb, 0), "Windows 95/98/Me/NT/2k/XP"); /* Native OS. */
		buffer_add_unicode(smb_get_data(smb, 0), "Native LanMan"); /* Native LAN Manager. */
	}
	else
	{
		if(logon == LOGONTYPE_ANONYMOUS)
		{
			buffer_add_ntstring(smb_get_data(smb, 0), ""); /* Account. */
			buffer_add_ntstring(smb_get_data(smb, 0), ""); /* Primary Domain. */
		}
		else
		{
			buffer_add_ntstring(smb_get_data(smb, 0), username); /* Account. */
			buffer_add_ntstring(smb_get_data(smb, 0), domain); /* Primary Domain. */
		}
		buffer_add_ntstring(smb_get_data(smb, 0), "Windows 95/98/Me/NT/2k/XP"); /* Native OS. */
		buffer_add_ntstring(smb_get_data(smb, 0), "Native LanMan"); /* Native LAN Manager. */
	}

	smb_send(smb, smbclient->s, &smbclient->sequence, smbclient->mac_key);
	smb_destroy(smb);
}
void parse_SMB_COM_SESSION_SETUP_ANDX(SMBCLIENT_t *smbclient, SMB_t *smb, size_t index)
{
	uint16_t action;

	char OS[1000];
	char LANManager[1000];
	char Domain[1000];

	if(smb_is_error(smb))
	{
		smbclient->protocol_error_callback(smbclient, smb->header.status, smb_get_error_nt(smb));
	}
	else
	{
		buffer_read_next_int8(smb->parameters[index].buffer); /* andx command. */
		buffer_read_next_int8(smb->parameters[index].buffer); /* andx reserved. */
		buffer_read_next_int16(smb->parameters[index].buffer); /* andx offset. */
		action = buffer_read_next_int16(smb->parameters[index].buffer);

		/* Save the UID we were given. */
		smbclient->uid = smb->header.uid;

		/* We're now authenticated! */
		smbclient->authenticated = TRUE;

		if(smbclient->verbose)
		{
			if(smbclient->unicode)
			{
				printf(" -> OS: %s\n",          buffer_read_unicode_at(smb->data[index].buffer, 0, OS, 1000));
				printf(" -> Lan manager: %s\n", buffer_read_unicode_at(smb->data[index].buffer, 0 + strlen(OS) + 1, LANManager, 1000));
				printf(" -> Domain: %s\n",      buffer_read_unicode_at(smb->data[index].buffer, 0 + strlen(OS) + 1 + strlen(LANManager) + 1, Domain, 1000));
			}
			else
			{
				printf(" -> OS: %s\n",          buffer_read_ntstring_at(smb->data[index].buffer, 0, OS, 1000));
				printf(" -> Lan manager: %s\n", buffer_read_ntstring_at(smb->data[index].buffer, 0 + strlen(OS) + 1, LANManager, 1000));
				printf(" -> Domain: %s\n",      buffer_read_ntstring_at(smb->data[index].buffer, 0 + strlen(OS) + 1 + strlen(LANManager) + 1, Domain, 1000));
			}
		}

		if(action & 1)
		{
			smbclient->event_callback(smbclient, SMBCLIENT_SESSION_SET_UP_GUEST, NULL);
		}
		else
		{
			smbclient->event_callback(smbclient, SMBCLIENT_SESSION_SET_UP, NULL);
		}
	}
}



/* This packet is sent first, as soon as the connection is established, and it contains a list of protocols that the
 * client understands.
 *
 * s is the socket, protocols is a null-terminated list of strings. */
void send_SMB_COM_NEGOTIATE(SMBCLIENT_t *smbclient, char **protocols)
{
	size_t i;

	SMB_t *smb = smb_create(SMB_COM_NEGOTIATE, 1, smbclient->uid, smbclient->tid, smbclient->check_signature);

	/* Parameters: none. */
	/* Data: a Null-delimited list of understood protocols (with 0x02s appended) */
	i = 0;
	while(protocols[i])
	{
		buffer_add_int8(smb_get_data(smb, 0), 0x02);
		buffer_add_ntstring(smb_get_data(smb, 0), protocols[i]);
		i++;
	}

	smb_send(smb, smbclient->s, &smbclient->sequence, smbclient->mac_key);
	smb_destroy(smb);
}
/* This is the response from the server. It contains important information like capabilities, the challenge value, etc. */
void parse_SMB_COM_NEGOTIATE(SMBCLIENT_t *smbclient, SMB_t *smb)
{
	if(smb_is_error(smb))
	{
		smbclient->protocol_error_callback(smbclient, smb->header.status, smb_get_error_nt(smb));
	}
	else
	{
		uint16_t           dialect                = buffer_read_next_int16(smb->parameters[0].buffer);
		uint8_t            security_mode          = buffer_read_next_int8(smb->parameters[0].buffer);
		uint16_t           max_mpx_count          = buffer_read_next_int16(smb->parameters[0].buffer);
		uint16_t           max_number_vcs         = buffer_read_next_int16(smb->parameters[0].buffer);
		uint32_t           max_buffer_size        = buffer_read_next_int32(smb->parameters[0].buffer);
		uint32_t           max_raw_size           = buffer_read_next_int32(smb->parameters[0].buffer);
		uint32_t           session_key            = buffer_read_next_int32(smb->parameters[0].buffer);
		SMB_CAPABILITIES_t capabilities           = buffer_read_next_int32(smb->parameters[0].buffer);
		uint32_t           system_time_low        = buffer_read_next_int32(smb->parameters[0].buffer);
		uint32_t           system_time_high       = buffer_read_next_int32(smb->parameters[0].buffer);

		smbclient->system_timezone                  = buffer_read_next_int16(smb->parameters[0].buffer);
		smbclient->encryption_key_length            = buffer_read_next_int8(smb->parameters[0].buffer);

		/* Convert the system time. */
		smbclient->system_time            = (((uint64_t)system_time_high) << 32) | system_time_low;
		smbclient->system_time_unix       = (smbclient->system_time / 10000000LL) - 11644473600LL;

		smbclient->server_capabilities = capabilities;
		smbclient->server_session_key         = session_key;

		if(smbclient->verbose > 0)
		{
			printf("Lowest supported protocol: %s [0x%02x]\n", protocols[dialect], dialect);
			printf("Security mode: %d\n",              security_mode);
			printf(" -> Signatures are %s\n",          security_mode & NEGOTIATE_SECURITY_SIGNATURES_REQUIRED ? "required"     : "optional");
			printf(" -> Message signing is %s\n",      security_mode & NEGOTIATE_SECURITY_SIGNATURES_ENABLED  ? "enabled"      : "not enabled");
			printf(" -> Plaintext passwords are %s\n", security_mode & NEGOTIATE_SECURITY_CHALLENGE_RESPONSE  ? "not required" : "required");
			printf(" -> Security is %s-level\n",       security_mode & NEGOTIATE_SECURITY_USER_LEVEL          ? "user"         : "share");

			printf("Max multiplex: %d\n",         max_mpx_count);
			printf("Max virtual circuits: %d\n",  max_number_vcs);
			printf("Max buffer: %d\n",            max_buffer_size);
			printf("Max raw size: %d\n",          max_raw_size);
			printf("Session key: %08x\n",         session_key);
			printf("Capabilities: %08x",          capabilities);
			smb_print_capabilities(capabilities);
			printf("\n");
			printf("System time: %s",                ctime((time_t*)&smbclient->system_time_unix));
			printf("UTC: %d minutes (%.2f hours)\n", smbclient->system_timezone, (smbclient->system_timezone / 60.0));
			printf("Encryption key length: %d\n",    smbclient->encryption_key_length);
			printf("\n");
		}

		/* We only support user-level security. */
		if(!(security_mode & NEGOTIATE_SECURITY_USER_LEVEL))
		{
			fprintf(stderr, "Server wants share-level security, we don't support that.\n\n");
			exit(1);
		}

		/* We also only support challenge-response (not plaintext). */
		if(!(security_mode & NEGOTIATE_SECURITY_CHALLENGE_RESPONSE))
		{
			fprintf(stderr, "Server doesn't understand challenge-response authentication, but that's all we can do.\n\n");
			exit(1);
		}

		/* Make sure we were given a challenge. */
		if(smbclient->encryption_key_length != 8)
		{
			fprintf(stderr, "Server didn't give us a 8-byte challenge value (it was %d bytes).\n\n", smbclient->encryption_key_length);
			exit(1);
		}

		buffer_read_next_bytes(smb->data[0].buffer, smbclient->encryption_key, smbclient->encryption_key_length);
		buffer_read_next_unicode(smb->data[0].buffer, smbclient->domain_name, 256);
		buffer_read_next_unicode(smb->data[0].buffer, smbclient->server_name, 256);

		if(smbclient->verbose > 0)
		{
			printf("Challenge: %x%x%x%x%x%x%x%x\n", smbclient->encryption_key[0], smbclient->encryption_key[1], smbclient->encryption_key[2], smbclient->encryption_key[3], smbclient->encryption_key[4], smbclient->encryption_key[5], smbclient->encryption_key[6], smbclient->encryption_key[7]);
		}

		smbclient->event_callback(smbclient, SMBCLIENT_PROTOCOL_NEGOTIATED, NULL);
	}
}

void send_NETBIOS_SESSION_REQUEST(SMBCLIENT_t *smbclient, char *netbios_name)
{
	char     *called_name_e   = name_encode(netbios_name,  "", ' ', NAME_SERVER);
	char     *calling_name_e  = name_encode("WINDOWS", "", ' ', NAME_SERVER);
	buffer_t *buffer          = buffer_create(BO_NETWORK);
	uint8_t   data[72]; /* Length is always 72. */

	buffer_add_int8(buffer, SESSION_REQUEST);
	buffer_add_int8(buffer, 0); /* Flags. */
	buffer_add_int16(buffer, 68); /* Length is constant 72, -4 for header. */
	buffer_add_ntstring(buffer, called_name_e);
	buffer_add_ntstring(buffer, calling_name_e);

	buffer_read_next_bytes(buffer, data, 72);
	tcp_send(smbclient->s, data, 72);

	buffer_destroy(buffer);
	safe_free(calling_name_e);
	safe_free(called_name_e);
}
void parse_NETBIOS_SESSION_RESPONSE(SMBCLIENT_t *smbclient, uint8_t *data)
{
	buffer_t *buffer = buffer_create_with_data(BO_NETWORK, data, 4);
	uint8_t response = buffer_read_next_int8(buffer);

	if(response != SESSION_POSITIVE_RESPONSE)
		smbclient->protocol_error_callback(smbclient, -1, "NetBIOS session rejected, likely due to an incorrect hostname.");

	buffer_destroy(buffer);
}

SELECT_RESPONSE_t incoming_callback(void *group, int s, uint8_t *data, size_t length, char *addr, uint16_t port, void *param)
{
	SMBCLIENT_t *smbclient = (SMBCLIENT_t*) param;
	buffer_t *buffer;

	switch(smbclient->state)
	{
		case RECV_STATE_SESSION_REQUEST:
		{
			/* Sanity check -- this should never happen with select_group. */
			if(length != 4)
				smbclient->protocol_error_callback(smbclient, -1, "Received incorrect number of bytes for NetBIOS header.");

			/* If this actually returns, we're set. */
			parse_NETBIOS_SESSION_RESPONSE(smbclient, data);

			/* We start by receiving a header. */
			smbclient->state = RECV_STATE_HEADER;
			/* NetBIOS Header is 4 bytes. */
			select_group_wait_for_bytes((select_group_t*)group, s, 4);
			/* Send the initial packet to kick things off. */
			send_SMB_COM_NEGOTIATE(smbclient, protocols);
			break;
		}
		case RECV_STATE_HEADER:
		{
			/* Sanity check -- this should never happen with select_group. */
			if(length != 4)
				smbclient->protocol_error_callback(smbclient, -1, "Received incorrect number of bytes for NetBIOS header.");

			/* The header is 24-bytes in network byte order. */
			buffer = buffer_create_with_data(BO_NETWORK, data, 4);
			smbclient->current_length = (buffer_read_next_int32(buffer) & 0x00FFFFFF);
			buffer_destroy(buffer);

			/* Enter body-receiving mode. */
			select_group_wait_for_bytes((select_group_t*)group, s, smbclient->current_length);
			smbclient->state = RECV_STATE_BODY;

			break;
		}
		case RECV_STATE_BODY:
		{
			SMB_t *smb;

			/* Sanity check -- this should never happen with select_group. */
			if(length != smbclient->current_length)
				smbclient->protocol_error_callback(smbclient, -1, "Received incorrect number of bytes for NetBIOS body.");

			smb = smb_create_from_data(data, length, &smbclient->sequence, smbclient->mac_key, smbclient->authenticated ? smbclient->check_signature : FALSE);

			/* Parse out some flags. */
			smbclient->error_nt          = (smb->header.flags2 & SMB_FLAGS2_32BIT_STATUS)      ? TRUE : FALSE;
			smbclient->unicode           = (smb->header.flags2 & SMB_FLAGS2_UNICODE_STRINGS)   ? TRUE : FALSE;

			/* Display them, if desired. */
			if(smbclient->verbose > 1)
			{
				printf("Flags: ");
				smb_print_flags(smb->header.flags);
				printf("\n");

				printf("Flags2: ");
				smb_print_flags2(smb->header.flags2);
				printf("\n");
			}

			switch(smb->header.command)
			{
				case SMB_COM_NEGOTIATE:
					parse_SMB_COM_NEGOTIATE(smbclient, smb);
					break;
				case SMB_COM_SESSION_SETUP_ANDX:
					parse_SMB_COM_SESSION_SETUP_ANDX(smbclient, smb, 0);
					break;
				case SMB_COM_ECHO:
					parse_SMB_COM_ECHO(smbclient, smb);
					break;
				case SMB_COM_TREE_CONNECT_ANDX:
					parse_SMB_COM_TREE_CONNECT_ANDX(smbclient, smb);
					break;
				case SMB_COM_TREE_DISCONNECT:
					parse_SMB_COM_TREE_DISCONNECT(smbclient, smb);
					break;
				case SMB_COM_LOGOFF_ANDX:
					parse_SMB_COM_LOGOFF_ANDX(smbclient, smb);
					break;
				case SMB_COM_NT_CREATE_ANDX:
					parse_SMB_COM_NT_CREATE_ANDX(smbclient, smb, 0);
					break;
				case SMB_COM_TRANSACTION:
					parse_SMB_COM_TRANSACTION(smbclient, smb);
					break;
				default:
					smbclient->event_callback(smbclient, SMBCLIENT_UNKNOWN_COMMAND, (void*)smb->header.command);
			}

			smb_destroy(smb);

			/* Return to header state. */
			select_group_wait_for_bytes((select_group_t*)group, s, 4);
			smbclient->state = RECV_STATE_HEADER;

			break;
		}
		default:
			DIE("Entered an unknown state.");
	}

	return SELECT_OK;
}

SELECT_RESPONSE_t timeout_callback(void *group, int s, void *param)
{
	return SELECT_OK;
}

SELECT_RESPONSE_t error_callback(void *group, int s, int err, void *param)
{
	((SMBCLIENT_t*)param)->connection_error_callback(param, err, strerror(err));
	return SELECT_OK;
}

SELECT_RESPONSE_t closed_callback(void *group, int s, void *param)
{
	((SMBCLIENT_t*)param)->connection_error_callback(param, 0, "Connection closed.");
	return SELECT_OK;
}

SMBCLIENT_t *smbclient_create()
{
	SMBCLIENT_t *new_smbclient = safe_malloc(sizeof(SMBCLIENT_t));
	memset(new_smbclient, 0, sizeof(SMBCLIENT_t));

	return new_smbclient;
}

void smbclient_set_event_callback(SMBCLIENT_t *smbclient, smbclient_event *event_callback)
{
	smbclient->event_callback = event_callback;
}

void smbclient_set_protocol_error_callback(SMBCLIENT_t *smbclient, smbclient_protocol_error *protocol_error_callback)
{
	smbclient->protocol_error_callback = protocol_error_callback;
}

void smbclient_set_connection_error_callback(SMBCLIENT_t *smbclient, smbclient_connection_error *connection_error_callback)
{
	smbclient->connection_error_callback = connection_error_callback;
}

void smbclient_connect(SMBCLIENT_t *smbclient, char *host, uint16_t port, NBBOOL try_other_ports, select_group_t *sg)
{
	/* Connect; if it fails, try some other ports. */
	int s = tcp_connect(host, port);
	if(s == -1 && try_other_ports)
	{
		if(port != 445)
		{
			fprintf(stderr, "Connection on port %d failed, trying port 445\n", port);
			port = 445;
			s = tcp_connect(host, port);
		}

		if(s == -1)
		{
			fprintf(stderr, "Connection on port %d failed, trying port 139\n", port);
			port = 139;
			s = tcp_connect(host, port);
		}
	}

	if(s == -1)
	{
		fprintf(stderr, "Couldn't connect, sorry!\n\n");
		exit(1);
	}

	smbclient->s = s;

	select_group_add_socket(sg, s, SOCKET_TYPE_STREAM, smbclient);
	select_set_recv(sg, s, incoming_callback);
	select_set_error(sg, s, error_callback);
	select_set_closed(sg, s, closed_callback);
	select_set_timeout(sg, s, timeout_callback);

	/* Put ourselves into the "receive header" state, even though nothing is going to come. */
	smbclient->state = RECV_STATE_HEADER;

	/* We're always waiting for 4 bytes initially. */
	select_group_wait_for_bytes(sg, s, 4);

	smbclient->event_callback(smbclient, SMBCLIENT_CONNECTED, (void*)((uint32_t)port));
}

void smbclient_netbios_start_session(SMBCLIENT_t *smbclient, char *netbios_name)
{
	/* We're in the received state. */
	smbclient->state = RECV_STATE_SESSION_REQUEST;
	/* Send the session request. */
	send_NETBIOS_SESSION_REQUEST(smbclient, netbios_name);
}

void smbclient_negotiate_protocol(SMBCLIENT_t *smbclient)
{
	send_SMB_COM_NEGOTIATE(smbclient, protocols);
}

void smbclient_logon(SMBCLIENT_t *smbclient, char *domain, char *username, char *password, char *hash, SMB_LOGONTYPE_t logontype)
{
	send_SMB_COM_SESSION_SETUP_ANDX(smbclient, domain, username, password, hash, logontype);
}

void smbclient_logoff(SMBCLIENT_t *smbclient)
{
	send_SMB_COM_LOGOFF_ANDX(smbclient);
}

void smbclient_tree_connect(SMBCLIENT_t *smbclient, char *path)
{
	send_SMB_COM_TREE_CONNECT_ANDX(smbclient, path);
}

void smbclient_tree_disconnect(SMBCLIENT_t *smbclient)
{
	send_SMB_COM_TREE_DISCONNECT(smbclient);
}

void smbclient_nt_create(SMBCLIENT_t *smbclient, char *path)
{
	send_SMB_COM_NT_CREATE_ANDX(smbclient, path);
}

void smbclient_msrpc_bind(SMBCLIENT_t *smbclient, uint8_t *interface, uint16_t interface_version, uint8_t *transfer_syntax)
{
	buffer_t *data = buffer_create(BO_LITTLE_ENDIAN);

	/* Seems to be a standard one. */
	if(!transfer_syntax)
		transfer_syntax = (uint8_t*)"\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60";

	memcpy(smbclient->service_uuid, interface, 16);
	memcpy(smbclient->send_syntax, transfer_syntax, 16);

	buffer_add_int8(data, 0x05); /* Version (major). */
	buffer_add_int8(data, 0x00); /* Version (minor). */
	buffer_add_int8(data, 0x0b); /* Packet type (0x0b => bind) -- determines structure of rest of packet. */
	buffer_add_int8(data, 0x03); /* Packet flags. */
	buffer_add_int32(data, 0x00000010); /* Data representation. */
	buffer_add_int16(data, 0x0048); /* Frag length. */
	buffer_add_int16(data, 0x0000); /* Auth length. */
	buffer_add_int32(data, 0x41414141); /* Call ID. */
	buffer_add_int16(data, 0x10b8); /* Max transmit flag. */
	buffer_add_int16(data, 0x10b8); /* Max receive flag. */
	buffer_add_int32(data, 0x00000000); /* Assoc group. */
	buffer_add_int8(data, 0x01); /* Num ctx items. */
	buffer_add_bytes(data, "\x00\x00\x00", 3); /* Padding */

	buffer_add_int16(data, 0x0000); /* Context Id. */
	buffer_add_int8(data, 0x01); /* Num Transaction Items. */
	buffer_add_int8(data, 0x00); /* ??? */
	buffer_add_bytes(data, interface, 16); /* Interface: Eg, SRVSVC UUID: 4b324fc8-1670-01d3-1278-5a47bf6ee188 */
	buffer_add_int16(data, interface_version); /* Interface version (major). */
	buffer_add_int16(data, 0x0000); /* Interface version (minor). */
	buffer_add_bytes(data, transfer_syntax, 16); /* Transfer Syntax: Eg, 8a885d04-1ceb-11c9-9fe8-08002b104860 */
	buffer_add_int32(data, 0x00000002); /* Version. */

	send_SMB_COM_TRANSACTION(smbclient, 0x0026, NULL, data);
}

void smbclient_msrpc_call_function(SMBCLIENT_t *smbclient, uint16_t opnum, buffer_t *arguments)
{
	uint16_t fraglength_offset;
	buffer_t *data = buffer_create(BO_LITTLE_ENDIAN);

	/* "data" starts here */
	buffer_add_int8(data, 0x05); /* Version (major). */
	buffer_add_int8(data, 0x00); /* Version (minor). */
	buffer_add_int8(data, 0x00); /* Packet type (0x00 => request). */
	buffer_add_int8(data, 0x03); /* Packet flags -- 0x03 = first frag + last frag. */
	buffer_add_int32(data, 0x00000010); /* Data representation (note: this value is big endian). */

	/* Save the current offset so we can stick in the frag length. */
	fraglength_offset = buffer_get_length(data);
	buffer_add_int16(data, 0xFFFF); /* Frag length -- the length of this fragment (same as total length, if not fragmenting). */
	buffer_add_int16(data, 0x0000); /* Auth length -- not sure how to do length yet. */
	buffer_add_int32(data, 0x41414141); /* Call ID -- echoed back. */

	buffer_add_int32(data, 0x00000100); /* Alloc hint -- technically ignored, but should roughly match the length. */
	buffer_add_int16(data, 0x0000); /* Context ID -- the ID retunred by the bind(). */
	buffer_add_int16(data, opnum); /* opnum (0x0f => NetShareEnumAll). */
	buffer_add_buffer(data, arguments);

	/* Set the fraglength location. */
	buffer_add_int16_at(data, buffer_get_length(data), fraglength_offset);

	send_SMB_COM_TRANSACTION(smbclient, 0x0026, NULL, data);
}

void smbclient_send_srvsvc_netshareenumall(SMBCLIENT_t *smbclient)
{
	buffer_t *arguments = buffer_create(BO_LITTLE_ENDIAN);

/*		[in]   [string,charset(UTF16)] uint16 *server_unc, */
	buffer_add_int32(arguments, 0x0012ee18); /* Referent Id. */
	buffer_add_int32(arguments, 0x00000012); /* Max count. */
	buffer_add_int32(arguments, 0x00000000); /* Offset. */
	buffer_add_int32(arguments, 0x00000012); /* Actual count. */
	buffer_add_unicode(arguments, "\\\\192.168.241.128"); /* Server Unc. */

/*		[in,out]   uint32 level, */
	buffer_add_int32(arguments, 0x00000000); /* Pointer to level (level: 0). */

/*		[in,out,switch_is(level)] srvsvc_NetShareCtr ctr, */
	buffer_add_int32(arguments, 0x00000000); /* Pointer to Ctr (ctr). */
	buffer_add_int32(arguments, 0x0012edbc); /* Referent ID. */
	buffer_add_int32(arguments, 0x00000000); /* Count. */
	buffer_add_int32(arguments, 0x00000000); /* Pointer to array (srvsvc_NetShareInfo0). */

/*		[out]  uint32 totalentries, */

/*		[in,out]   uint32 *resume_handle*/
	buffer_add_int32(arguments, 0x0012ff28); /* Referent ID. */
	buffer_add_int32(arguments, 0x00000000); /* Resume handle. */

	smbclient->msrpc_state = MSRPC_SENT_NETSHAREENUMALL;
	smbclient_msrpc_call_function(smbclient, 0x0F, arguments);

	buffer_destroy(arguments);
}

static uint32_t smbclient_parse_srvsvc_netshareenumall(buffer_t *data, NETSHAREENUMALL_t *result)
{
	size_t i;

/*		[in]   [string,charset(UTF16)] uint16 *server_unc, */
/*		[in,out]   uint32 level, */
	buffer_read_next_int32(data);

/*		[in,out,switch_is(level)] srvsvc_NetShareCtr ctr, */
	buffer_read_next_int32(data); /* Ctr. */
	buffer_read_next_int32(data); /* Referent ID. */
	result->name_count = buffer_read_next_int32(data); /* Count. */
	buffer_read_next_int32(data); /* Referent ID. */
	buffer_read_next_int32(data); /* Max count. */

	/* Allocate room for the string list. */
	result->names = (char**) safe_malloc(result->name_count * sizeof(char*));

	/* Read in the headers. */
	for(i = 0; i < result->name_count; i++)
	{
		buffer_read_next_int32(data); /* Referent ID. */
	}

	/* Read in the values. */
	for(i = 0; i < result->name_count; i++)
	{
		uint32_t actual_size;

		buffer_read_next_int32(data); /* Max size. */
		buffer_read_next_int32(data); /* Offset. */
		actual_size = buffer_read_next_int32(data); /* Actual size. */

		result->names[i] = (char*)safe_malloc(actual_size);
		buffer_read_next_unicode(data, result->names[i], actual_size);

		buffer_read_next_int16(data); /* Padding. */
	}

/*		[out]  uint32 totalentries, */
/*		[in,out]   uint32 *resume_handle*/
	buffer_read_next_int16(data); /* Padding. */
	buffer_read_next_int32(data);

	return 0;
}

void smbclient_send_samr_connect4(SMBCLIENT_t *smbclient)
{
	buffer_t *arguments = buffer_create(BO_LITTLE_ENDIAN);

/*		[in,string,charset(UTF16)] uint16 *system_name, */
	buffer_add_int32(arguments, 0x0012ee18); /* Referent Id. */
	buffer_add_int32(arguments, 0x00000012); /* Max count. */
	buffer_add_int32(arguments, 0x00000000); /* Offset. */
	buffer_add_int32(arguments, 0x00000012); /* Actual count. */
	buffer_add_unicode(arguments, "\\\\192.168.241.128"); /* System name. */

/*		[in] uint32 unknown, */
	buffer_add_int32(arguments, 0x00000002); /* Unknown. */

/*		[in] samr_ConnectAccessMask access_mask, */
	buffer_add_int32(arguments, 0x00000030); /* Access mask. */

/*		[out,ref]  policy_handle *connect_handle */

	smbclient->msrpc_state = MSRPC_SENT_CONNECT4;
	smbclient_msrpc_call_function(smbclient, 0x3E, arguments);
	buffer_destroy(arguments);
}

static uint32_t smbclient_parse_samr_connect4(buffer_t *data, CONNECT4_t *result)
{
/*		[in,string,charset(UTF16)] uint16 *system_name, */
/*		[in] uint32 unknown, */
/*		[in] samr_ConnectAccessMask access_mask, */
/*		[out,ref]  policy_handle *connect_handle */
	buffer_read_next_bytes(data, result->connect_handle, 0x14);

	return 0;
}

void smbclient_send_samr_enumdomains(SMBCLIENT_t *smbclient)
{
	buffer_t *arguments = buffer_create(BO_LITTLE_ENDIAN);

/*		[in,ref]      policy_handle *connect_handle, */
	buffer_add_bytes(arguments, smbclient->connect4.connect_handle, 0x14);
/*		[in,out,ref]  uint32 *resume_handle, */
	buffer_add_int32(arguments, 0);
/*		[in]          uint32 buf_size, */
	buffer_add_int32(arguments, 8192);
/*		[out]         samr_SamArray *sam, */
/*		[out]         uint32 num_entries */

	smbclient->msrpc_state = MSRPC_SENT_ENUMDOMAINS;
	smbclient_msrpc_call_function(smbclient, 0x06, arguments);
	buffer_destroy(arguments);
}

static uint32_t smbclient_parse_samr_enumdomains(buffer_t *data, ENUMDOMAINS_t *result)
{
	size_t i;
/*		[in,ref]      policy_handle *connect_handle, */
/*		[in,out,ref]  uint32 *resume_handle, */
	buffer_read_next_int32(data);
/*		[in]          uint32 buf_size, */
/*		[out]         samr_SamArray *sam, */
	buffer_read_next_int32(data); /* Referent ID */
	result->name_count = buffer_read_next_int32(data); /* Count */
	buffer_read_next_int32(data); /* Referent ID */
	buffer_read_next_int32(data); /* Max count. */

	/* Allocate room for the string list. */
	result->names = (char**) safe_malloc(result->name_count * sizeof(char*));

	for(i = 0; i < result->name_count; i++)
	{
		buffer_read_next_int32(data); /* Idx. */
		buffer_read_next_int16(data); /* Name length. */
		buffer_read_next_int16(data); /* Name size. */
		buffer_read_next_int32(data); /* Referent ID. */
	}

	for(i = 0; i < result->name_count; i++)
	{
		uint32_t max_length;
		max_length = buffer_read_next_int32(data); /* Max count. */
		buffer_read_next_int32(data); /* Offset. */
		buffer_read_next_int32(data); /* Actual count. */

		result->names[i] = safe_malloc(max_length);

		buffer_read_next_unicode(data, result->names[i], max_length);
	}

/*		[out]         uint32 num_entries */
	buffer_read_next_int32(data);

	return 0;
}

void smbclient_send_samr_lookupdomain(SMBCLIENT_t *smbclient, char *domain)
{
	size_t    i;
	buffer_t *arguments = buffer_create(BO_LITTLE_ENDIAN);

/*		[in,ref]  policy_handle *connect_handle, */
	buffer_add_bytes(arguments, smbclient->connect4.connect_handle, 0x14);

/*		[in,ref]  lsa_String *domain_name, */
	buffer_add_int16(arguments, strlen(domain) * 2); /* Name length. */
	buffer_add_int16(arguments, strlen(domain) * 2); /* Name size. */
	buffer_add_int32(arguments, 0x123456); /* Referent ID. */
	buffer_add_int32(arguments, strlen(domain)); /* Max count. */
	buffer_add_int32(arguments, 0); /* Offset. */
	buffer_add_int32(arguments, strlen(domain)); /* Actual count. */

	/* For some reason, this string isn't null-terminated, so just add it manually... */
	for(i = 0; i < strlen(domain); i++)
		buffer_add_int16(arguments, domain[i]);

/*		[out]     dom_sid2 *sid */

	smbclient->msrpc_state = MSRPC_SENT_LOOKUPDOMAIN;
	smbclient_msrpc_call_function(smbclient, 0x05, arguments);
	buffer_destroy(arguments);
}

static uint32_t smbclient_parse_samr_lookupdomain(buffer_t *data, LOOKUPDOMAIN_t *result)
{
	size_t i;

/*		[in,ref]  policy_handle *connect_handle, */
/*		[in,ref]  lsa_String *domain_name, */
/*		[out]     dom_sid2 *sid */
	buffer_read_next_int32(data); /* Referent ID. */

	result->count = buffer_read_next_int32(data); /* Count. */

	result->subauthority = safe_malloc(result->count * sizeof(uint32_t));

	result->revision        = buffer_read_next_int8(data); /* Revision. */
	buffer_read_next_int8(data); /* Num authority. */
	result->authority_high  = buffer_read_next_int16(data); /* Should be part of 'authority', but seems to be 0. */
	result->authority       = buffer_read_next_int32(data); /* Authority. */

	for(i = 0; i < result->count; i++)
		result->subauthority[i] = buffer_read_next_int32(data); /* Sub-authority. */

	return 0;
}

void smbclient_send_samr_opendomain(SMBCLIENT_t *smbclient)
{
	size_t    i;
	buffer_t *arguments = buffer_create(BO_LITTLE_ENDIAN);

/*		[in,ref]      policy_handle *connect_handle, */
	buffer_add_bytes(arguments, smbclient->connect4.connect_handle, 0x14);
/*		[in]          samr_DomainAccessMask access_mask, */
	buffer_add_int32(arguments, 0x00000305);
/*	buffer_add_int32(arguments, 0x00000201);*/
/*		[in,ref]      dom_sid2 *sid, */
	buffer_add_int32(arguments, smbclient->lookupdomain.count);
	buffer_add_int8(arguments, smbclient->lookupdomain.revision);
	buffer_add_int8(arguments, smbclient->lookupdomain.count);
	buffer_add_int16(arguments, smbclient->lookupdomain.authority_high);
	buffer_add_int32(arguments, smbclient->lookupdomain.authority);

	for(i = 0; i < smbclient->lookupdomain.count; i++)
		buffer_add_int32(arguments, smbclient->lookupdomain.subauthority[i]);

/*		[out,ref]     policy_handle *domain_handle */

	smbclient->msrpc_state = MSRPC_SENT_OPENDOMAIN;
	smbclient_msrpc_call_function(smbclient, 0x07, arguments);
	buffer_destroy(arguments);
}

static uint32_t smbclient_parse_samr_opendomain(buffer_t *data, OPENDOMAIN_t *result)
{
/*		[in,ref]      policy_handle *connect_handle, */
/*		[in]          samr_DomainAccessMask access_mask, */
/*		[in,ref]      dom_sid2 *sid, */
/*		[out,ref]     policy_handle *domain_handle */
	buffer_read_next_bytes(data, result->domain_handle, 0x14);

	return 0;
}

void smbclient_send_samr_querydisplayinfo(SMBCLIENT_t *smbclient, uint32_t index)
{
	buffer_t *arguments = buffer_create(BO_LITTLE_ENDIAN);

/*		[in,ref]    policy_handle *domain_handle, */
	buffer_add_bytes(arguments, smbclient->opendomain.domain_handle, 0x14);
/*		[in]        uint16 level, */
	buffer_add_int16(arguments, 0x0001);
	buffer_add_int16(arguments, 0x0000); /* Padding. */
/*		[in]        uint32 start_idx, */
	buffer_add_int32(arguments, index);
/*		[in]        uint32 max_entries, */
	buffer_add_int32(arguments, 1);
/*		[in]        uint32 buf_size, */
	buffer_add_int32(arguments, 0);
/*		[out]       uint32 total_size, */
/*		[out]       uint32 returned_size, */
/*		[out,switch_is(level)] samr_DispInfo info */

	smbclient->msrpc_state = MSRPC_SENT_QUERYDISPLAYINFO;
	smbclient_msrpc_call_function(smbclient, 0x28, arguments);
	buffer_destroy(arguments);
}

static uint32_t smbclient_parse_samr_querydisplayinfo(buffer_t *data, QUERYDISPLAYINFO_t *result, SMBCLIENT_t *smbclient)
{
	uint32_t count;
	uint32_t name_ptr;
	uint32_t fullname_ptr;
	uint32_t description_ptr;
	uint32_t status;

	/* Re-allocate room for one more pointer. This isn't the most efficient way of doing this, but it's the
	 * easiest. */
	result->elements = realloc(result->elements, (result->count + 1) * sizeof(QUERYDISPLAYINFO_ELEMENT_t));
/*	result->elements[result->count] = safe_malloc(sizeof(QUERYDISPLAYINFO_ELEMENT_t));*/

/*		[in,ref]    policy_handle *domain_handle, */
/*		[in]        uint16 level, */
/*		[in]        uint32 start_idx, */
/*		[in]        uint32 max_entries, */
/*		[in]        uint32 buf_size, */
/*		[out]       uint32 total_size, */
	buffer_read_next_int32(data);
/*		[out]       uint32 returned_size, */
	buffer_read_next_int32(data);
/*		[out,switch_is(level)] samr_DispInfo info */
	buffer_read_next_int16(data); /* Info (??). */
	buffer_read_next_int16(data); /* Padding. */
	count = buffer_read_next_int32(data); /* Count. */

	if(count != 1)
		DIE("Don't know how to handle multiple accounts at once!");

	buffer_read_next_int32(data); /* Referent ID. */
	buffer_read_next_int32(data); /* Max count. */
	buffer_read_next_int32(data); /* Index. */
	result->elements[result->count].rid   = buffer_read_next_int32(data); /* RID. */
	result->elements[result->count].flags = buffer_read_next_int32(data); /* Flags. */

	buffer_read_next_int16(data); /* Name length. */
	buffer_read_next_int16(data); /* Name size. */
	name_ptr = buffer_read_next_int32(data); /* Referent ID. */

	buffer_read_next_int16(data); /* Full name length. */
	buffer_read_next_int16(data); /* Full name size. */
	fullname_ptr = buffer_read_next_int32(data); /* Referent ID. */

	buffer_read_next_int16(data); /* Description length. */
	buffer_read_next_int16(data); /* Description size. */
	description_ptr = buffer_read_next_int32(data); /* Referent ID. */

	if(name_ptr)
	{
		uint32_t length;

		length = buffer_read_next_int32(data); /* Name max count. */
		result->elements[result->count].name = safe_malloc_add(length, 1);

		buffer_read_next_int32(data); /* Name offset. */
		buffer_read_next_int32(data); /* Name actual count. */
		buffer_read_next_unicode_data(data, result->elements[result->count].name, length);

		if((length % 2))
			buffer_read_next_int16(data); /* Padding. */
	}
	else
	{
		result->elements[result->count].name = NULL;
	}

	if(fullname_ptr)
	{
		uint32_t length;

		length = buffer_read_next_int32(data); /* Fullname max count. */
		result->elements[result->count].fullname = safe_malloc_add(length, 1);

		buffer_read_next_int32(data); /* Fullname offset. */
		buffer_read_next_int32(data); /* Fullname actual count. */
		buffer_read_next_unicode_data(data, result->elements[result->count].fullname, length);

		if((length % 2))
			buffer_read_next_int16(data); /* Padding. */
	}
	else
	{
		result->elements[result->count].fullname = NULL;
	}

	if(description_ptr)
	{
		uint32_t length;

		length = buffer_read_next_int32(data); /* Description max count. */
		result->elements[result->count].description = safe_malloc_add(length, 1);

		buffer_read_next_int32(data); /* Description offset. */
		buffer_read_next_int32(data); /* Description actual count. */
		buffer_read_next_unicode_data(data, result->elements[result->count].description, length);

		if((length % 2))
			buffer_read_next_int16(data); /* Padding. */
	}
	else
	{
		result->elements[result->count].description = NULL;
	}

	/* Increment the number of results. */
	result->count = result->count + 1;

	/* Ask for next packet, if there are more entries. */
	status = buffer_read_next_int32(data);
	if(status == 0x00000105)
	{
		smbclient_send_samr_querydisplayinfo(smbclient, result->count);
		return 1;
	}

	return 0;
}

void smbclient_send_samr_querydomaininfo2(SMBCLIENT_t *smbclient, uint16_t level)
{
	buffer_t *arguments = buffer_create(BO_LITTLE_ENDIAN);

/*		[in,ref]      policy_handle *domain_handle, */
	buffer_add_bytes(arguments, smbclient->opendomain.domain_handle, 0x14);
/*		[in]          uint16 level, */
	buffer_add_int16(arguments, level);
/*		[out,switch_is(level)] samr_DomainInfo *info */

	smbclient->msrpc_state = MSRPC_SENT_QUERYDOMAININFO2;
	smbclient_msrpc_call_function(smbclient, 0x2e, arguments);
	buffer_destroy(arguments);
}

static uint32_t smbclient_parse_samr_querydomaininfo2(buffer_t *data, QUERYDOMAININFO2_t *result, SMBCLIENT_t *smbclient)
{
	uint16_t level;

	buffer_read_next_int32(data); /* Referent ID. */
	level = buffer_read_next_int16(data); /* Level. */
	buffer_read_next_int16(data); /* Padding. */

	switch(level)
	{
		case 1:
		{
/*		uint16 min_password_length; */
			result->min_password_length = buffer_read_next_int16(data);
/*		uint16 password_history_length; */
			result->password_history_length = buffer_read_next_int16(data);
/*		samr_PasswordProperties password_properties; */
			result->password_properties = buffer_read_next_int32(data);
/*		dlong  max_password_age; */
			result->max_password_age_high = buffer_read_next_int32(data);
			result->max_password_age_low  = buffer_read_next_int32(data);
/*		dlong  min_password_age; */
			result->min_password_age_high = buffer_read_next_int32(data);
			result->min_password_age_low  = buffer_read_next_int32(data);

			smbclient_send_samr_querydomaininfo2(smbclient, 8);

			return 1;
		}
		break;

		case 8:
		{
/*		hyper sequence_num; */
			buffer_read_next_int32(data);
			buffer_read_next_int32(data);
/*		NTTIME domain_create_time; */
			result->create_time_high = buffer_read_next_int32(data);
			result->create_time_low  = buffer_read_next_int32(data);

			smbclient_send_samr_querydomaininfo2(smbclient, 12);

			return 1;
		}
		break;

		case 12:
		{
/*		hyper lockout_duration; */
			result->lockout_duration_high = buffer_read_next_int32(data);
			result->lockout_duration_high = buffer_read_next_int32(data);
/*		hyper lockout_window; */
			result->lockout_duration_high = buffer_read_next_int32(data);
			result->lockout_duration_high = buffer_read_next_int32(data);
/*		uint16 lockout_threshold; */
			result->lockout_threshold = buffer_read_next_int16(data);

			return 0;
		}
		break;
	}

	return 1;
}


static uint32_t smbclient_msrpc_parse(SMBCLIENT_t *smbclient, SMB_t *smb, size_t parameter_position, uint16_t parameter_size, size_t data_position, uint16_t data_size)
{
	MSRPC_TYPE_t type;
	uint8_t flags;
	uint16_t auth_length;

	/* Put the buffer to the start of the data. */
	buffer_set_current_offset(smb_get_data(smb, 0), data_position);

	/* Read the common stuff. */
	buffer_read_next_int8(smb_get_data(smb, 0)); /* Version (major). */
	buffer_read_next_int8(smb_get_data(smb, 0));  /* Version (minor). */
	type = buffer_read_next_int8(smb_get_data(smb, 0));  /* Packet type. */
	flags = buffer_read_next_int8(smb_get_data(smb, 0));  /* Packet flags -- unless it's 0x03, we don't know how to handle. */
	buffer_read_next_int32(smb_get_data(smb, 0)); /* Data representation (big endian). */
	buffer_read_next_int16(smb_get_data(smb, 0)); /* Frag length. */
	auth_length = buffer_read_next_int16(smb_get_data(smb, 0)); /* Auth length -- Don't know how to handle this. */
	buffer_read_next_int32(smb_get_data(smb, 0)); /* Call ID -- What we sent, echoed back. */

	if(auth_length > 0)
		DIE("Received an auth request, don't know how to handle it.");

	if((flags & 0x03) != 0x03)
		DIE("Received fragmented response, don't know how to handle.");

	/* 0x20 = call failed. */
	if(flags & 0x20 || type == MSRPC_FAULT)
	{
		uint32_t status;

		buffer_read_next_int32(smb_get_data(smb, 0)); /* Alloc hint. */
		buffer_read_next_int16(smb_get_data(smb, 0)); /* Context ID. */
		buffer_read_next_int8(smb_get_data(smb, 0));  /* Cancel count. */
		buffer_read_next_int8(smb_get_data(smb, 0));  /* Padding. */
		status = buffer_read_next_int32(smb_get_data(smb, 0)); /* Status. */

		return status;
	}
	else if(type == MSRPC_BIND_ACK)
	{
		uint32_t status;

		buffer_read_next_int16(smb_get_data(smb, 0)); /* Max transmit frag. */
		buffer_read_next_int16(smb_get_data(smb, 0)); /* Max receive frag. */
		buffer_read_next_int32(smb_get_data(smb, 0)); /* Assoc group -- ???. */
		smbclient->service_length = buffer_read_next_int16(smb_get_data(smb, 0)); /* Secondary address length. */
		smbclient->service = safe_malloc(smbclient->service_length);
		buffer_read_next_bytes(smb_get_data(smb, 0), smbclient->service, smbclient->service_length);
		smb_align_data(smb, 0, 4);
		buffer_read_next_int8(smb_get_data(smb, 0));  /* Num results. */
		smb_align_data(smb, 0, 4);
		status = buffer_read_next_int16(smb_get_data(smb, 0)); /* Result. */
		smb_align_data(smb, 0, 4);
		buffer_read_next_bytes(smb_get_data(smb, 0), smbclient->receive_syntax, 16);
		buffer_read_next_int32(smb_get_data(smb, 0)); /* Syntax version. */

		if(memcmp(smbclient->send_syntax, smbclient->receive_syntax, 16))
		{
			int i;

			fprintf(stderr, "WARNING: receive syntax is different than send syntax, this may be due to alignment problems!\n");
			printf("Requested: ");
			for(i = 0; i < 16; i++)
				printf("%02x", smbclient->send_syntax[i]);
			printf("\n");
			printf("Received:  ");
			for(i = 0; i < 16; i++)
				printf("%02x", smbclient->receive_syntax[i]);
			printf("\n");
		}

		if(!status)
		{
			smbclient->bound = TRUE;

			smbclient->event_callback(smbclient, SMBCLIENT_MSRPC_BIND_ACK, NULL);
		}
		else
		{
			smbclient->event_callback(smbclient, SMBCLIENT_MSRPC_BIND_FAILED, NULL);
		}
	}
	else if(type == MSRPC_RESPONSE) /* RESPONSE */
	{
		buffer_read_next_int32(smb_get_data(smb, 0)); /* Alloc hint. */
		buffer_read_next_int16(smb_get_data(smb, 0)); /* Context ID. */
		buffer_read_next_int8(smb_get_data(smb, 0));  /* Cancel count. */
		buffer_read_next_int8(smb_get_data(smb, 0));  /* Padding. */

		switch(smbclient->msrpc_state)
		{
			case MSRPC_SENT_NETSHAREENUMALL:
			{
				if(!smbclient_parse_srvsvc_netshareenumall(smb_get_data(smb, 0), &smbclient->netshareenumall))
					smbclient->event_callback(smbclient, SMBCLIENT_MSRPC_NETSHAREENUMALL, &smbclient->netshareenumall);
			}
			break;

			case MSRPC_SENT_CONNECT4:
			{
				if(!smbclient_parse_samr_connect4(smb_get_data(smb, 0), &smbclient->connect4))
					smbclient->event_callback(smbclient, SMBCLIENT_MSRPC_CONNECT4, &smbclient->connect4);
			}
			break;

			case MSRPC_SENT_ENUMDOMAINS:
			{
				if(!smbclient_parse_samr_enumdomains(smb_get_data(smb, 0), &smbclient->enumdomains))
					smbclient->event_callback(smbclient, SMBCLIENT_MSRPC_ENUMDOMAINS, &smbclient->enumdomains);
			}
			break;

			case MSRPC_SENT_LOOKUPDOMAIN:
			{
				if(!smbclient_parse_samr_lookupdomain(smb_get_data(smb, 0), &smbclient->lookupdomain))
					smbclient->event_callback(smbclient, SMBCLIENT_MSRPC_LOOKUPDOMAIN, &smbclient->lookupdomain);
			}
			break;

			case MSRPC_SENT_OPENDOMAIN:
			{
				if(!smbclient_parse_samr_opendomain(smb_get_data(smb, 0), &smbclient->opendomain))
					smbclient->event_callback(smbclient, SMBCLIENT_MSRPC_OPENDOMAIN, &smbclient->opendomain);
			}
			break;

			case MSRPC_SENT_QUERYDISPLAYINFO:
			{
				if(!smbclient_parse_samr_querydisplayinfo(smb_get_data(smb, 0), &smbclient->querydisplayinfo, smbclient))
					smbclient->event_callback(smbclient, SMBCLIENT_MSRPC_QUERYDISPLAYINFO, &smbclient->querydisplayinfo);
			}
			break;

			case MSRPC_SENT_QUERYDOMAININFO2:
			{
				if(!smbclient_parse_samr_querydomaininfo2(smb_get_data(smb, 0), &smbclient->querydomaininfo2, smbclient))
					smbclient->event_callback(smbclient, SMBCLIENT_MSRPC_QUERYDOMAININFO2, &smbclient->querydomaininfo2);
			}
			break;

			case MSRPC_NULL:
			{
				DIE("Received packet in bad state!");
			}
		}
	}

	return 0;
}

void smbclient_raise_verbose(SMBCLIENT_t *smbclient)
{
	smbclient->verbose++;
}

void smbclient_raise_check_signature(SMBCLIENT_t *smbclient)
{
	smbclient->check_signature++;
}



