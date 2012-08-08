/* smb.c
 * By Ron
 * Created August 26, 2008
 *
 * (See LICENSE.txt)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "buffer.h"
#include "crypto.h"
#include "memory.h"
#include "tcp.h"
#include "types.h"

#include "smb.h"

static void smb_get_internal(SMB_t *smb, uint8_t *buffer, size_t buffer_length, uint32_t sequence_number, NBBOOL netbios_header);
static void smb_populate_signature(SMB_t *smb, uint32_t *sequence_number, uint8_t mac_key[40]);
static void smb_check_signature(SMB_t *smb, uint32_t *sequence_number, uint8_t mac_key[40], int check_signature);

/* Create a new instance of the class with the given command and default values. */
SMB_t *smb_create(SMB_COMMAND_t command, size_t andx_count, uint16_t uid, uint16_t tid, NBBOOL signatures)
{
	size_t i;

	SMB_t *smb_new = safe_malloc(sizeof(SMB_t));
	memset(smb_new, 0, sizeof(SMB_t));

	smb_new->andx_count = andx_count;

	smb_new->header.protocol[0] = 0xFF;
	smb_new->header.protocol[1] = 'S';
	smb_new->header.protocol[2] = 'M';
	smb_new->header.protocol[3] = 'B';

	/* Set the command. */
	smb_new->header.command = command;

	/* Use a static pid, since it doesn't really matter. */
	smb_new->header.pid     = 0x1337;

	/* Use the client's uid and tid. */
	smb_new->header.uid = uid;
	smb_new->header.tid = tid;

	/* Set some nice default flags. */
	smb_new->header.flags  = SMB_FLAGS_CANONICAL_PATHNAMES | SMB_FLAGS_CASELESS_PATHNAMES;
	smb_new->header.flags2 = SMB_FLAGS2_32BIT_STATUS | SMB_FLAGS2_IS_LONG_NAME | SMB_FLAGS2_KNOWS_LONG_NAMES;
	if(signatures)
		smb_new->header.flags2 |= SMB_FLAGS2_SECURITY_SIGNATURE;

	/* Allocate memory for the parameters/data arrays. */
	smb_new->parameters = safe_malloc(sizeof(SMB_PARAMETERS_t) * andx_count);
	smb_new->data       = safe_malloc(sizeof(SMB_PARAMETERS_t) * andx_count);

	for(i = 0; i < andx_count; i++)
	{
		smb_new->parameters[i].buffer = buffer_create(BO_LITTLE_ENDIAN);
		smb_new->data[i].buffer       = buffer_create(BO_LITTLE_ENDIAN);
	}

	return smb_new;
}

/* Designed for servers. */
SMB_t *smb_create_response(SMB_COMMAND_t command, size_t andx_count, SMB_t *base)
{
	SMB_t *smb = smb_create(command, andx_count, 0, 0, 0);
	/* Set as a response. */
	smb->header.flags |= SMB_FLAGS_SERVER_TO_REDIR;
	smb->header.flags2 = 0xc8f3; /* TODO: Testinog */
	smb->header.extra.pid_high = base->header.extra.pid_high;
	smb->header.pid = base->header.pid;
	smb->header.mid = base->header.mid;

	return smb;
}

SMB_t *smb_create_from_data(uint8_t *data, size_t length, uint32_t *sequence_number, uint8_t mac_key[40], int check_signature)
{
	size_t i, j;
	SMB_t    *smb = safe_malloc(sizeof(SMB_t));

	/* Start by putting everything into a buffer. */
	buffer_t *buffer = buffer_create_with_data(BO_LITTLE_ENDIAN, data, length);

	/* Zero-out the buffer to start. */
	memset(smb, 0, sizeof(SMB_t));


	/* Read all the data into a buffer. */
	smb->header.protocol[0]     = buffer_read_next_int8(buffer);
	smb->header.protocol[1]     = buffer_read_next_int8(buffer);
	smb->header.protocol[2]     = buffer_read_next_int8(buffer);
	smb->header.protocol[3]     = buffer_read_next_int8(buffer);

	smb->header.command         = buffer_read_next_int8(buffer);
	smb->header.status          = buffer_read_next_int32(buffer);

	smb->header.flags           = buffer_read_next_int8(buffer);
	smb->header.flags2          = buffer_read_next_int16(buffer);
	smb->header.extra.pid_high  = buffer_read_next_int16(buffer);
	buffer_read_next_bytes(buffer, smb->header.extra.signature, 8);
	smb->header.extra.unused    = buffer_read_next_int16(buffer);
	smb->header.tid             = buffer_read_next_int16(buffer);
	smb->header.pid             = buffer_read_next_int16(buffer);
	smb->header.uid             = buffer_read_next_int16(buffer);
	smb->header.mid             = buffer_read_next_int16(buffer);

	/* Check some variables to make sure we're sane. */
	if((smb->header.protocol[0] != 0xFF) || (smb->header.protocol[1] != 'S') || (smb->header.protocol[2] != 'M') || (smb->header.protocol[3] != 'B'))
		DIE("SMB header was incorrect ('B'), are we out of sync?");

	/* Check the PID (TODO: check against proper value, if I ever bother with one). */
/*	if(smb->header.pid != 0x1337)
		DIE("Returned 'PID' was incorrect"); */

	/* TODO: This may not be the best way to handle errors. */
	if(!smb_is_error(smb))
	{
		/* Now, it gets a little painful. We should be at the end of the header and the start of the
		 * parameters. Now, we need to check if we're in an ANDX packet. */
		if(smb_is_andx(smb->header.command))
		{
			uint8_t  parameter_length;
			uint16_t data_length;
			size_t   current_offset;
			uint8_t  next_command;

			/* Start off by getting the number of ANDXes. We do this by hopping across the objects in the buffer. */

			/* Should point to the parameter's length, which is 1 byte, followed by the 2-byte command that we
			 * don't current care about, then the 2-byte offset which we do. */
			current_offset = buffer_get_current_offset(buffer);
			do
			{
				smb->andx_count++;
				next_command   = buffer_read_int8_at(buffer, current_offset + 1);
				current_offset = buffer_read_int16_at(buffer, current_offset + 3);
			}
			while(current_offset && next_command != SMB_NO_FURTHER_COMMANDS);

			/* Now that we hopefully have the ANDX count, allocate memory to hold the objects. */
			smb->parameters = safe_malloc(sizeof(SMB_PARAMETERS_t) * smb->andx_count);
			smb->data       = safe_malloc(sizeof(SMB_DATA_t) * smb->andx_count);

			/* For each ANDX section, read it in. */
			current_offset = buffer_get_current_offset(buffer);
			for(i = 0; i < smb->andx_count; i++)
			{
				/* Create the parameter buffer. */
				smb->parameters[i].buffer = buffer_create(BO_LITTLE_ENDIAN);
				parameter_length = buffer_read_int8_at(buffer, current_offset);
				for(j = 0; j < (size_t)parameter_length * 2; j++)
					buffer_add_int8(smb->parameters[i].buffer, buffer_read_int8_at(buffer, current_offset + 1 + j));

				/* Create the data buffer. */
				smb->data[i].buffer = buffer_create(BO_LITTLE_ENDIAN);
				data_length = buffer_read_int16_at(buffer, current_offset + 1 + (parameter_length * 2));
				for(j = 0; j < data_length; j++)
					buffer_add_int8(smb->data[i].buffer, buffer_read_int8_at(buffer, current_offset + 1 + (parameter_length * 2) + 2 + j));

				/* And finally, move to the next offset. */
				current_offset = buffer_read_int16_at(buffer, current_offset + 3);
			}
		}
		else
		{
			uint8_t  parameter_length;
			uint16_t data_length;

			/* Without andx, it's easy -- just allocate one of everything. */
			smb->andx_count = 1;
			smb->parameters = safe_malloc(sizeof(SMB_PARAMETERS_t));
			smb->data = safe_malloc(sizeof(SMB_DATA_t));

			smb->parameters[0].buffer = buffer_create(BO_LITTLE_ENDIAN);
			smb->data[0].buffer = buffer_create(BO_LITTLE_ENDIAN);

			/* Read in the parameter size + parameters (remember, it's the number of 2-byte values so
			 * it's doubled). TODO: Make this more efficient than byte-by-byte?*/
			parameter_length = buffer_read_next_int8(buffer);
			for(i = 0; i < (size_t)parameter_length * 2; i++)
				buffer_add_int8(smb->parameters[0].buffer, buffer_read_next_int8(buffer));

			/* Read in the data size + data. TODO: More efficient? */
			data_length = buffer_read_next_int16(buffer);
			for(i = 0; i < data_length; i++)
				buffer_add_int8(smb->data[0].buffer, buffer_read_next_int8(buffer));
		}
	}

	buffer_destroy(buffer);

	smb_check_signature(smb, sequence_number, mac_key, check_signature);

	return smb;
}


/* Destroy an instance. */
void smb_destroy(SMB_t *smb)
{
	size_t i;

	for(i = 0; i < smb->andx_count; i++)
	{
		buffer_destroy(smb->parameters[i].buffer);
		buffer_destroy(smb->data[i].buffer);
	}

	memset(smb->parameters, 0, sizeof(SMB_PARAMETERS_t) * smb->andx_count);
	safe_free(smb->parameters);

	memset(smb->data, 0, sizeof(SMB_DATA_t) * smb->andx_count);
	safe_free(smb->data);

	memset(smb, 0, sizeof(SMB_t));
	safe_free(smb);
}

SMB_t *smb_duplicate(SMB_t *base)
{
	size_t i;

	SMB_t *new = safe_malloc(sizeof(SMB_t));
	memcpy(new, base, sizeof(SMB_t));

	new->parameters = safe_malloc(sizeof(SMB_PARAMETERS_t) * new->andx_count);
	new->data       = safe_malloc(sizeof(SMB_DATA_t) * new->andx_count);

	for(i = 0; i < new->andx_count; i++)
	{
		new->parameters[i].buffer = buffer_duplicate(base->parameters[i].buffer);
		new->data[i].buffer = buffer_duplicate(base->data[i].buffer);
	}

	return new;
}

/* Get the parameter buffer. */
buffer_t *smb_get_parameters(SMB_t *smb, size_t index)
{
	return smb->parameters[index].buffer;
}

/* Get the data buffer. */
buffer_t *smb_get_data(SMB_t *smb, size_t index)
{
	return smb->data[index].buffer;
}

/* Gets the length of the SMB packet, that will be returned by smb_get() */
size_t smb_get_length_internal(SMB_t *smb, NBBOOL netbios_header)
{
	size_t i;
	size_t size = netbios_header ? 4 : 0; /* NetBIOS Session header. */
	size = size + 32; /* Header = 8 * 4 * 8 bits. */

	for(i = 0; i < smb->andx_count; i++)
	{
		size = size + 1 + buffer_get_length(smb->parameters[i].buffer); /* 1 for the length. */
		size = size + 2 + buffer_get_length(smb->data[i].buffer); /* 2 for the length. */
	}

	return size;
}

size_t smb_get_length(SMB_t *smb)
{
	return smb_get_length_internal(smb, TRUE);
}

void smb_get(SMB_t *smb, uint8_t *buffer, size_t buffer_length)
{
	smb_get_internal(smb, buffer, buffer_length, -1, TRUE);
}

/* Set sequence_number to -1 (or 0xFFFFFFFF) to get the packet without. */
static void smb_get_internal(SMB_t *smb, uint8_t *buffer, size_t buffer_length, uint32_t sequence_number, NBBOOL netbios_header)
{
	size_t i;

	buffer_t *ret = buffer_create(BO_LITTLE_ENDIAN);

	/* Session Header -- note that, since this is NetBIOS and not SMB, this is network byte order. Also, it's 24-bits. */
	if(smb_get_length(smb) - 4 > 0x00FFFFFF)
		DIE("Attempted to send a huge SMB message (max = 0x00FFFFFF)");

	if(netbios_header)
	{
		buffer_add_int8(ret, 0);
		buffer_add_int8(ret, (uint8_t)(((smb_get_length(smb) - 4) >> 16) & 0x0FF));
		buffer_add_int8(ret, (uint8_t)(((smb_get_length(smb) - 4) >>  8) & 0x0FF));
		buffer_add_int8(ret, (uint8_t)(((smb_get_length(smb) - 4) >>  0) & 0x0FF));
	}

	/* Header */
	buffer_add_int8(ret, smb->header.protocol[0]);
	buffer_add_int8(ret, smb->header.protocol[1]);
	buffer_add_int8(ret, smb->header.protocol[2]);
	buffer_add_int8(ret, smb->header.protocol[3]);

	buffer_add_int8(ret, smb->header.command);
	buffer_add_int32(ret, smb->header.status);
	buffer_add_int8(ret, smb->header.flags);
	buffer_add_int16(ret, smb->header.flags2);

	buffer_add_int16(ret, smb->header.extra.pid_high);
	if(sequence_number == 0xFFFFFFFF)
	{
		buffer_add_bytes(ret, smb->header.extra.signature, 8);
	}
	else
	{
		buffer_add_int32(ret, sequence_number);
		buffer_add_int32(ret, 0);
	}
	buffer_add_int16(ret, smb->header.extra.unused);

	buffer_add_int16(ret, smb->header.tid);
	buffer_add_int16(ret, smb->header.pid);
	buffer_add_int16(ret, smb->header.uid);
	buffer_add_int16(ret, smb->header.mid);

	/* Loop across the 'andx'ed parameters and data. */
	for(i = 0; i < smb->andx_count; i++)
	{
		uint8_t *parameter_buffer;
		uint8_t *data_buffer;

		size_t parameter_length = buffer_get_length(smb->parameters[i].buffer);
		size_t data_length      = buffer_get_length(smb->data[i].buffer);

		/* Perform some sanity checks. */
		if(parameter_length > 0x0FF)
			DIE("Too much data in parameters (max length is 254 bytes).");
		if(parameter_length % 2)
			DIE("Size of parameters has to be a multiple of 2.");

		if(data_length > 0x0FFFF)
			DIE("Too much data in SMB packet (max is 65535 bytes).");

		parameter_buffer = safe_malloc(parameter_length);
		buffer_peek_next_bytes(smb->parameters[i].buffer, parameter_buffer, parameter_length);

		data_buffer = safe_malloc(data_length);
		buffer_peek_next_bytes(smb->data[i].buffer, data_buffer, data_length);

		/* Parameters */
		buffer_add_int8(ret, parameter_length / 2);
		buffer_add_bytes(ret, parameter_buffer, parameter_length);

		/* Data */
		buffer_add_int16(ret, data_length);
		buffer_add_bytes(ret, data_buffer, data_length);

		/* Free the resources. */
		safe_free(data_buffer);
		safe_free(parameter_buffer);
	}

	if(netbios_header && (buffer_get_length(ret) != buffer_length))
		DIE("Lengths don't match up.");

	/* Finally, copy it all into the buffer. */
	buffer_read_next_bytes(ret, buffer, buffer_get_length(ret));

	buffer_destroy(ret);
}

static void smb_populate_signature(SMB_t *smb, uint32_t *sequence_number, uint8_t mac_key[40])
{
	size_t   length = smb_get_length_internal(smb, FALSE);
	uint8_t *data   = safe_malloc(length);
	uint8_t  signature[8];

	/* Get the full SMB structure, with the sequence number in place of the signature. */
	smb_get_internal(smb, data, length, *sequence_number, FALSE);

	/* Increment the sequence number. */
	*sequence_number = *sequence_number + 1;

	/* Calculate the signature appropriately. */
	calculate_signature(data, length, mac_key, signature);

	/* Populate it in the smb struct. */
	memcpy(smb->header.extra.signature, signature, 8);

	/* Free our temp data. */
	safe_free(data);
}

static void smb_check_signature(SMB_t *smb, uint32_t *sequence_number, uint8_t mac_key[40], int check_signature)
{
	size_t   length = smb_get_length_internal(smb, FALSE);
	uint8_t *data   = safe_malloc(length);
	uint8_t  signature[8];

	/* Get the full SMB structure, with the sequence number in place of the signature. */
	smb_get_internal(smb, data, length, *sequence_number, FALSE);

	/* Increment the sequence number. */
	*sequence_number = *sequence_number + 1;

	/* Calculate the signature appropriately. */
	calculate_signature(data, length, mac_key, signature);

	/* Verify it in the smb struct. */
	if(memcmp(signature, smb->header.extra.signature, 8))
	{
		if(check_signature == 0)
			; /* We don't care. */
		else if(check_signature == 1)
			fprintf(stderr, "*** Warning: Server sent invalid signature!\n");
		else
			DIE("Server sent invalid signature.\n");
	}
	else
	{
/*		printf("server signature matched!\n");*/
	}
}

void smb_send(SMB_t *smb, int s, uint32_t *sequence_number, uint8_t mac_key[40])
{
	size_t   length = smb_get_length(smb);
	uint8_t *data   = safe_malloc(length);

	smb_populate_signature(smb, sequence_number, mac_key); /* TODO: Make this configurable. */
	smb_get(smb, data, length);
	tcp_send(s, data, length);

	safe_free(data);
}

NBBOOL smb_is_andx(SMB_COMMAND_t command)
{
	if((command == SMB_COM_LOCKING_ANDX) ||
	    (command == SMB_COM_OPEN_ANDX) ||
	    (command == SMB_COM_READ_ANDX) ||
	    (command == SMB_COM_WRITE_ANDX) ||
	    (command == SMB_COM_SESSION_SETUP_ANDX) ||
	    (command == SMB_COM_LOGOFF_ANDX) ||
	    (command == SMB_COM_TREE_CONNECT_ANDX) ||
	    (command == SMB_COM_NT_CREATE_ANDX))
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

NBBOOL smb_is_error(SMB_t *smb)
{
	if(smb->header.flags2 & SMB_FLAGS2_32BIT_STATUS)
	{
		return (smb->header.status & 0xC0000000) == 0xC0000000;
	}
	else
	{
		return smb->header.status;
	}
}

static size_t smb_get_current_position_data(SMB_t *smb, size_t index)
{
	size_t i;
	size_t location = 0;

	/* Header size. */
	location = location + 0x20;

	/* Parameters. */
	for(i = 0; i < smb->andx_count; i++)
	{
		/* Word length. */
		location = location + 0x01;
		/* Buffer length. */
		location = location + buffer_get_length(smb_get_parameters(smb, i));
	}

	/* Data sections before the current one. */
	if(index > 0)
	{
		for(i = 0; i < index - 1; i++)
		{
			printf("i = %d, index - 1 = %d\n", i, index - 1);
			/* Length. */
			location = location + 0x02;
			/* Buffer. */
			location = location + buffer_get_length(smb_get_data(smb, i));
		}
	}

	/* Size of the current buffer. */
	location = location + 2;

	/* Current position in the current buffer */
	location = location + buffer_get_current_offset(smb_get_data(smb, index));

	return location;
}

void smb_align_data(SMB_t *smb, size_t index, int align)
{
	while(smb_get_current_position_data(smb, index) % align)
		buffer_read_next_int8(smb_get_data(smb, index));
}


