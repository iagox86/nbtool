/* smb.c
 * By Ron
 * Created August 26, 2008
 *
 * (See LICENSE.txt)
 *
 * Implements part of the SMB protocol (TCP ports 139 or 445).
 *
 * Last time I checked it worked, but I'm not using it for anything right now.
 */

#ifndef __SMB_H__
#define __SMB_H__

#include "buffer.h"
#include "smb_types.h"
#include "types.h"

/* Some data that is required by all SMBs. */
/*typedef struct
{
	uint32_t sequence_number;
	uint8_t mac_key[40];
	int check_signature;
} SMB_SETTINGS_t;*/

/* Create a new instance of the class with the given command and default values. The number of 'andx'ed packets
 * is given as the second parameter. */
SMB_t *smb_create(SMB_COMMAND_t command, size_t andx_count, uint16_t uid, uint16_t tid, NBBOOL signatures);

/* Create a new instance of the class, designed as a reply. Uses the PID and such from 'base'. */
SMB_t *smb_create_response(SMB_COMMAND_t command, size_t andx_count, SMB_t *base);

/* Create a new instance of the class based on received data. */
SMB_t *smb_create_from_data(uint8_t *data, size_t length, uint32_t *sequence_number, uint8_t mac_key[40], int check_signature);

/* Destroy an instance. */
void   smb_destroy(SMB_t *smb);

/* Make a copy of the SMB object. */
SMB_t *smb_duplicate(SMB_t *base);

/* Get the parameter buffer. Second parameter is which 'andx'ed element to return. */
buffer_t *smb_get_parameters(SMB_t *smb, size_t index);
/* Get the data buffer. Second parameter is which 'andx'ed element to return. */
buffer_t *smb_get_data(SMB_t *smb, size_t index);

/* Gets the length of the SMB packet, that will be returned by smb_get() */
size_t smb_get_length(SMB_t *smb);
/* Ensure buffer is long enough using smb_get_length(). */
void smb_get(SMB_t *smb, uint8_t *buffer, size_t buffer_length);

/* Send the SMB packet over the socket. A signature is always attached, if possible. */
void smb_send(SMB_t *smb, int s, uint32_t *sequence_number, uint8_t mac_key[40]);

/* Check if a command is ANDX */
NBBOOL smb_is_andx(SMB_COMMAND_t command);

/* Check if an error is present. */
NBBOOL smb_is_error(SMB_t *smb);

/* Aligns the current position in the buffer to an even multiple from the beginning of
 * the SMB packet. Actual implementations often align data to multiples of 4. */
void smb_align_data(SMB_t *smb, size_t index, int align);

#endif
