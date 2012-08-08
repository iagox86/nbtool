/* datagram.c
 * By Ron Bowes
 * Created August, 2008
 *
 * (See LICENSE.txt)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "buffer.h"
#include "memory.h"
#include "nameservice.h"
#include "types.h"
#include "udp.h"

#include "datagram.h"

void ds_send_datagram(int s, DS_MSG_TYPE_t msg_type, DS_FLAGS_t flags, uint16_t DGM_ID, uint16_t packet_offset, char *sourcename, NAME_TYPE_t sourcename_type, char *sourceip, uint16_t sourceport, char *destinationname, NAME_TYPE_t destinationname_type, char *destinationip, uint8_t *data, uint16_t datalength)
{
	uint8_t *buffer_data;
	uint16_t buffer_length;
	char    *encoded_sourcename      = name_encode(sourcename,      "", name_choose_padding(sourcename),      sourcename_type);
	char    *encoded_destinationname = name_encode(destinationname, "", name_choose_padding(destinationname), destinationname_type);


	buffer_t *buffer = buffer_create(BO_NETWORK);

	buffer_add_int8(buffer,  msg_type);
	buffer_add_int8(buffer,  flags);
	buffer_add_int16(buffer, DGM_ID);
	buffer_add_int32(buffer, ntohl(inet_addr(sourceip)));
	buffer_add_int16(buffer, sourceport);
	buffer_add_int16(buffer, strlen(encoded_sourcename) + 1 + strlen(encoded_destinationname) + 1 + datalength);
	buffer_add_int16(buffer, packet_offset);
	buffer_add_ntstring(buffer, encoded_sourcename);
	buffer_add_ntstring(buffer, encoded_destinationname);
	buffer_add_bytes(buffer, data, datalength);

	buffer_length = buffer_get_length(buffer);
	buffer_data = safe_malloc(buffer_length);
	buffer_read_next_bytes(buffer, buffer_data, buffer_length);

	udp_send(s, destinationip, 138, buffer_data, buffer_length);

	buffer_destroy(buffer);

	safe_free(buffer_data);
	safe_free(encoded_destinationname);
	safe_free(encoded_sourcename);
}

void ds_send_query(int s, DS_FLAGS_t flags, uint16_t DGM_ID, char *sourceip, uint16_t sourceport, char *destinationip, char *lookupname, NAME_TYPE_t lookupname_type)
{
	uint8_t *buffer_data;
	uint16_t buffer_length;
	char    *lookupname_encoded = name_encode(lookupname, "", name_choose_padding(lookupname), lookupname_type);

	buffer_t *buffer = buffer_create(BO_NETWORK);
	buffer_add_int8(buffer, MSG_TYPE_QUERY_REQUEST);
	buffer_add_int8(buffer, flags);
	buffer_add_int16(buffer, DGM_ID);
	buffer_add_int32(buffer, ntohl(inet_addr(sourceip)));
	buffer_add_int16(buffer, sourceport);
	buffer_add_ntstring(buffer, lookupname_encoded);

	buffer_length = buffer_get_length(buffer);
	buffer_data = safe_malloc(buffer_length);
	buffer_read_next_bytes(buffer, buffer_data, buffer_length);

	udp_send(s, destinationip, 138, buffer_data, buffer_length);

	safe_free(buffer_data);
	buffer_destroy(buffer);
	safe_free(lookupname_encoded);
}






