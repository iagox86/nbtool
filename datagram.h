/* datagram.h
 * By Ron Bowes
 * Created August, 2008
 *
 * (See LICENSE.txt)
 *
 * This implements the NetBIOS datagram service, which runs on UDP port 138. I implemented
 * it in the hopes of learning more about the protocol, but never actually got around to
 * using it. At this point, this library works, but is unused.
 */

#ifndef __DATAGRAM_H__
#define __DATAGRAM_H__

#include "nameservice.h"
#include "types.h"

/* Datagram packet header
 * --------------------------------------------------
 * |  15 14 13 12 11 10 9  8  7  6  5  4  3  2  1  0 |
 * |        MSG_TYPE        |       FLAGS            |
 * |                     DGM_ID                      | (FLAGS)
 * |                   SOURCE_IP                     |
 * |                                                 |
 * |                  SOURCE_PORT                    |
 * --------------------------------------------------
 */


typedef enum
{
	MSG_TYPE_DIRECT_UNIQUE     = 0x10, /* Unicast */
	MSG_TYPE_DIRECT_GROUP      = 0x11, /* Multicast */
	MSG_TYPE_BROADCAST         = 0x12, /* Broadcast */
	MSG_TYPE_ERROR             = 0x13,
	MSG_TYPE_QUERY_REQUEST     = 0x14,
	MSG_TYPE_POSITIVE_RESPONSE = 0x15,
	MSG_TYPE_NEGATIVE_RESPONSE = 0x15
} DS_MSG_TYPE_t;

#define DS_FLAGS_SNT_LOCATION 0x02
#define DS_FLAGS_F_LOCATION   0x01
#define DS_FLAGS_M_LOCATION   0x00

#define DS_FLAGS_SNT_MASK     0x0C
#define DS_FLAGS_F_MASK       0x02
#define DS_FLAGS_M_MASK       0x01

typedef enum
{
	DS_FLAGS_SNT_B = 0x0 << DS_FLAGS_SNT_LOCATION, /* Broadcast */
	DS_FLAGS_SNT_P = 0x1 << DS_FLAGS_SNT_LOCATION, /* Point-to-point */
	DS_FLAGS_SNT_M = 0x2 << DS_FLAGS_SNT_LOCATION, /* Mixed */
	DS_FLAGS_SNT_H = 0x3 << DS_FLAGS_SNT_LOCATION, /* Hybrid */

	DS_FLAGS_F        = 0x1 << DS_FLAGS_F_LOCATION, /* First packet */
	DS_FLAGS_M        = 0x1 << DS_FLAGS_M_LOCATION  /* More packets coming */
} DS_FLAGS_t;

/* Sends a standard datagram (with data) to the specified server. Sorry for all the parameters! :) */
void ds_send_datagram(int s, DS_MSG_TYPE_t msg_type, DS_FLAGS_t flags, uint16_t DGM_ID, uint16_t packet_offset, char *sourcename, NAME_TYPE_t sourcename_type, char *sourceip, uint16_t sourceport, char *destinationname, NAME_TYPE_t destinationname_type, char *destinationip, uint8_t *data, uint16_t datalength);

/* Sends a NBDD query to look up a name. This is untested, since I don't even know what a NBDD is. */
void ds_send_query(int s, DS_FLAGS_t flags, uint16_t DGM_ID, char *sourceip, uint16_t sourceport, char *destinationip, char *lookupname, NAME_TYPE_t lookupname_type);




#endif
