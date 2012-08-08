/* smbsession.h
 * By Ron Bowes
 * Created August, 2008
 *
 * Defines the NetBIOS Session header, used for SMB-over-NetBIOS requests
 * (TCP port 139).
 *
 * Not really used anywhere, yet.
 */

#ifndef __SMBSESSION_H__
#define __SMBSESSION_H__

#include "types.h"

/* Datagram packet header
 * --------------------------------------------------
 * |  15 14 13 12 11 10 9  8  7  6  5  4  3  2  1  0 |
 * |          TYPE          |      RESERVED      | E |
 * |                     LENGTH                      |
 * --------------------------------------------------
 */


typedef enum
{
	SESSION_MESSAGE = 0x00,
	SESSION_REQUEST = 0x81,
	SESSION_POSITIVE_RESPONSE = 0x82,
	SESSION_NEGATIVE_RESPONSE = 0x83,
	SESSION_RETARGET_RESPONSE = 0x84,
	SESSION_KEEPALIVE = 0x85
} SESSION_TYPE_t;





#endif
