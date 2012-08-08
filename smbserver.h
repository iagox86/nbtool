/* smbserver.h
 * By Ron Bowes
 * Created August 26, 2008
 *
 * (See LICENSE.txt)
 *
 * Tasks related to SMB servers.
 *
 * Not currently being used. I don't think it worked.
 */

#ifndef __SMBSERVER_H__
#define __SMBSERVER_H__

#include "types.h"


typedef struct
{
	NBBOOL extended_security;
	NBBOOL error_nt;
	NBBOOL unicode;
} SMB_SETTINGS_t;


#endif
