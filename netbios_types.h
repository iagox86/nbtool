/* netbios_types.h
 * By Ron
 * Created January, 2010
 *
 * (See LICENSE.txt)
 *
 * Defines datatypes for NetBIOS, and lets programs convert certain types
 * into strings.
 */

#ifndef __NETBIOS_TYPES_H__
#define __NETBIOS_TYPES_H__

#include "dns.h"
#include "types.h"

#define NAME_PADDING_DEFAULT ' '   /* Most names are padded with spaces. */
#define NAME_PADDING_WILDCARD '\0' /* Some names are padded with nulls. */

typedef enum
{
	NAME_WORKSTATION   = 0x00,
	NAME_MESSENGER     = 0x03,
	NAME_SERVER        = 0x20,
	NAME_DOMAIN_MASTER = 0x1B,
	NAME_ELECTION      = 0x1E
} NAME_TYPE_t;
char *name_type_to_string(NAME_TYPE_t name_type);

#define FLAGS_R_MASK        0x8000
#define FLAGS_OPCODE_MASK   0x7800
#define FLAGS_NM_FLAGS_MASK 0x07F0
#define FLAGS_RCODE_MASK    0x000F

#define FLAGS_R_LOCATION      15
#define FLAGS_OPCODE_LOCATION 11
#define FLAGS_AA_LOCATION     10
#define FLAGS_TR_LOCATION      9
#define FLAGS_RD_LOCATION      8
#define FLAGS_RA_LOCATION      7
#define FLAGS_B_LOCATION       4
#define FLAGS_RCODE_LOCATION   0


typedef enum
{
	FLAGS_R_REQUEST  = 0<<FLAGS_R_LOCATION,
	FLAGS_R_RESPONSE = 1<<FLAGS_R_LOCATION,

	FLAGS_OPCODE_QUERY             = 0x00<<FLAGS_OPCODE_LOCATION,
	FLAGS_OPCODE_NAME_REGISTRATION = 0x05<<FLAGS_OPCODE_LOCATION,
	FLAGS_OPCODE_NAME_RELEASE      = 0x06<<FLAGS_OPCODE_LOCATION,
	FLAGS_OPCODE_WACK              = 0x07<<FLAGS_OPCODE_LOCATION, /* Wait for acknowledgement */
	FLAGS_OPCODE_NAME_REFRESH      = 0x08<<FLAGS_OPCODE_LOCATION,
	FLAGS_OPCODE_NAME_REFRESH_ALT  = 0x09<<FLAGS_OPCODE_LOCATION,

	FLAGS_NM_AA = 1<<FLAGS_AA_LOCATION,
	FLAGS_NM_TR = 1<<FLAGS_TR_LOCATION,
	FLAGS_NM_RD = 1<<FLAGS_RD_LOCATION, /* Recursion denied */
	FLAGS_NM_RA = 1<<FLAGS_RA_LOCATION,
	FLAGS_NM_B  = 1<<FLAGS_B_LOCATION,  /* Broadcast */

	FLAGS_RCODE_POS_RSP = 0x0000,  /* Positive Response    */
	FLAGS_RCODE_FMT_ERR = 0x0001,  /* Format Error         */
	FLAGS_RCODE_SRV_ERR = 0x0002,  /* Server failure       */
	FLAGS_RCODE_NAM_ERR = 0x0003,  /* Name Not Found       */
	FLAGS_RCODE_IMP_ERR = 0x0004,  /* Unsupported request  */
	FLAGS_RCODE_RFS_ERR = 0x0005,  /* Refused              */
	FLAGS_RCODE_ACT_ERR = 0x0006,  /* Active error         */
	FLAGS_RCODE_CFT_ERR = 0x0007   /* Name in conflict     */
} FLAGS_t;

typedef enum
{
	NAME_FLAGS_G   = 1 << 15, /* Group (opposite: unique). */
	NAME_FLAGS_DRG = 1 << 12, /* Deregister */
	NAME_FLAGS_CNF = 1 << 11, /* Conflict */
	NAME_FLAGS_ACT = 1 << 10, /* Active */
	NAME_FLAGS_PRM = 1 <<  9  /* Permanent */
} NAME_FLAGS_t;

char *flags_to_error(uint16_t flags);
char *flags_to_op(uint16_t flags);

void NB_decode_name(char encoded[32], char decoded[16], uint8_t *type);
void NB_print_question(question_t question, uint16_t flags);
void NBSTAT_print_question(question_t question, uint16_t flags);
void NB_print_answer(answer_t full_answer, uint16_t flags);
void NBSTAT_print_answer(answer_t full_answer, uint16_t flags);

#endif

