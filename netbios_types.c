/* netbios_types.c
 * By Ron
 * Created January, 2010
 *
 * (See LICENSE.txt)
 *
 */

#include <stdio.h>
#include <string.h>

#include "netbios_types.h"

char *name_type_to_string(NAME_TYPE_t name_type)
{
	switch(name_type)
	{
		case NAME_WORKSTATION:
			return "workstation";
		case NAME_MESSENGER:
			return "messenger";
		case NAME_SERVER:
			return "server";
		case NAME_DOMAIN_MASTER:
			return "master";
		case NAME_ELECTION:
			return "election";
		default:
			return "unknown";
	}
}

char *flags_to_error(uint16_t flags)
{
    char *ret = "success";
    switch(flags & FLAGS_RCODE_MASK)
    {
        case FLAGS_RCODE_POS_RSP: ret = "success";               break;
        case FLAGS_RCODE_FMT_ERR: ret = "error: format error";   break;
        case FLAGS_RCODE_SRV_ERR: ret = "error: server failure"; break;
        case FLAGS_RCODE_NAM_ERR: ret = "error: name not found"; break;
        case FLAGS_RCODE_IMP_ERR: ret = "error: unsupported";    break;
        case FLAGS_RCODE_RFS_ERR: ret = "error: refused";        break;
        case FLAGS_RCODE_ACT_ERR: ret = "error: active";         break;
        case FLAGS_RCODE_CFT_ERR: ret = "error: conflict";       break;
        default:                  ret = "error: ???";            break;
    }
    return ret;
}

char *flags_to_op(uint16_t flags)
{
	char *ret = "unknown";
	switch(flags & FLAGS_OPCODE_MASK)
	{
		case FLAGS_OPCODE_QUERY:             ret = "query";          break;
		case FLAGS_OPCODE_NAME_REGISTRATION: ret = "registration";   break;
		case FLAGS_OPCODE_NAME_RELEASE:      ret = "release";        break;
		case FLAGS_OPCODE_WACK:              ret = "wack";           break;
		case FLAGS_OPCODE_NAME_REFRESH:      ret = "refresh";        break;
		case FLAGS_OPCODE_NAME_REFRESH_ALT:  ret = "refresh (alt)";  break;
	}

	return ret;
}

void NB_decode_name(char encoded[32], char decoded[16], uint8_t *type)
{
	uint8_t i;

	memset(decoded, 0, 16);

	/* Decode the question. */
	for(i = 0; i < 15; i++)
		decoded[i] = ((encoded[i << 1] - 'A') << 4) | (encoded[(i << 1) + 1] - 'A');

	/* Decode the type. */
	*type = ((encoded[30] - 'A') << 4) | (encoded[31] - 'A');
}

void NB_print_question(question_t question, uint16_t flags)
{
	char    decoded[16];
	uint8_t type;

	NB_decode_name(question.name, decoded, &type);

	printf("QUESTION %s: (NB:%s<%02x|%s>)\n", flags_to_op(flags), decoded, type, name_type_to_string(type));
}

void NBSTAT_print_question(question_t question, uint16_t flags)
{
	char    decoded[16];
	uint8_t type;

	NB_decode_name(question.name, decoded, &type);

	printf("QUESTION %s: (NBSTAT:%s<%02x|%s>)\n", flags_to_op(flags), decoded, type, name_type_to_string(type));
}

void NB_print_answer(answer_t answer, uint16_t flags)
{
	char    decoded[16];
	uint8_t type;

	NB_decode_name(answer.question, decoded, &type);

	printf("ANSWER query: (NB:%s<%02x|%s>): %s, IP: %s, TTL: %ds\n", decoded, type, name_type_to_string(type), flags_to_error(flags), answer.answer->NB.address, answer.ttl);
}

void NBSTAT_print_answer(answer_t full_answer, uint16_t flags)
{
	/* Get the answer. */
	NBSTAT_answer_t answer = full_answer.answer->NBSTAT;

	/* Get the question, and make room for the decoded question. */
	char    decoded[16];
	uint8_t type;
	uint8_t j;

	NB_decode_name(full_answer.question, decoded, &type);

	printf("NBSTAT response: Received %d names; %s (MAC: %02x:%02x:%02x:%02x:%02x:%02x)\n", answer.name_count, flags_to_error(flags), answer.stats[0], answer.stats[1], answer.stats[2], answer.stats[3], answer.stats[4], answer.stats[5]);

	for(j = 0; j < answer.name_count; j++)
	{
		printf("ANSWER: (NBSTAT:%s<%02x|%s>): %s<%02x> ", decoded, type, name_type_to_string(type), answer.names[j].name, answer.names[j].name_type);
		if(answer.names[j].name_flags & NAME_FLAGS_G)
			printf("<group>");
		else
			printf("<unique>");

		if(answer.names[j].name_flags & NAME_FLAGS_DRG)
			printf("<deregister>");
		if(answer.names[j].name_flags & NAME_FLAGS_CNF)
			printf("<conflict>");
		if(answer.names[j].name_flags & NAME_FLAGS_ACT)
			printf("<active>");
		if(answer.names[j].name_flags & NAME_FLAGS_PRM)
			printf("<permanent>");

		printf(" (0x%04x)\n", answer.names[j].name_flags);
	}
}

