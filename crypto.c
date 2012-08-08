/* crypto.c
 * By Ron
 * Created August, 2008
 *
 * (See LICENSE.txt)
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/des.h>
#include <openssl/hmac.h>
#include <openssl/md4.h>
#include <openssl/md5.h>

#include "memory.h"
#include "types.h"

#include "crypto.h"


static void password_to_key(const uint8_t password[7], uint8_t key[8])
{
	/* make room for parity bits */
	key[0] =                        (password[0] >> 0);
	key[1] = ((password[0]) << 7) | (password[1] >> 1);
	key[2] = ((password[1]) << 6) | (password[2] >> 2);
	key[3] = ((password[2]) << 5) | (password[3] >> 3);
	key[4] = ((password[3]) << 4) | (password[4] >> 4);
	key[5] = ((password[4]) << 3) | (password[5] >> 5);
	key[6] = ((password[5]) << 2) | (password[6] >> 6);
	key[7] = ((password[6]) << 1);
}

static void des(const uint8_t password[7], const uint8_t data[8], uint8_t result[])
{
	DES_cblock key;
	DES_key_schedule schedule;

	password_to_key(password, key);

	DES_set_odd_parity(&key);
	DES_set_key_unchecked(&key, &schedule);
	DES_ecb_encrypt((DES_cblock*)data, (DES_cblock*)result, &schedule, DES_ENCRYPT);
}

void lm_create_hash(const char *password, uint8_t result[16])
{
	size_t           i;
	uint8_t          password1[7];
	uint8_t          password2[7];
	uint8_t          kgs[] = "KGS!@#$%";
	uint8_t          hash1[8];
	uint8_t          hash2[8];

	/* Initialize passwords to NULLs. */
	memset(password1, 0, 7);
	memset(password2, 0, 7);

	/* Copy passwords over, convert to uppercase, they're automatically padded with NULLs. */
	for(i = 0; i < 7; i++)
	{
		if(i < strlen(password))
			password1[i] = toupper(password[i]);
		if(i + 7 < strlen(password))
			password2[i] = toupper(password[i + 7]);
	}

	/* Do the encryption. */
	des(password1, kgs, hash1);
	des(password2, kgs, hash2);

	/* Copy the result to the return parameter. */
	memcpy(result + 0, hash1, 8);
	memcpy(result + 8, hash2, 8);
}

void lm_create_response(const uint8_t lanman[16], const uint8_t challenge[8], uint8_t result[24])
{
	size_t i;

	uint8_t password1[7];
	uint8_t password2[7];
	uint8_t password3[7];

	uint8_t hash1[8];
	uint8_t hash2[8];
	uint8_t hash3[8];

	/* Initialize passwords. */
	memset(password1, 0, 7);
	memset(password2, 0, 7);
	memset(password3, 0, 7);

	/* Copy data over. */
	for(i = 0; i < 7; i++)
	{
		password1[i] = lanman[i];
		password2[i] = lanman[i + 7];
		password3[i] = (i + 14 < 16) ? lanman[i + 14] : 0;
	}

	/* do the encryption. */
	des(password1, challenge, hash1);
	des(password2, challenge, hash2);
	des(password3, challenge, hash3);

	/* Copy the result to the return parameter. */
	memcpy(result + 0,  hash1, 8);
	memcpy(result + 8,  hash2, 8);
	memcpy(result + 16, hash3, 8);
}

void ntlm_create_hash(const char *password, uint8_t result[16])
{
	char *unicode = unicode_alloc(password);
	MD4_CTX ntlm;

	if(!unicode)
		DIE_MEM();

	MD4_Init(&ntlm);
	MD4_Update(&ntlm, unicode, strlen(password) * 2);
	MD4_Final(result, &ntlm);
}

void ntlm_create_response(const uint8_t ntlm[16], const uint8_t challenge[8], uint8_t result[24])
{
	lm_create_response(ntlm, challenge, result);
}

void ntlmv2_create_hash(const uint8_t ntlm[16], const char *username, const char *domain, uint8_t hash[16])
{
	/* Convert username to unicode. */
	size_t username_length = strlen(username);
	size_t domain_length   = strlen(domain);
	char    *combined;
	uint8_t *combined_unicode;

	/* Probably shouldn't do this, but this is all prototype so eh? */
	if(username_length > 256 || domain_length > 256)
		DIE("username or domain too long.");

	/* Combine the username and domain into one string. */
	combined = safe_malloc(username_length + domain_length + 1);
	memset(combined, 0, username_length + domain_length + 1);

	memcpy(combined,                   username, username_length);
	memcpy(combined + username_length, domain,   domain_length);

	/* Convert to Unicode. */
	combined_unicode = (uint8_t*)unicode_alloc_upper(combined);
	if(!combined_unicode)
		DIE_MEM();

	/* Perform the Hmac-MD5. */
	HMAC(EVP_md5(), ntlm, 16, combined_unicode, (username_length + domain_length) * 2, hash, NULL);

	safe_free(combined_unicode);
	safe_free(combined);
}

void lmv2_create_response(const uint8_t ntlm[16], const char *username, const char *domain, const uint8_t challenge[8], uint8_t *result, uint8_t *result_size)
{
	ntlmv2_create_response(ntlm, username, domain, challenge, result, result_size);
}

void ntlmv2_create_response(const uint8_t ntlm[16], const char *username, const char *domain, const uint8_t challenge[8], uint8_t *result, uint8_t *result_size)
{
	size_t  i;
	uint8_t v2hash[16];
	uint8_t *data;

	uint8_t blip[8];
	uint8_t *blob;
	uint8_t blob_length;


	/* Create the 'blip'. TODO: Do I care if this is random? */
	for(i = 0; i < 8; i++)
		blip[i] = i;

	if(*result_size < 24)
	{
		/* Result can't be less than 24 bytes. */
		DIE("Result size is too low!");
	}
	else if(*result_size == 24)
	{
		/* If they're looking for 24 bytes, then it's just the raw blob. */
		blob = safe_malloc(8);
		memcpy(blob, blip, 8);
		blob_length = 8;
	}
	else
	{
		blob = safe_malloc(24);
		for(i = 0; i < 24; i++)
			blob[i] = i;
		blob_length = 24;
	}

	/* Allocate room enough for the server challenge and the client blob. */
	data = safe_malloc(8 + blob_length);

	/* Copy the challenge into the memory. */
	memcpy(data, challenge, 8);
	/* Copy the blob into the memory. */
	memcpy(data + 8, blob, blob_length);

	/* Get the v2 hash. */
	ntlmv2_create_hash(ntlm, username, domain, v2hash);

	/* Generate the v2 response. */
	HMAC(EVP_md5(), v2hash, 16, data, 8 + blob_length, result, NULL);

	/* Copy the blob onto the end of the v2 response. */
	memcpy(result + 16, blob, blob_length);

	/* Store the result size. */
	*result_size = blob_length + 16;

	/* Finally, free up some memory. */
	safe_free(data);
	safe_free(blob);
}

void lm_create_session_key(const uint8_t lanman[16], uint8_t result[16])
{
	/* LM key is the first 8 bytes of the LM hash, followed by 8 NULL bytes. Seriously. */
	memcpy(result, lanman, 8);
	memset(result + 8, 0, 9);
}

void ntlm_create_session_key(const uint8_t ntlm[16], uint8_t result[16])
{
	/* NTLM key is an MD4 of the ntlm hash. */
	MD4_CTX session_key;
	MD4_Init(&session_key);
	MD4_Update(&session_key, ntlm, 16);
	MD4_Final(result, &session_key);
}

void lmv2_create_session_key(const uint8_t ntlm[16], const char *username, const char *domain, const uint8_t lmv2_response[16], uint8_t result[16])
{
	uint8_t v2hash[16];

	ntlmv2_create_hash(ntlm, username, domain, v2hash);
	HMAC(EVP_md5(), v2hash, 16, lmv2_response, 16, result, NULL);

	DIE("This function doesn't work.");
}
void ntlmv2_create_session_key(const uint8_t ntlm[16], const char *username, const char *domain, const uint8_t ntlmv2_response[16], uint8_t result[16])
{
	lmv2_create_session_key(ntlm, username, domain, ntlmv2_response, result);

	DIE("This function doesn't work.");
}

/* mac_key = concat(session_key, response_hash);
 * signature = first 8 bytes of MD5(mac_key, smb_data);
 */
void calculate_signature(const uint8_t *data, size_t length, const uint8_t mac_key[40], uint8_t signature[8])
{
	MD5_CTX md5;
	uint8_t full_result[16];

	MD5_Init(&md5);
	MD5_Update(&md5, mac_key, 40);
	MD5_Update(&md5, data, length);
	MD5_Final(full_result, &md5);

	memcpy(signature, full_result, 8);
}


/* Converts a single character ('0' = '9', 'a' - 'f', and 'A' - 'F') to its equivalent.
 * Returns -1 for error. */
static int character_to_hex(char ch)
{
	if(ch >= '0' && ch <= '9')
		return ch - '0';

	if(ch >= 'A' && ch <= 'F')
		return ch - 'A' + 10;

	if(ch >= 'a' && ch <= 'f')
		return ch - 'a' + 10;

	return -1;
}

/* String has to be 32 bytes, hash has to be 16.
 *
 * Returns TRUE on success. */
static NBBOOL single_string_to_hash(const char *string, uint8_t hash[16])
{
	size_t i;

	for(i = 0; i < 32; i += 2)
	{
		int upper = character_to_hex(string[i]);
		int lower = character_to_hex(string[i + 1]);
		if(upper < 0 || lower < 0)
			return FALSE;

		hash[i / 2] = (upper << 4) | lower;
	}

	return TRUE;
}

int string_to_hash(const char *string, uint8_t first[16], uint8_t second[16])
{
	memset(first,  0, 16);
	memset(second, 0, 16);

	/* Single hash. */
	if(strlen(string) == 32)
	{
		if(single_string_to_hash(string, first))
			return 1;
		return 0;
	}

	/* Two hashes, with no separators. */
	if(strlen(string) == 64)
	{
		if(single_string_to_hash(string, first) && single_string_to_hash(string + 32, second))
			return 2;
		return 0;
	}

	/* Two hashes, with a separator. */
	if(strlen(string) == 65)
	{
		if(single_string_to_hash(string, first) && single_string_to_hash(string + 33, second))
			return 2;
		return 0;
	}

	return 0;
}

#if 0
/* Test data:
 * Challenge: 7b9cb5458f2631cd
 * Password: iagotest1
 * LM:         d702a1d01b6bc24127bcbf149915a329
 * NTLM:       bce0ce40de0d1d9cd08a4e6066a14b92
 * LM c/r:     5c8b5515cd84996359cef9c7c40832390831aa88933d2198
 * NTLMv1 c/r: 07648d36df458762fa4178f548254c6dd337607cc92e8e19
 */

static void print_hex(char *prefix, uint8_t *hex, int length)
{
	size_t i;

	printf("%s", prefix);
	for(i = 0; i < length; i++)
		printf("%02x", hex[i]);
	printf("\n");
}

int main(int argc, char *argv[])
{
	uint8_t  lanman[16];
	uint8_t  ntlm[16];
	uint8_t ntlmv2[16];
	uint8_t  lanman_response[24];
	uint8_t  ntlm_response[24];
	uint8_t ntlmv2_response[24];
	uint8_t ntlmv2_length = 24;
	uint8_t *challenge = (uint8_t *)"\x7b\x9c\xb5\x45\x8f\x26\x31\xcd";
	char    *password  = "iagotest1";

/*	for(i = 1; i < argc; i++)
	{
		lm_create_hash(argv[i], lanman);
		ntlm_create_hash(argv[i], ntlm);

		printf("test%d:%d:", i, 1000+i);
		for(j = 0; j < 16; j++)
			printf("%02x", lanman[j]);
		printf(":");
		for(j = 0; j < 16; j++)
			printf("%02x", ntlm[j]);
		printf(":::\n");
	}
*/

	lm_create_hash(password, lanman);
	lm_create_response(lanman, challenge, lanman_response);

	ntlm_create_hash("iagotest1", ntlm);
	ntlm_create_response(ntlm, challenge, ntlm_response);

	ntlmv2_create_hash(ntlm, "ron", "", ntlmv2);
	ntlmv2_create_response(ntlm, "ron", "", challenge, ntlmv2_response, &ntlmv2_length);

 	printf("+LM:         d702a1d01b6bc24127bcbf149915a329\n");
	print_hex("LM:          ", lanman,          16);
	printf("\n");

	printf("=NTLM:       bce0ce40de0d1d9cd08a4e6066a14b92\n");
	print_hex("NTLM:        ", ntlm,            16);
	printf("\n");

	print_hex("NTLMv2:      ", ntlmv2,            16);
	printf("\n");

	printf("+LM c/r:     5c8b5515cd84996359cef9c7c40832390831aa88933d2198\n");
	print_hex("LM c/r:      ", lanman_response, 24);
	printf("\n");

	printf("+NTLMv1 c/r: 07648d36df458762fa4178f548254c6dd337607cc92e8e19\n");
	print_hex("NTLMv1 c/r:  ", ntlm_response,   24);
	printf("\n");

	print_hex("NTLMv2 c/r:  ", ntlmv2_response,   24);
	printf("\n");

	printf("\n");
#if 0
	printf("testing string_to_hash...\n");
	printf("%d hashes:\n", string_to_hash("d702a1d01b6bc24127bcbf149915a329", test1, test2));
	print_hex("Test1: ", test1, 16);
	print_hex("Test2: ", test2, 16);
	printf("\n");

	printf("testing string_to_hash...\n");
	printf("%d hashes:\n", string_to_hash("bce0ce40de0d1d9cd08a4e6066a14b92", test1, test2));
	print_hex("Test1: ", test1, 16);
	print_hex("Test2: ", test2, 16);
	printf("\n");

	printf("testing string_to_hash...\n");
	printf("%d hashes:\n", string_to_hash("d702a1d01b6bc24127bcbf149915a329bce0ce40de0d1d9cd08a4e6066a14b92", test1, test2));
	print_hex("Test1: ", test1, 16);
	print_hex("Test2: ", test2, 16);
	printf("\n");

	printf("testing string_to_hash...\n");
	printf("%d hashes:\n", string_to_hash("d702a1d01b6bc24127bcbf149915a329:bce0ce40de0d1d9cd08a4e6066a14b92", test1, test2));
	print_hex("Test1: ", test1, 16);
	print_hex("Test2: ", test2, 16);
	printf("\n");
#endif

	return 0;
}

#endif
