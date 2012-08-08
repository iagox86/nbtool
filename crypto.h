/* crypto.h
 * By Ron Bowes
 * Created August, 2008
 *
 * (See LICENSE.txt)
 *
 * This module calculates the various important values for LM, NTLM, LMv2, and NTLMv2 hashes.
 * Right now, it depends on OpenSSL and therefore doesn't compile on Windows (I really don't
 * want to have a dependency on OpenSSL), so I'm not using it for anything.
 */

#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include "types.h"

void lm_create_hash(const char *password, uint8_t result[16]);
void lm_create_response(const uint8_t lanman[16], const uint8_t challenge[8], uint8_t result[24]);
void ntlm_create_hash(const char *password, uint8_t result[16]);
void ntlm_create_response(const uint8_t ntlm[16], const uint8_t challenge[8], uint8_t result[24]);
void lmv2_create_response(const uint8_t ntlm[16],   const char *username, const char *domain, const uint8_t challenge[8], uint8_t *result, uint8_t *result_size);
void ntlmv2_create_response(const uint8_t ntlm[16], const char *username, const char *domain, const uint8_t challenge[8], uint8_t *result, uint8_t *result_size);

void lm_create_session_key(const uint8_t lanman[16], uint8_t result[16]);
void ntlm_create_session_key(const uint8_t ntlm[16], uint8_t result[16]);

/* Note: These two functions don't work, and simply die with an error. */
void lmv2_create_session_key(const uint8_t ntlm[16], const char *username, const char *domain, const uint8_t lmv2_response[16], uint8_t result[24]);
void ntlmv2_create_session_key(const uint8_t ntlm[16], const char *username, const char *domain, const uint8_t ntlmv2_response[16], uint8_t result[24]);

void calculate_signature(const uint8_t *data, size_t length, const uint8_t mac_key[40], uint8_t signature[8]);

/* Attempts to convert a string to one or two hashes. It will attempt:
 * - A single hash (32 characters)
 * - Two hashes, concatinated (64 characters)
 * - Two hashes, with a separator (65 characters)
 *
 * Return value is the number of hashes generated (0 for error, 1 or 2 otherwise). */
int string_to_hash(const char *string, uint8_t first[16], uint8_t second[16]);

#endif
