/* genhash.c
 * By Ron
 * Created August 31, 2008
 *
 * (See LICENSE.txt)
 *
 * Simple module to hash passwords.
 *
 * Doesn't compile on Windows right now due to the dependency on OpenSSL.
 */

#include <stdio.h>
#include <stdlib.h>

#include "crypto.h"

int main(int argc, char *argv[])
{
	size_t i;

	uint8_t lm[16];
	uint8_t ntlm[16];

	if(argc == 1)
	{
		printf("Usage: %s <password>\n\n", argv[0]);
		exit(1);
	}

	lm_create_hash(argv[1], lm);
	ntlm_create_hash(argv[1], ntlm);

	for(i = 0; i < 16; i++)
		printf("%02x", lm[i]);
	printf(":");
	for(i = 0; i < 16; i++)
		printf("%02x", ntlm[i]);
	printf("\n\n");

	return 0;
}

