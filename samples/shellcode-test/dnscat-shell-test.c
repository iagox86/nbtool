#include <stdio.h>
#include <stdlib.h>

#include "dnscat-shell-test.h"

int main(int argc, char **argv)
{
	printf("%d bytes of shellcode\n", (int)sizeof(shellcode));

	if(argc != 1)
		exit(0);

	asm("call *%0\n" : :"r"(shellcode));

	return 0;
}

