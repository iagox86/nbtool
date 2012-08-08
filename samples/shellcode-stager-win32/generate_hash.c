//written by Rick2600 rick2600s[at]gmail{dot}com
//tweaked just a little by Peter Van Eeckhoutte
//http://www.corelan.be:8800
//This script will produce a hash for a given function name
//If no arguments are given, a list with some common function
//names and their corresponding hashes will be displayed

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <arpa/inet.h>

long rol(long value, int n);
long ror(long value, int n);
int calculate_hash(char *function_name);
void banner();

int main(int argc, char *argv[])
{
    banner();
    if (argc < 2)
    {
        int i=0;
        char *func[] =
        {
"VirtualAlloc",   /* kernel32.dll */
"LoadLibraryA",
"DnsQuery_A",    /* dnsapi.dll */
0x0
        };
       printf("HASH\t\t\tFUNCTION\n----\t\t\t--------\n");
        while ( *func )
        {
              printf("0x%X\t\t%s\n", calculate_hash(*func), *func);
              i++;
              *func = func[i];

        }
    }
    else
    {
       char *manfunc[] = {argv[1]};
       printf("HASH\t\t\tFUNCTION\n----\t\t\t--------\n");
       printf("0x%X\t\t%s\n", calculate_hash(*manfunc), *manfunc);
    }

    return 0;
}

int calculate_hash( char *function_name )
{
    int aux = 0;
    unsigned long hash = 0;

    while (*function_name)
    {
          hash = ror(hash, 13);
          hash += *function_name;
          function_name++;

    }

    while ( hash > 0 )
    {
          aux = aux << 8;
          aux += (hash & 0x00000FF);
          hash = hash >> 8;

    }

    hash = aux;
    return htonl(hash);
}

long rol(long value, int n)
{
   __asm__ ("rol %%cl, %%eax"
        : "=a" (value)
        : "a" (value), "c" (n)
    );

    return value;
}

long ror(long value, int n)
{
   __asm__ ("ror %%cl, %%eax"
        : "=a" (value)
        : "a" (value), "c" (n)
    );

    return value;
}

void banner()
{
    printf("----------------------------------------------\n");
    printf("     --==[ GenerateHash v1.0 ]==--\n");
    printf(" written by rick2600 and Peter Van Eeckhoutte\n");
    printf("      http://www.corelan.be:8800\n");
    printf("----------------------------------------------\n");
}

