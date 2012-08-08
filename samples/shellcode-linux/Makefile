# Makefile
# By Ron Bowes
# Created February, 2010
#
# (See LICENSE.txt)
#

CC=gcc
CFLAGS=-Wall -g

all: dnscat-shell-test
#	@echo Compile should be complete

dnscat-shell-test: dnscat-shell-test.h ../shellcode-test/dnscat-shell-test.c
	@echo "Compiling the test program..."
	${CC} ${CFLAGS} -o ./dnscat-shell-test -I. ../shellcode-test/dnscat-shell-test.c

dnscat-shell-test.h: dnscat-shell-linux
	@echo "Creating dnscat-shell-test.h with shellcode..."
	@echo 'char shellcode[] = ' > dnscat-shell-test.h
	@hexdump -C dnscat-shell-linux | cut -b10- | sed 's/  / /' | sed 's/  .*$$//' | sed 's/ /\\x/g' | sed 's/^/\t"/' | sed 's/$$/"/' | grep -v '""' >> dnscat-shell-test.h
	@echo ';' >> dnscat-shell-test.h

dnscat-shell-linux: dnscat-shell-linux.asm
	@echo "Assembling dnscat-shell-linux.asm..."
	@nasm dnscat-shell-linux.asm
	@wc -c dnscat-shell-linux

clean:
	rm -f dnscat-shell dnscat-shell-linux dnscat-shell-test dnscat-shell-test.exe*
	rm -f dnscat-shell-test.h

