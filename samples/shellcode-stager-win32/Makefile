# Makefile
# By Ron Bowes
# Created February, 2010
#
# (See LICENSE.txt)
#

CC=gcc
CFLAGS=-Wall -g

all: dnscat-stager-win32-test.out dnscat-stager-win32-test.h dnscat-stager-win32-msf.rb
#	@echo Compile should be complete

dnscat-stager-win32-test.out: dnscat-shell-test.h ../shellcode-test/dnscat-shell-test.c
	@echo "Compiling the test stager program..."
	${CC} ${CFLAGS} -o ./dnscat-stager-test -I. ../shellcode-test/dnscat-shell-test.c

dnscat-shell-test.h: dnscat-stager-win32-test.h
	@ln -s ./dnscat-stager-win32-test.h ./dnscat-shell-test.h

dnscat-stager-win32-test.asm: dnscat-stager-win32.asm
	@echo "Generating 'test' stager shellcode"
	@bash -c "cat dnscat-stager-win32.asm | grep -v REPLACEMSF | sed \"s/RANDOM/$$RANDOM/\" > dnscat-stager-win32-test.asm"

dnscat-stager-win32-test: dnscat-stager-win32-test.asm
	@echo "Assembling 'test' stager"
	@nasm dnscat-stager-win32-test.asm

dnscat-stager-win32-test.h: dnscat-stager-win32-test
	@echo "Converting 'test' stager into a .h file"
	@echo 'char shellcode[] = ' > dnscat-stager-win32-test.h
	@hexdump -C dnscat-stager-win32-test | cut -b10- | sed 's/  / /' | sed 's/  .*$$//' | sed 's/ /\\x/g' | sed 's/^/\t"/' | sed 's/$$/"/' | grep -v '""' >> dnscat-stager-win32-test.h
	@echo ';' >> dnscat-stager-win32-test.h

dnscat-stager-win32-msf.asm: dnscat-stager-win32.asm
	@echo "Generating 'msf' stager shellcode"
	@cat dnscat-stager-win32.asm | grep -v REPLACETEST > dnscat-stager-win32-msf.asm

dnscat-stager-win32-msf: dnscat-stager-win32-msf.asm
	@echo "Assembling 'msf' stager"
	@nasm dnscat-stager-win32-msf.asm
	@wc -c dnscat-stager-win32-msf

dnscat-stager-win32-msf.rb: dnscat-stager-win32-msf
	@echo "Converting 'msf' stager into a .rb file"
	@hexdump -C dnscat-stager-win32-test | cut -b10- | sed 's/  / /' | sed 's/  .*$$//' | sed 's/ /\\x/g' | sed 's/^/\t"/' | sed 's/$$/" +/' | grep -v '""' > dnscat-stager-win32-msf.rb

clean:
	rm -f dnscat-stager dnscat-stager-win32 dnscat-stager-test dnscat-stager-test.exe*
	rm -f dnscat-stager-win32-msf dnscat-stager-win32-msf.asm dnscat-stager-win32-msf.rb
	rm -f dnscat-stager-win32-test dnscat-stager-win32-test.asm dnscat-stager-win32-test.h
	rm -f dnscat-shell-test.h
	rm -f generate_hash generate_hash.exe*

