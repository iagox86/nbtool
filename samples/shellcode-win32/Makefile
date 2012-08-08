# Makefile
# By Ron Bowes
# Created February, 2010
#
# (See LICENSE.txt)
#

CC=gcc
CFLAGS=-Wall -g

all: dnscat-shell-win32-test.h dnscat-shell-win32-msf.rb dnscat-shell-win32-test.out
#	@echo Compile should be complete

# The test program that can be run independantly
dnscat-shell-win32-test.out: dnscat-shell-test.h ../shellcode-test/dnscat-shell-test.c
	@echo "Compiling the test program..."
	${CC} ${CFLAGS} -o ./dnscat-shell-win32-test.out -I. -DDNSCATFILE=dnscat-shell-win32-test.h ../shellcode-test/dnscat-shell-test.c

dnscat-shell-test.h: dnscat-shell-win32-test.h
	@ln -s ./dnscat-shell-win32-test.h dnscat-shell-test.h

# Generate the 'test' asm file (based on the core)
dnscat-shell-win32-test.asm: dnscat-shell-win32.asm
	@echo "Creating 'test' shellcode"
	@cat dnscat-shell-win32.asm | grep -v "REPLACEMSF" > dnscat-shell-win32-test.asm

# Assemble the 'test' .asm file
dnscat-shell-win32-test: dnscat-shell-win32-test.asm
	@echo "Assembling 'test' shellcode"
	@nasm dnscat-shell-win32-test.asm

# A .h file that contains the C version of the shellocde
dnscat-shell-win32-test.h: dnscat-shell-win32-test
	@echo "Converting 'test' shellcode into a .h file"
	@echo 'char shellcode[] = ' > dnscat-shell-win32-test.h
	@hexdump -C dnscat-shell-win32-test | cut -b10- | sed 's/  / /' | sed 's/  .*$$//' | sed 's/ /\\x/g' | sed 's/^/\t"/' | sed 's/$$/"/' | grep -v '""' >> dnscat-shell-win32-test.h
	@echo ';' >> dnscat-shell-win32-test.h

# Generate the 'msf' asm file (based on teh core)
dnscat-shell-win32-msf.asm: dnscat-shell-win32.asm
	@echo "Creating 'msf' shellcode"
	@cat dnscat-shell-win32.asm | grep -v "REPLACETEST" > dnscat-shell-win32-msf.asm

# Assemble the 'msf' asm file
dnscat-shell-win32-msf: dnscat-shell-win32-msf.asm
	@echo "Assembling 'msf' shellcode"
	@nasm dnscat-shell-win32-msf.asm
	@wc -c dnscat-shell-win32-msf

# A .h file that contains the ruby version of the shellcode
dnscat-shell-win32-msf.rb: dnscat-shell-win32-msf
	@echo "Converting 'msf' shellcode into a .rb file"
	@hexdump -C dnscat-shell-win32-msf | cut -b10- | sed 's/  / /' | sed 's/  .*$$//' | sed 's/ /\\x/g' | sed 's/^/    "/' | sed 's/$$/"/' | grep -v '""' | sed "s/$$/ +/" > dnscat-shell-win32-msf.rb



clean:
	rm -f dnscat-shell dnscat-shell-win32 dnscat-shell-test dnscat-shell-test.exe* dnscat-shell-win32-test dnscat-shell-msf-test dnscat-shell-win32-test.out
	rm -f dnscat-shell-win32-test dnscat-shell-win32-test.asm
	rm -f dnscat-shell-win32-msf dnscat-shell-win32-msf.asm
	rm -f dnscat-shell-win32-msf.rb
	rm -f dnscat-shell-win32-test.h
	rm -f *.h
	rm -f generate_hash generate_hash.exe*

