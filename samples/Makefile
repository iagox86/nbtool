# Makefile
# By Ron Bowes
# Created March, 2010
#
# (See LICENSE.txt)
#

all:
	-cd shellcode-linux && make
	-cd shellcode-win32 && make
	-cd shellcode-stager-win32 && make
	-cd jsdnscat && make

clean:
	-cd shellcode-linux && make clean
	-cd shellcode-win32 && make clean
	-cd shellcode-stager-win32 && make clean
	-cd jsdnscat && make clean

