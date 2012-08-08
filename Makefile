# Makefile
# By Ron Bowes
# Created August, 2008
#
# (See LICENSE.txt)
#
# Should work for Linux and BSD make. Windows (without Cygwin) should use the .vcproj file in mswin32/. 
#
# 'make ipod' and 'make iphone' will run 'ldid -S' on the files in addition to everything else. 

CC=gcc
COMMON_CFLAGS=-ansi -std=c89
CFLAGS?=-Wall -g #-DTESTMEMORY #-DTEST # Note: -DTESTMEMORY and -DTEST should be removed for final versions
LIBS=
CFLAGS+=$(COMMON_CFLAGS)

all: nbquery nbsniff dnsxss dnslogger dnscat dnstest samples_build
	@echo Compile should be complete

samples_build:
	@echo "Trying to build samples (shellcode, etc) -- don't worry if it fails"
	-cd samples && make

smbclient:
	@echo "Not a valid target anymore!"

iphone: ipod
ipod: all
	@echo "Signing binaries for iPhones/iPods"
	ldid -S nbquery
	ldid -S nbsniff
	ldid -S smbtest
	ldid -S smbserver
	ldid -S dnsxss
	ldid -S dnslogger
	ldid -S dnscat
	ldid -S dnstest

install: all
	mkdir -p /usr/local/bin
	cp nbquery    /usr/local/bin/nbquery
	cp nbsniff    /usr/local/bin/nbsniff
	cp dnsxss     /usr/local/bin/dnsxss
	cp dnslogger  /usr/local/bin/dnslogger
	cp dnscat     /usr/local/bin/dnscat 
	cp dnstest    /usr/local/bin/dnstest
	chown root.root /usr/local/bin/nbquery
	chown root.root /usr/local/bin/nbsniff
	chown root.root /usr/local/bin/dnsxss
	chown root.root /usr/local/bin/dnslogger
	chown root.root /usr/local/bin/dnscat
	chown root.root /usr/local/bin/dnstest

remove:
	rm -f /usr/local/bin/nbquery
	rm -f /usr/local/bin/nbregister
	rm -f /usr/local/bin/nbpoison
	rm -f /usr/local/bin/nbsniff
	rm -f /usr/local/bin/genhash
	rm -f /usr/local/bin/dnsxss
	rm -f /usr/local/bin/dnslogger
	rm -f /usr/local/bin/dnscat
	rm -f /usr/local/bin/dnstest

uninstall: remove

clean:
	rm -f *.o *.exe *.stackdump nbquery nbregister nbpoison nbsniff genhash dnsxss dnslogger dnscat dnstest smbserver smbtest core 
	rm -f nbtool buffer select_group crypto smbclient
	-cd samples && make clean

nbquery: nbquery.o dns.o buffer.o udp.o tcp.o select_group.o types.o memory.o netbios_types.o
	${CC} ${CFLAGS} -o nbquery nbquery.o dns.o buffer.o udp.o tcp.o select_group.o types.o memory.o netbios_types.o ${LIBS}

nbsniff: nbsniff.o dns.o buffer.o udp.o tcp.o select_group.o types.o memory.o netbios_types.o
	${CC} ${CFLAGS} -o nbsniff nbsniff.o dns.o buffer.o udp.o tcp.o select_group.o types.o memory.o netbios_types.o ${LIBS}

#genhash: genhash.o crypto.o types.o memory.o buffer.o
#	${CC} ${CFLAGS} -o genhash genhash.o crypto.o types.o memory.o buffer.o ${LIBS}

dnscat: dnscat.o buffer.o tcp.o udp.o select_group.o types.o memory.o dns.o session.o
	${CC} ${CFLAGS} ${DNSCATFLAGS} -o dnscat dnscat.o buffer.o tcp.o udp.o select_group.o types.o memory.o dns.o session.o ${LIBS}

dnsxss: dnsxss.o buffer.o tcp.o udp.o select_group.o types.o memory.o dns.o
	${CC} ${CFLAGS} -o dnsxss dnsxss.o buffer.o tcp.o udp.o select_group.o types.o memory.o dns.o ${LIBS}

dnstest: dnstest.o buffer.o tcp.o udp.o select_group.o types.o memory.o dns.o
	${CC} ${CFLAGS} -o dnstest dnstest.o buffer.o tcp.o udp.o select_group.o types.o memory.o dns.o ${LIBS}

dnslogger: dnslogger.o buffer.o tcp.o udp.o select_group.o types.o memory.o dns.o
	${CC} ${CFLAGS} -o dnslogger dnslogger.o buffer.o tcp.o udp.o select_group.o types.o memory.o dns.o ${LIBS}

#smbtest: smbtest.o smbclient.o buffer.o udp.o tcp.o select_group.o smb.o nameservice.o crypto.o smb_types.o memory.o types.o 
#	${CC} ${CFLAGS} -o smbtest smbtest.o smbclient.o buffer.o udp.o tcp.o select_group.o smb.o nameservice.o crypto.o smb_types.o memory.o types.o ${LIBS}

#smbserver: smbserver.o buffer.o udp.o tcp.o select_group.o smb.o nameservice.o crypto.o smb_types.o memory.o types.o
#	${CC} ${CFLAGS} -o smbserver smbserver.o buffer.o udp.o tcp.o select_group.o smb.o nameservice.o crypto.o smb_types.o memory.o types.o ${LIBS}

