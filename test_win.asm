bits 64
org 0x00400000

; ==================== DOS HEADER ====================
dos_header:
    dw 0x5A4D                   ; MZ Signature
    times 29 dw 0               ; Padding
    dd pe_header - dos_header   ; Pointer to PE Header

; ==================== PE HEADER ====================
pe_header:
    dd 0x00004550               ; PE Signature
; COFF File Header
    dw 0x8664                   ; Machine: AMD64 (x64)
    dw 1                        ; Number of Sections
    dd 0                        ; TimeDateStamp
    dd 0                        ; PointerToSymbolTable
    dd 0                        ; NumberOfSymbols
    dw 240                      ; SizeOfOptionalHeader
    dw 0x0022                   ; Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

; ==================== OPTIONAL HEADER ====================
optional_header:
    dw 0x020B                   ; Magic: PE32+ (64-bit)
    db 0, 0                     ; Major/Minor Linker Version
    dd 0x1000                   ; SizeOfCode
    dd 0, 0                     ; SizeOfInitialized / Uninitialized Data
    dd entry_point - dos_header ; AddressOfEntryPoint (RVA)
    dd code_start - dos_header  ; BaseOfCode (RVA)
    dq 0x00400000               ; ImageBase
    dd 0x1000                   ; SectionAlignment
    dd 0x1000                   ; FileAlignment
    dw 6, 0                     ; Major/Minor OS Version
    dw 0, 0                     ; Major/Minor Image Version
    dw 6, 0                     ; Major/Minor Subsystem Version
    dd 0                        ; Win32VersionValue
    dd 0x2000                   ; SizeOfImage (Headers + Section)
    dd 0x1000                   ; SizeOfHeaders
    dd 0                        ; CheckSum
    dw 2                        ; Subsystem: Windows GUI
    dw 0x8140                   ; DllCharacteristics
    dq 0x100000, 0x1000         ; SizeOfStackReserve / Commit
    dq 0x100000, 0x1000         ; SizeOfHeapReserve / Commit
    dd 0                        ; LoaderFlags
    dd 16                       ; NumberOfRvaAndSizes

; Data Directories
    times 16 dq 0               ; 16 directories, 8 bytes each

; ==================== SECTION HEADER ====================
section_header:
    db '.text', 0, 0, 0         ; Name
    dd 0x1000                   ; VirtualSize
    dd 0x1000                   ; VirtualAddress (RVA)
    dd 0x1000                   ; SizeOfRawData (disk size)
    dd 0x1000                   ; PointerToRawData (4096)
    dd 0, 0                     ; Relocations / Linenumbers
    dw 0, 0                     ; Number of Relocations / Linenumbers
    dd 0xE0000020               ; Characteristics: CODE | EXECUTE | READ | WRITE

; Padding to 4096 bytes (offset 0x1000)
    times 4096 - ($ - dos_header) db 0

; ==================== CODE START ====================
code_start:

; ROR13 hashes of API names
hash_LdrLoadDll equ 0xB0988FE4
hash_Sleep equ 0xDB2D49B0
hash_RegisterClassA equ 0x2538882E
hash_CreateWindowExA equ 0x84454941
hash_DefWindowProcA equ 0x577A6CB2
hash_PeekMessageA equ 0xF2667BF4
hash_TranslateMessage equ 0x8FDE2C7E
hash_DispatchMessageA equ 0x690A1701
hash_PostQuitMessage equ 0x4BE0469D

entry_point:
    sub rsp, 40                 ; Shadow space + alignment

    ; 1. Find ntdll.dll via PEB
    mov rax, [gs:0x60]          ; PEB
    mov rax, [rax + 0x18]       ; PEB->Ldr
    mov rsi, [rax + 0x10]       ; Ldr->InLoadOrderModuleList (Flink)
.find_ntdll:
    mov rdi, [rsi + 0x30]       ; DllBase
    test rdi, rdi
    jz .next_ntdll
    mov rbx, [rsi + 0x58 + 8]   ; BaseDllName.Buffer
    test rbx, rbx
    jz .next_ntdll
    movzx ecx, word [rbx]
    or ecx, 0x20
    cmp ecx, 'n'
    jne .next_ntdll
    movzx ecx, word [rbx + 2]
    or ecx, 0x20
    cmp ecx, 't'
    jne .next_ntdll
    mov [rel ntdll_base], rdi
    jmp .ntdll_found
.next_ntdll:
    mov rsi, [rsi]
    jmp .find_ntdll
.ntdll_found:

    ; 2. Resolve LdrLoadDll from ntdll.dll
    mov rcx, [rel ntdll_base]
    mov edx, hash_LdrLoadDll
    call get_proc_address_manual
    mov [rel p_LdrLoadDll], rax
    
    ; 3. Find kernel32.dll/kernelbase.dll via PEB
    mov rax, [gs:0x60]
    mov rax, [rax + 0x18]
    mov rsi, [rax + 0x10]
.find_kernel:
    mov rdi, [rsi + 0x30]
    test rdi, rdi
    jz .next_kernel
    mov rbx, [rsi + 0x58 + 8]
    test rbx, rbx
    jz .next_kernel
    movzx ecx, word [rbx]
    or ecx, 0x20
    cmp ecx, 'k'
    jne .next_kernel
    movzx ecx, word [rbx + 2]
    or ecx, 0x20
    cmp ecx, 'e'
    jne .next_kernel
    mov [rel kernel32_base], rdi
    jmp .kernel_found
.next_kernel:
    mov rsi, [rsi]
    jmp .find_kernel
.kernel_found:

    ; 4. Resolve Sleep from kernel32.dll
    mov rcx, [rel kernel32_base]
    mov edx, hash_Sleep
    call get_proc_address_manual
    mov [rel p_Sleep], rax

    ; 5. Dynamic initialization of unicode strings for DLL paths
    lea rax, [rel user32_wstr]
    mov [rel user32_unicode + 8], rax
    lea rax, [rel gdi32_wstr]
    mov [rel gdi32_unicode + 8], rax

    ; 6. Load user32.dll via LdrLoadDll
    lea rcx, [rel user32_unicode]
    lea rdx, [rel user32_base]
    call load_dll

    ; 7. Resolve user32.dll functions
    mov rcx, [rel user32_base]
    mov edx, hash_RegisterClassA
    call get_proc_address_manual
    mov [rel p_RegisterClassA], rax

    mov rcx, [rel user32_base]
    mov edx, hash_CreateWindowExA
    call get_proc_address_manual
    mov [rel p_CreateWindowExA], rax

    mov rcx, [rel ntdll_base]   ; Resolve from ntdll to get raw pointer (bypasses forwarder)
    mov edx, hash_DefWindowProcA
    call get_proc_address_manual
    mov [rel p_DefWindowProcA], rax

    mov rcx, [rel user32_base]
    mov edx, hash_PeekMessageA
    call get_proc_address_manual
    mov [rel p_PeekMessageA], rax

    mov rcx, [rel user32_base]
    mov edx, hash_TranslateMessage
    call get_proc_address_manual
    mov [rel p_TranslateMessage], rax

    mov rcx, [rel user32_base]
    mov edx, hash_DispatchMessageA
    call get_proc_address_manual
    mov [rel p_DispatchMessageA], rax

    mov rcx, [rel user32_base]
    mov edx, hash_PostQuitMessage
    call get_proc_address_manual
    mov [rel p_PostQuitMessage], rax

    mov rax, [rel p_RegisterClassA]
    test rax, rax
    jz .err_101
    mov rax, [rel p_CreateWindowExA]
    test rax, rax
    jz .err_102
    mov rax, [rel p_DefWindowProcA]
    test rax, rax
    jz .err_103
    mov rax, [rel p_PeekMessageA]
    test rax, rax
    jz .err_104
    mov rax, [rel p_TranslateMessage]
    test rax, rax
    jz .err_105
    mov rax, [rel p_DispatchMessageA]
    test rax, rax
    jz .err_106
    mov rax, [rel p_PostQuitMessage]
    test rax, rax
    jz .err_107
    jmp .err_ok

.err_101: mov eax, 101; jmp .err_exit
.err_102: mov eax, 102; jmp .err_exit
.err_103: mov eax, 103; jmp .err_exit
.err_104: mov eax, 104; jmp .err_exit
.err_105: mov eax, 105; jmp .err_exit
.err_106: mov eax, 106; jmp .err_exit
.err_107: mov eax, 107; jmp .err_exit

.err_exit:
    add rsp, 40
    ret

.err_ok:

    ; 8. Register window class
    ; Clear wndclass
    lea rdi, [rel wndclass]
    xor eax, eax
    mov ecx, 72
    rep stosb

    ; Set fields
    mov dword [rel wndclass], 0x0023 ; CS_OWNDC | CS_HREDRAW | CS_VREDRAW
    lea rax, [rel WndProc]
    mov [rel wndclass + 8], rax
    mov qword [rel wndclass + 24], 0x400000 ; hInstance
    lea rax, [rel class_name]
    mov [rel wndclass + 64], rax

    lea rcx, [rel wndclass]
    call [rel p_RegisterClassA]

    ; 9. Create Window
    sub rsp, 96
    xor rcx, rcx
    lea rdx, [rel class_name]
    lea r8, [rel window_name]
    mov r9d, 0x10CF0000         ; WS_OVERLAPPEDWINDOW | WS_VISIBLE
    mov dword [rsp + 32], 100
    mov dword [rsp + 40], 100
    mov dword [rsp + 48], 800
    mov dword [rsp + 56], 600
    mov qword [rsp + 64], 0
    mov qword [rsp + 72], 0
    mov qword [rsp + 80], 0x400000 ; hInstance
    mov qword [rsp + 88], 0
    call [rel p_CreateWindowExA]
    add rsp, 96
    mov [rel hwnd], rax

    ; 10. Message loop
.loop:
    mov rax, [rel game_running]
    test rax, rax
    jz .exit

    ; Message check
.msg_loop:
    sub rsp, 48
    lea rcx, [rel msg]
    xor rdx, rdx
    xor r8, r8
    xor r9, r9
    mov dword [rsp + 32], 1     ; PM_REMOVE
    call [rel p_PeekMessageA]
    add rsp, 48
    test eax, eax
    jz .no_msg

    lea rcx, [rel msg]
    call [rel p_TranslateMessage]
    lea rcx, [rel msg]
    call [rel p_DispatchMessageA]
    jmp .msg_loop

.no_msg:
    ; Do a short sleep to avoid CPU hogging in test
    mov ecx, 16
    call [rel p_Sleep]
    jmp .loop

.exit:
    add rsp, 40
    ret

; ==================== MANUAL EXPORT RESOLVER ====================
get_proc_address_manual:
    push rbp
    push rdi
    push rsi
    push rbx
    
    mov rbx, rcx                ; rbx = DLL Base
    mov r8d, edx                ; r8d = Target Hash
    
    mov eax, [rbx + 0x3C]       ; eax = e_lfanew
    lea r9, [rbx + rax]         ; r9 = PE Header
    
    mov eax, [r9 + 136]         ; eax = Export Directory RVA (136 is offset of export directory in PE32+)
    test eax, eax
    jz .not_found
    lea r10, [rbx + rax]        ; r10 = Export Directory
    
    mov r11d, [r10 + 0x18]      ; r11d = NumberOfNames
    mov edi, [r10 + 0x20]       ; edi = AddressOfNames RVA
    lea r12, [rbx + rdi]        ; r12 = AddressOfNames absolute
    
    xor ecx, ecx                ; ecx = Name Index
.loop:
    cmp ecx, r11d
    jae .not_found
    
    mov edi, [r12 + rcx*4]      ; edi = Name RVA
    lea rdi, [rbx + rdi]        ; rdi = Name absolute
    
    xor esi, esi                ; rsi = Hash
.hash_loop:
    movzx eax, byte [rdi]
    test al, al
    jz .hash_done
    ror esi, 13
    add esi, eax
    inc rdi
    jmp .hash_loop
.hash_done:
    
    cmp esi, r8d
    je .found
    
    inc ecx
    jmp .loop
    
.found:
    mov edi, [r10 + 0x24]       ; AddressOfNameOrdinals RVA
    lea rdi, [rbx + rdi]
    movzx eax, word [rdi + rcx*2] ; eax = Ordinal
    
    mov edi, [r10 + 0x1C]       ; AddressOfFunctions RVA
    lea rdi, [rbx + rdi]
    mov eax, [rdi + rax*4]      ; eax = Function RVA
    
    lea rax, [rbx + rax]        ; rax = Function absolute
    jmp .done
    
.not_found:
    xor rax, rax
.done:
    pop rbx
    pop rsi
    pop rdi
    pop rbp
    ret

; ==================== LOAD DLL HELPER ====================
load_dll:
    push rbp
    mov rbp, rsp
    sub rsp, 32
    mov r8, rcx                 ; r8 = DllName
    mov r9, rdx                 ; r9 = DllHandle
    xor rcx, rcx
    xor rdx, rdx
    call [rel p_LdrLoadDll]
    add rsp, 32
    pop rbp
    ret

; ==================== WNDPROC ====================
WndProc:
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    cmp edx, 0x0010             ; WM_CLOSE
    je .close
    cmp edx, 0x0002             ; WM_DESTROY
    je .destroy
    
    call [rel p_DefWindowProcA]
    jmp .done
    
.close:
.destroy:
    xor ecx, ecx
    call [rel p_PostQuitMessage]
    mov qword [rel game_running], 0
    xor rax, rax
    
.done:
    add rsp, 32
    pop rbp
    ret

; ==================== DATA SECTION ====================
align 8
ntdll_base:         dq 0
kernel32_base:      dq 0
user32_base:        dq 0
hwnd:               dq 0

p_LdrLoadDll:       dq 0
p_Sleep:            dq 0
p_RegisterClassA:   dq 0
p_CreateWindowExA:  dq 0
p_DefWindowProcA:   dq 0
p_PeekMessageA:     dq 0
p_TranslateMessage: dq 0
p_DispatchMessageA: dq 0
p_PostQuitMessage:  dq 0

game_running:       dq 1

class_name:         db 'AscendClass', 0
window_name:        db 'Ascend - Vampire Survivors Clone', 0

; Unicode strings for LdrLoadDll
user32_unicode:
    dw 20
    dw 22
    dd 0
    dq 0
gdi32_unicode:
    dw 18
    dw 20
    dd 0
    dq 0

user32_wstr:        dw 'u','s','e','r','3','2','.','d','l','l',0
gdi32_wstr:         dw 'g','d','i','3','2','.','d','l','l',0

wndclass:           times 72 db 0
msg:                times 48 db 0

; Pad file to exactly 8192 bytes
    times 8192 - ($ - dos_header) db 0
