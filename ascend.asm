bits 64
org 0x00400000

section .text

; ==================== DOS HEADER ====================
dos_header:
    dw 0x5A4D                   ; MZ Signature
    times 29 dw 0               ; Padding
    dd pe_header - dos_header   ; Pointer to PE Header (file offset 0x40)

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
    dd 0x1E00                   ; SizeOfCode (7680 bytes)
    dd 0, 0                     ; SizeOfInitialized / Uninitialized Data
    dd entry_point - dos_header + 3584 ; AddressOfEntryPoint (RVA, adjusted for 512->4096 section shift)
    dd code_start - dos_header + 3584  ; BaseOfCode (RVA)
    dq 0x00400000               ; ImageBase
    dd 0x1000                   ; SectionAlignment (4096)
    dd 0x200                    ; FileAlignment (512)
    dw 6, 0                     ; Major/Minor OS Version
    dw 0, 0                     ; Major/Minor Image Version
    dw 6, 0                     ; Major/Minor Subsystem Version
    dd 0                        ; Win32VersionValue
    dd 0x4000                   ; SizeOfImage (Headers 4K + Section 12K)
    dd 0x200                    ; SizeOfHeaders (512)
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
    dd 0x3000                   ; VirtualSize (12KB memory range)
    dd 0x1000                   ; VirtualAddress (RVA)
    dd 0x1E00                   ; SizeOfRawData (7680 bytes = 8192 - 512)
    dd 0x200                    ; PointerToRawData (512)
    dd 0, 0                     ; Relocations / Linenumbers
    dw 0, 0                     ; Number of Relocations / Linenumbers
    dd 0xE0000020               ; Characteristics: CODE | EXECUTE | READ | WRITE (single readable-writable code section)

; Padding to 512 bytes (offset 0x200)
    times 512 - ($ - $$) db 0

; ==================== CODE START ====================
code_start:

; ROR13 hashes of API names
hash_LdrLoadDll equ 0xB0988FE4
hash_Sleep equ 0xDB2D49B0
hash_DefWindowProcA equ 0x577A6CB2 ; NtdllDefWindowProc_A from ntdll.dll

; user32
hash_RegisterClassA equ 0x2538882E
hash_CreateWindowExA equ 0x84454941
hash_PeekMessageA equ 0xF2667BF4
hash_TranslateMessage equ 0x8FDE2C7E
hash_DispatchMessageA equ 0x690A1701
hash_GetDC equ 0xCC248D43
hash_ReleaseDC equ 0xBBD63656
hash_GetAsyncKeyState equ 0x2B245A7A
hash_PostQuitMessage equ 0x4BE0469D
hash_ShowCursor equ 0xD15E1334

; gdi32
hash_CreateCompatibleDC equ 0x66F33A69
hash_CreateCompatibleBitmap equ 0x1EB1121F
hash_SelectObject equ 0xFE97A655
hash_DeleteObject equ 0xFE3DA875
hash_DeleteDC equ 0xEBBA7239
hash_PatBlt equ 0xEB66211C
hash_CreateSolidBrush equ 0x2BACB18D
hash_CreatePen equ 0x91C362DF
hash_Rectangle equ 0x32F23700
hash_Ellipse equ 0xD6B2DC9B
hash_MoveToEx equ 0xABEA7613
hash_LineTo equ 0xDEA6A9D5
hash_SetTextColor equ 0x7805F866
hash_SetBkMode equ 0xF1F6D8E6
hash_TextOutA equ 0xA33B683D
hash_BitBlt equ 0xEB66A115

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

    ; 6. Load user32.dll and gdi32.dll via LdrLoadDll
    lea rcx, [rel user32_unicode]
    lea rdx, [rel user32_base]
    call load_dll
    mov rax, [rel user32_base]
    test rax, rax
    jz .err_user32_fail

    lea rcx, [rel gdi32_unicode]
    lea rdx, [rel gdi32_base]
    call load_dll
    mov rax, [rel gdi32_base]
    test rax, rax
    jz .err_gdi32_fail
    jmp .dlls_ok

.err_user32_fail:
    mov eax, 50
    add rsp, 40
    ret

.err_gdi32_fail:
    mov eax, 60
    add rsp, 40
    ret

.dlls_ok:

    ; 7. Resolve user32.dll functions
    mov rcx, [rel user32_base]
    mov edx, hash_RegisterClassA
    call get_proc_address_manual
    mov [rel p_RegisterClassA], rax

    mov rcx, [rel user32_base]
    mov edx, hash_CreateWindowExA
    call get_proc_address_manual
    mov [rel p_CreateWindowExA], rax

    mov rcx, [rel ntdll_base]   ; DefWindowProcA resolved from ntdll to bypass forwarding!
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
    mov edx, hash_GetDC
    call get_proc_address_manual
    mov [rel p_GetDC], rax

    mov rcx, [rel user32_base]
    mov edx, hash_ReleaseDC
    call get_proc_address_manual
    mov [rel p_ReleaseDC], rax

    mov rcx, [rel user32_base]
    mov edx, hash_GetAsyncKeyState
    call get_proc_address_manual
    mov [rel p_GetAsyncKeyState], rax

    mov rcx, [rel user32_base]
    mov edx, hash_PostQuitMessage
    call get_proc_address_manual
    mov [rel p_PostQuitMessage], rax

    mov rcx, [rel user32_base]
    mov edx, hash_ShowCursor
    call get_proc_address_manual
    mov [rel p_ShowCursor], rax

    ; 8. Resolve gdi32.dll functions
    mov rcx, [rel gdi32_base]
    mov edx, hash_CreateCompatibleDC
    call get_proc_address_manual
    mov [rel p_CreateCompatibleDC], rax

    mov rcx, [rel gdi32_base]
    mov edx, hash_CreateCompatibleBitmap
    call get_proc_address_manual
    mov [rel p_CreateCompatibleBitmap], rax

    mov rcx, [rel gdi32_base]
    mov edx, hash_SelectObject
    call get_proc_address_manual
    mov [rel p_SelectObject], rax

    mov rcx, [rel gdi32_base]
    mov edx, hash_DeleteObject
    call get_proc_address_manual
    mov [rel p_DeleteObject], rax

    mov rcx, [rel gdi32_base]
    mov edx, hash_DeleteDC
    call get_proc_address_manual
    mov [rel p_DeleteDC], rax

    mov rcx, [rel gdi32_base]
    mov edx, hash_PatBlt
    call get_proc_address_manual
    mov [rel p_PatBlt], rax

    mov rcx, [rel gdi32_base]
    mov edx, hash_CreateSolidBrush
    call get_proc_address_manual
    mov [rel p_CreateSolidBrush], rax

    mov rcx, [rel gdi32_base]
    mov edx, hash_CreatePen
    call get_proc_address_manual
    mov [rel p_CreatePen], rax

    mov rcx, [rel gdi32_base]
    mov edx, hash_Rectangle
    call get_proc_address_manual
    mov [rel p_Rectangle], rax

    mov rcx, [rel gdi32_base]
    mov edx, hash_Ellipse
    call get_proc_address_manual
    mov [rel p_Ellipse], rax

    mov rcx, [rel gdi32_base]
    mov edx, hash_MoveToEx
    call get_proc_address_manual
    mov [rel p_MoveToEx], rax

    mov rcx, [rel gdi32_base]
    mov edx, hash_LineTo
    call get_proc_address_manual
    mov [rel p_LineTo], rax

    mov rcx, [rel gdi32_base]
    mov edx, hash_SetTextColor
    call get_proc_address_manual
    mov [rel p_SetTextColor], rax

    mov rcx, [rel gdi32_base]
    mov edx, hash_SetBkMode
    call get_proc_address_manual
    mov [rel p_SetBkMode], rax

    mov rcx, [rel gdi32_base]
    mov edx, hash_TextOutA
    call get_proc_address_manual
    mov [rel p_TextOutA], rax

    mov rcx, [rel gdi32_base]
    mov edx, hash_BitBlt
    call get_proc_address_manual
    mov [rel p_BitBlt], rax

    ; Check all dynamic function pointers
    lea rsi, [rel p_LdrLoadDll]
    xor ecx, ecx
.chk_ptr_loop:
    cmp ecx, 29
    jae .chk_ptr_ok
    mov rax, [rsi + rcx*8]
    test rax, rax
    jz .chk_ptr_fail
    inc ecx
    jmp .chk_ptr_loop
.chk_ptr_fail:
    mov eax, ecx
    inc eax                     ; Fail code is 1-based index of failed API
    add rsp, 40
    ret
.chk_ptr_ok:
    ; Debug exit: Step 6
    ; 9. Calibrate RDTSC
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov rbx, rax
    mov ecx, 100
    call [rel p_Sleep]
    rdtsc
    shl rdx, 32
    or rax, rdx
    sub rax, rbx
    xor rdx, rdx
    mov rcx, 6                  ; divisor (100ms / 6 = 16.67ms = 1 frame)
    div rcx
    mov [rel cycles_per_frame], rax

    ; Seed RNG
    rdtsc
    test eax, eax
    jnz .rng_ok
    mov eax, 1
.rng_ok:
    mov [rel rng_state], eax

    ; 10. Register window class
    lea rdi, [rel wndclass]
    xor eax, eax
    mov ecx, 72
    rep stosb

    mov dword [rel wndclass], 0x0023 ; CS_OWNDC | CS_HREDRAW | CS_VREDRAW
    lea rax, [rel WndProc]
    mov [rel wndclass + 8], rax
    mov qword [rel wndclass + 24], 0x400000 ; hInstance
    lea rax, [rel class_name]
    mov [rel wndclass + 64], rax

    lea rcx, [rel wndclass]
    call [rel p_RegisterClassA]

    ; 11. Create Window
    sub rsp, 96
    xor rcx, rcx
    lea rdx, [rel class_name]
    lea r8, [rel window_name]
    mov r9d, 0x10CF0000         ; WS_OVERLAPPEDWINDOW | WS_VISIBLE
    mov dword [rsp + 32], 100
    mov dword [rsp + 40], 100
    mov dword [rsp + 48], 816   ; client width 800
    mov dword [rsp + 56], 639   ; client height 600
    mov qword [rsp + 64], 0
    mov qword [rsp + 72], 0
    mov qword [rsp + 80], 0x400000
    mov qword [rsp + 88], 0
    call [rel p_CreateWindowExA]
    add rsp, 96
    mov [rel hwnd], rax

    ; Initialize GDI Double Buffering
    mov rcx, rax
    call [rel p_GetDC]
    mov [rel hdc], rax

    mov rcx, rax
    call [rel p_CreateCompatibleDC]
    mov [rel hdcMem], rax

    mov rcx, [rel hdc]
    mov edx, 800
    mov r8d, 600
    call [rel p_CreateCompatibleBitmap]
    mov [rel hbmMem], rax

    mov rcx, [rel hdcMem]
    mov rdx, rax
    call [rel p_SelectObject]

    ; Hide system cursor inside game window
    xor ecx, ecx
    call [rel p_ShowCursor]



    ; Initialize Option strings array
    lea rsi, [rel opt_strings]
    lea rax, [rel opt_speed]
    mov [rsi + 0], rax
    lea rax, [rel opt_damage]
    mov [rsi + 8], rax
    lea rax, [rel opt_cooldown]
    mov [rsi + 16], rax
    lea rax, [rel opt_proj]
    mov [rsi + 24], rax
    lea rax, [rel opt_shield]
    mov [rsi + 32], rax

    ; Initialize brushes and pens
    lea rsi, [rel colors]
    lea rdi, [rel hBrushes]
    lea rbx, [rel hPens]
    xor ecx, ecx
.init_gdi:
    cmp ecx, 8
    jae .gdi_done
    mov r8d, [rsi + rcx*4]

    push rcx
    push rsi
    push rdi
    push rbx
    mov ecx, r8d
    sub rsp, 32
    call [rel p_CreateSolidBrush]
    add rsp, 32
    pop rbx
    pop rdi
    pop rsi
    pop rcx
    mov [rdi + rcx*8], rax

    push rcx
    push rsi
    push rdi
    push rbx
    xor ecx, ecx
    mov edx, 1
    mov r8d, r8d
    sub rsp, 32
    call [rel p_CreatePen]
    add rsp, 32
    pop rbx
    pop rdi
    pop rsi
    pop rcx
    mov [rbx + rcx*8], rax

    inc ecx
    jmp .init_gdi
.gdi_done:

    ; Initialize Player entity at index 0
    lea rdi, [rel entities]
    mov dword [rdi + 0], 400    ; X
    mov dword [rdi + 4], 300    ; Y
    mov byte [rdi + 16], 1      ; Type = Player
    mov byte [rdi + 17], 5      ; HP = 5
    mov dword [rdi + 18], 0     ; Cooldown

    ; ==================== MAIN GAME LOOP ====================
game_loop:
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [rel frame_start], rax

    ; Process window messages
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

    ; Check ESC key to exit
    mov ecx, 0x1B               ; VK_ESCAPE
    call [rel p_GetAsyncKeyState]
    test ax, 0x8000
    jnz exit_game

    ; Branch on Game State
    mov rax, [rel game_state]
    cmp rax, 1
    je update_levelup
    cmp rax, 2
    je update_gameover

    ; ----- NORMAL PLAY STATE -----
    ; 1. Player Input
    xor eax, eax                ; dx
    xor ebx, ebx                ; dy

    mov ecx, 0x41               ; 'A'
    call [rel p_GetAsyncKeyState]
    test ax, 0x8000
    jz .no_a
    dec eax
.no_a:
    mov ecx, 0x44               ; 'D'
    push rax
    call [rel p_GetAsyncKeyState]
    pop rax
    test ax, 0x8000
    jz .no_d
    inc eax
.no_d:
    mov ecx, 0x57               ; 'W'
    push rax
    call [rel p_GetAsyncKeyState]
    pop rax
    test ax, 0x8000
    jz .no_w
    dec ebx
.no_w:
    mov ecx, 0x53               ; 'S'
    push rax
    push rbx
    call [rel p_GetAsyncKeyState]
    pop rbx
    pop rax
    test ax, 0x8000
    jz .no_s
    inc ebx
.no_s:
    ; Move Player
    mov r8, [rel player_speed]
    imul eax, r8d
    imul ebx, r8d

    lea rdi, [rel entities]
    add [rdi + 0], eax
    add [rdi + 4], ebx

    ; Boundaries check
    cmp dword [rdi + 0], 10
    jge .x_min_ok
    mov dword [rdi + 0], 10
.x_min_ok:
    cmp dword [rdi + 0], 790
    jle .x_max_ok
    mov dword [rdi + 0], 790
.x_max_ok:
    cmp dword [rdi + 4], 10
    jge .y_min_ok
    mov dword [rdi + 4], 10
.y_min_ok:
    cmp dword [rdi + 4], 590
    jle .y_max_ok
    mov dword [rdi + 4], 590
.y_max_ok:



    ; 2. Handle Spawning
    dec qword [rel spawn_timer]
    jg .skip_spawn
    ; Reset spawn timer
    mov rax, [rel spawn_cooldown]
    mov [rel spawn_timer], rax

    ; Find inactive entity from index 1 to 79 to spawn enemy
    mov ecx, 1
.spawn_loop:
    cmp ecx, 80
    jae .skip_spawn
    imul rsi, rcx, 28
    lea rax, [rel entities]
    add rsi, rax
    cmp byte [rsi + 16], 0      ; inactive?
    je .do_spawn
    inc ecx
    jmp .spawn_loop
.do_spawn:
    ; Pick border (0=Top, 1=Bottom, 2=Left, 3=Right)
    push rsi
    call xorshift32
    pop rsi
    xor edx, edx
    mov r8d, 4
    div r8d                     ; edx = border

    push rdx
    push rsi
    call xorshift32
    pop rsi
    pop rdx
    xor edx, edx
    mov r9d, 800
    div r9d
    mov r8d, edx                ; r8d = rand(0, 800)

    push r8
    push rdx
    push rsi
    call xorshift32
    pop rsi
    pop rdx
    pop r8
    xor edx, edx
    mov r10d, 600
    div r10d
    mov r9d, edx                ; r9d = rand(0, 600)

    cmp edx, 0
    je .sp_top
    cmp edx, 1
    je .sp_bot
    cmp edx, 2
    je .sp_left
    jmp .sp_right
.sp_top:
    mov [rsi + 0], r8d
    mov dword [rsi + 4], -20
    jmp .sp_init
.sp_bot:
    mov [rsi + 0], r8d
    mov dword [rsi + 4], 620
    jmp .sp_init
.sp_left:
    mov dword [rsi + 0], -20
    mov [rsi + 4], r9d
    jmp .sp_init
.sp_right:
    mov dword [rsi + 0], 820
    mov [rsi + 4], r9d
.sp_init:
    ; Decide enemy type based on wave
    mov byte [rsi + 16], 2      ; Default basic enemy
    mov byte [rsi + 17], 1      ; HP = 1
    mov dword [rsi + 18], 0     ; Cooldown timer

    ; Wave elite spawning
    mov rax, [rel wave]
    xor rdx, rdx
    mov r8d, 5
    div r8d
    test rdx, rdx
    jnz .skip_spawn             ; Only spawn elite every 5 waves

    ; Decide elite type based on division result
    push rsi
    call xorshift32
    pop rsi
    xor edx, edx
    mov r8d, 3
    div r8d                     ; edx = 0, 1, 2
    cmp edx, 0
    je .elite_tank
    cmp edx, 1
    je .elite_runner
    jmp .elite_shooter

.elite_tank:
    mov byte [rsi + 16], 3      ; Tank
    mov byte [rsi + 17], 3      ; HP = 3
    jmp .skip_spawn
.elite_runner:
    mov byte [rsi + 16], 4      ; Runner
    mov byte [rsi + 17], 1      ; HP = 1
    jmp .skip_spawn
.elite_shooter:
    mov byte [rsi + 16], 5      ; Shooter
    mov byte [rsi + 17], 2      ; HP = 2

.skip_spawn:



    ; 3. Auto-Attack nearest enemy
    dec dword [rdi + 18]        ; player cooldown timer
    jg .skip_attack

    ; Find closest enemy
    mov ecx, 1                  ; loop index
    mov r8d, 99999999           ; min dist sq
    xor r9d, r9d                ; closest index
.closest_loop:
    cmp ecx, 80
    jae .closest_done
    imul rsi, rcx, 28
    lea rax, [rel entities]
    add rsi, rax
    mov al, [rsi + 16]
    cmp al, 2
    jl .next_closest
    cmp al, 5
    jg .next_closest

    ; Calculate dist sq
    mov eax, [rdi + 0]          ; player X
    sub eax, [rsi + 0]          ; player X - enemy X
    imul eax, eax
    mov ebx, [rdi + 4]          ; player Y
    sub ebx, [rsi + 4]          ; player Y - enemy Y
    imul ebx, ebx
    add eax, ebx                ; dist sq

    cmp eax, r8d
    jge .next_closest
    mov r8d, eax
    mov r9d, ecx
.next_closest:
    inc ecx
    jmp .closest_loop
.closest_done:

    test r9d, r9d
    jz .skip_attack

    ; Spawn projectile targeting closest enemy
    mov r9, r9                  ; zero-extend
    imul rsi, r9, 28
    lea rax, [rel entities]
    add rsi, rax

    ; Shoot first projectile
    mov rcx, rsi
    call shoot_projectile

    ; If extra_projectiles > 0, shoot at other active enemies
    mov r10, [rel extra_projectiles]
    test r10, r10
    jz .reset_cooldown

    ; Find another active enemy
    mov ecx, 1
.extra_loop:
    cmp ecx, 80
    jae .reset_cooldown
    cmp ecx, r9d
    je .next_extra
    imul rsi, rcx, 28
    lea rax, [rel entities]
    add rsi, rax
    mov al, [rsi + 16]
    cmp al, 2
    jl .next_extra
    cmp al, 5
    jg .next_extra

    push rcx
    push r10
    mov rcx, rsi
    call shoot_projectile
    pop r10
    pop rcx
    dec r10
    jz .reset_cooldown
.next_extra:
    inc ecx
    jmp .extra_loop

.reset_cooldown:
    mov rax, [rel attack_cooldown_rate]
    mov [rdi + 18], eax         ; Reset player attack timer

.skip_attack:



    ; 4. Update Entities AI, physics, limits, attacks
    mov ecx, 1
.update_loop:
    cmp ecx, 100
    jae .update_done
    imul rsi, rcx, 28
    lea rax, [rel entities]
    add rsi, rax
    mov al, [rsi + 16]
    test al, al
    jz .next_entity

    ; Branch on type
    cmp al, 2
    jge .not_player_type
    jmp .next_entity            ; Player updated separately
.not_player_type:
    cmp al, 5
    jg .projectile_type

    ; ----- ENEMY AI & MOVEMENT -----
    ; Base speed based on type
    mov r8d, 2                  ; basic enemy speed
    cmp al, 3
    jne .not_tank
    mov r8d, 1                  ; tank speed
    jmp .got_speed
.not_tank:
    cmp al, 4
    jne .not_runner
    mov r8d, 4                  ; runner speed
    jmp .got_speed
.not_runner:
    cmp al, 5
    jne .got_speed
    mov r8d, 2                  ; shooter speed
.got_speed:
    ; Scale speed with wave
    mov rax, [rel wave]
    shr rax, 2                  ; wave / 4
    add r8d, eax                ; speed + wave/4

    ; AI: Normalize towards player
    mov eax, [rel entities + 0] ; Player X
    sub eax, [rsi + 0]          ; Player X - Enemy X
    mov ebx, [rel entities + 4] ; Player Y
    sub ebx, [rsi + 4]          ; Player Y - Enemy Y

    mov r9d, eax
    cdq
    xor r9d, edx
    sub r9d, edx                ; r9d = abs(dx)

    mov r10d, ebx
    cdq
    xor r10d, edx
    sub r10d, edx               ; r10d = abs(dy)

    mov r11d, r9d
    cmp r10d, r9d
    cmovg r11d, r10d            ; r11d = max_dist

    test r11d, r11d
    jz .enemy_no_move

    push rcx
    imul eax, r8d
    cdq
    idiv r11d
    mov [rsi + 8], eax          ; vx

    imul ebx, r8d
    mov eax, ebx
    cdq
    idiv r11d
    mov [rsi + 12], eax         ; vy
    pop rcx

.enemy_no_move:
    ; Update position
    mov eax, [rsi + 8]
    add [rsi + 0], eax
    mov eax, [rsi + 12]
    add [rsi + 4], eax

    ; Shooter special attack
    cmp byte [rsi + 16], 5
    jne .next_entity
    dec dword [rsi + 18]        ; shooter cooldown timer
    jg .next_entity
    mov dword [rsi + 18], 90    ; Shoot every 1.5s (90 frames)

    ; Spawn enemy projectile
    push rcx
    mov rcx, rsi
    call shoot_enemy_projectile
    pop rcx
    jmp .next_entity

.projectile_type:
    ; ----- PROJECTILE MOVEMENT -----
    mov eax, [rsi + 8]          ; vx
    add [rsi + 0], eax
    mov eax, [rsi + 12]         ; vy
    add [rsi + 4], eax

    ; Boundary / lifetime check for projectile
    cmp dword [rsi + 0], -50
    jl .kill_projectile
    cmp dword [rsi + 0], 850
    jg .kill_projectile
    cmp dword [rsi + 4], -50
    jl .kill_projectile
    cmp dword [rsi + 4], 650
    jg .kill_projectile
    jmp .next_entity

.kill_projectile:
    mov byte [rsi + 16], 0      ; make inactive
.next_entity:
    inc ecx
    jmp .update_loop
.update_done:



    ; 5. Collisions & Health
    ; Projectiles (type 6) vs Enemies (type 2..5)
    mov ecx, 80
.proj_col_loop:
    cmp ecx, 100
    jae .proj_col_done
    imul rsi, rcx, 28
    lea rax, [rel entities]
    add rsi, rax
    cmp byte [rsi + 16], 6      ; active player projectile?
    jne .next_proj_col

    ; Compare against all enemies
    mov edx, 1
.enemy_col_loop:
    cmp edx, 80
    jae .next_proj_col
    imul rdi, rdx, 28
    lea rax, [rel entities]
    add rdi, rax
    mov al, [rdi + 16]
    cmp al, 2
    jl .next_enemy_col
    cmp al, 5
    jg .next_enemy_col

    ; Collision distance squared (radius sum squared ~400)
    mov eax, [rsi + 0]
    sub eax, [rdi + 0]
    imul eax, eax
    mov ebx, [rsi + 4]
    sub ebx, [rdi + 4]
    imul ebx, ebx
    add eax, ebx

    cmp eax, 400
    jge .next_enemy_col

    ; Collision! Damage enemy
    mov al, [rel player_damage]
    sub [rdi + 17], al          ; enemy HP -= player_damage
    mov byte [rsi + 16], 0      ; kill projectile

    cmp byte [rdi + 17], 0
    jg .next_proj_col            ; Enemy survived

    ; Enemy died!
    mov byte [rdi + 16], 0      ; kill enemy
    inc qword [rel score]
    inc qword [rel kills]

    ; Check level up (every 30 kills)
    mov rax, [rel kills]
    cmp rax, 30
    jl .next_proj_col
    mov qword [rel kills], 0
    inc qword [rel level]

    ; Trigger level-up choice
    mov qword [rel game_state], 1
    call trigger_levelup_choices
    jmp .proj_col_done           ; break collision loops to handle pause

.next_enemy_col:
    inc edx
    jmp .enemy_col_loop
.next_proj_col:
    inc ecx
    jmp .proj_col_loop
.proj_col_done:

    ; Skip player collisions if level up triggered
    mov rax, [rel game_state]
    cmp rax, 1
    je .skip_player_cols

    ; Player (index 0) vs Enemies (2..5) and Enemy Projectiles (7)
    lea rdi, [rel entities]     ; Player
    mov ecx, 1
.player_col_loop:
    cmp ecx, 100
    jae .player_col_done
    imul rsi, rcx, 28
    lea rax, [rel entities]
    add rsi, rax
    mov al, [rsi + 16]
    test al, al
    jz .next_player_col
    cmp al, 1
    je .next_player_col
    cmp al, 6
    je .next_player_col         ; ignore player projectiles

    ; Check collision
    mov eax, [rdi + 0]
    sub eax, [rsi + 0]
    imul eax, eax
    mov ebx, [rdi + 4]
    sub ebx, [rsi + 4]
    imul ebx, ebx
    add eax, ebx

    cmp eax, 400
    jge .next_player_col

    ; Collision!
    mov byte [rsi + 16], 0      ; kill enemy/projectile on hit

    ; Absorb with shield first
    mov rax, [rel shield_count]
    test rax, rax
    jz .take_damage
    dec qword [rel shield_count]
    jmp .next_player_col

.take_damage:
    dec byte [rdi + 17]         ; Player HP -= 1
    cmp byte [rdi + 17], 0
    jg .next_player_col
    mov qword [rel game_state], 2 ; Game Over!
    jmp .player_col_done

.next_player_col:
    inc ecx
    jmp .player_col_loop
.player_col_done:
.skip_player_cols:



    ; 6. Update wave progression
    dec qword [rel wave_timer]
    jg .skip_wave
    mov qword [rel wave_timer], 1800 ; 30s per wave
    inc qword [rel wave]

    ; Increase spawn rate
    cmp qword [rel spawn_cooldown], 15
    jle .skip_wave
    sub qword [rel spawn_cooldown], 5 ; Spawn faster
.skip_wave:



    ; ----- RENDER GAME FRAME -----
    call render_frame
    jmp wait_frame

    ; ----- LEVEL UP STATE -----
update_levelup:
    ; Draw current level up screen
    call render_frame

    ; Read upgrade keys 1, 2, 3
    mov ecx, 0x31               ; '1'
    call [rel p_GetAsyncKeyState]
    test ax, 0x8000
    jnz .select_1

    mov ecx, 0x32               ; '2'
    call [rel p_GetAsyncKeyState]
    test ax, 0x8000
    jnz .select_2

    mov ecx, 0x33               ; '3'
    call [rel p_GetAsyncKeyState]
    test ax, 0x8000
    jnz .select_3
    jmp wait_frame

.select_1:
    mov edx, [rel upgrade_choice_1]
    call apply_upgrade
    mov qword [rel game_state], 0
    jmp wait_frame
.select_2:
    mov edx, [rel upgrade_choice_2]
    call apply_upgrade
    mov qword [rel game_state], 0
    jmp wait_frame
.select_3:
    mov edx, [rel upgrade_choice_3]
    call apply_upgrade
    mov qword [rel game_state], 0
    jmp wait_frame

    ; ----- GAME OVER STATE -----
update_gameover:
    call render_frame
    ; just loop wait_frame until ESC closed it

wait_frame:
    rdtsc
    shl rdx, 32
    or rax, rdx
    sub rax, [rel frame_start]
    cmp rax, [rel cycles_per_frame]
    jb wait_frame

    mov rax, [rel game_running]
    test rax, rax
    jnz game_loop

exit_game:
    ; Clean up GDI handles
    ; Delete brushes and pens
    xor ecx, ecx
.cleanup_gdi:
    cmp ecx, 8
    jae .cleanup_done
    push rcx
    lea rax, [rel hBrushes]
    mov rcx, [rax + rcx*8]
    call [rel p_DeleteObject]
    pop rcx
 
    push rcx
    lea rax, [rel hPens]
    mov rcx, [rax + rcx*8]
    call [rel p_DeleteObject]
    pop rcx
 
    inc ecx
    jmp .cleanup_gdi
.cleanup_done:

    mov rcx, [rel hdcMem]
    call [rel p_DeleteDC]
    mov rcx, [rel hbmMem]
    call [rel p_DeleteObject]
    mov rcx, [rel hwnd]
    mov rdx, [rel hdc]
    call [rel p_ReleaseDC]

    xor ecx, ecx
    add rsp, 40
    ret

; ==================== HELPER: SHOOT PROJECTILE ====================
shoot_projectile:
    ; rcx = targeted enemy base address
    push rbp
    mov rbp, rsp
    sub rsp, 32

    mov r8, rcx                 ; r8 = enemy address
    ; Find inactive projectile (index 80 to 99)
    mov edx, 80
.proj_loop:
    cmp edx, 100
    jae .done
    imul rsi, rdx, 28
    lea rax, [rel entities]
    add rsi, rax
    cmp byte [rsi + 16], 0      ; inactive?
    je .do_shoot
    inc edx
    jmp .proj_loop

.do_shoot:
    ; Set properties
    mov byte [rsi + 16], 6      ; Type = Player Projectile
    mov byte [rsi + 17], 1      ; HP = 1
    mov dword [rsi + 18], 120   ; Lifetime timer = 2 seconds

    ; Spawn at player X, Y
    mov eax, [rel entities + 0]
    mov [rsi + 0], eax
    mov eax, [rel entities + 4]
    mov [rsi + 4], eax

    ; Calculate direction vector to enemy (speed = 8)
    mov eax, [r8 + 0]           ; enemy X
    sub eax, [rel entities + 0] ; enemy X - player X
    mov ebx, [r8 + 4]           ; enemy Y
    sub ebx, [rel entities + 4] ; enemy Y - player Y

    mov r9d, eax
    cdq
    xor r9d, edx
    sub r9d, edx                ; abs(dx)

    mov r10d, ebx
    cdq
    xor r10d, edx
    sub r10d, edx               ; abs(dy)

    mov r11d, r9d
    cmp r10d, r9d
    cmovg r11d, r10d            ; max_dist

    test r11d, r11d
    jz .done

    ; vx = (dx * 8) / max_dist
    imul eax, 8
    cdq
    idiv r11d
    mov [rsi + 8], eax          ; vx

    ; vy = (dy * 8) / max_dist
    imul ebx, 8
    mov eax, ebx
    cdq
    idiv r11d
    mov [rsi + 12], eax         ; vy

.done:
    add rsp, 32
    pop rbp
    ret

; ==================== HELPER: SHOOT ENEMY PROJECTILE ====================
shoot_enemy_projectile:
    ; rcx = shooter enemy base address
    push rbp
    mov rbp, rsp
    sub rsp, 32

    mov r8, rcx                 ; r8 = shooter enemy address
    ; Find inactive projectile (index 80 to 99)
    mov edx, 80
.proj_loop:
    cmp edx, 100
    jae .done
    imul rsi, rdx, 28
    lea rax, [rel entities]
    add rsi, rax
    cmp byte [rsi + 16], 0      ; inactive?
    je .do_shoot
    inc edx
    jmp .proj_loop

.do_shoot:
    ; Set properties
    mov byte [rsi + 16], 7      ; Type = Enemy Projectile
    mov byte [rsi + 17], 1      ; HP = 1
    mov dword [rsi + 18], 180   ; Lifetime

    ; Spawn at shooter X, Y
    mov eax, [r8 + 0]
    mov [rsi + 0], eax
    mov eax, [r8 + 4]
    mov [rsi + 4], eax

    ; Calculate direction vector to player (speed = 5)
    mov eax, [rel entities + 0] ; player X
    sub eax, [r8 + 0]
    mov ebx, [rel entities + 4] ; player Y
    sub ebx, [r8 + 4]

    mov r9d, eax
    cdq
    xor r9d, edx
    sub r9d, edx                ; abs(dx)

    mov r10d, ebx
    cdq
    xor r10d, edx
    sub r10d, edx               ; abs(dy)

    mov r11d, r9d
    cmp r10d, r9d
    cmovg r11d, r10d            ; max_dist

    test r11d, r11d
    jz .done

    ; vx = (dx * 5) / max_dist
    imul eax, 5
    cdq
    idiv r11d
    mov [rsi + 8], eax          ; vx

    ; vy = (dy * 5) / max_dist
    imul ebx, 5
    mov eax, ebx
    cdq
    idiv r11d
    mov [rsi + 12], eax         ; vy

.done:
    add rsp, 32
    pop rbp
    ret

; ==================== HELPER: APPLY UPGRADE ====================
apply_upgrade:
    ; edx = upgrade index (0..4)
    cmp edx, 0
    je .up_speed
    cmp edx, 1
    je .up_damage
    cmp edx, 2
    je .up_cooldown
    cmp edx, 3
    je .up_proj
    cmp edx, 4
    je .up_shield
    ret

.up_speed:
    inc qword [rel player_speed]
    ret
.up_damage:
    inc byte [rel player_damage]
    ret
.up_cooldown:
    mov rax, [rel attack_cooldown_rate]
    imul rax, 4
    xor rdx, rdx
    mov r8, 5
    div r8                      ; rax = rax * 4/5
    mov [rel attack_cooldown_rate], rax
    ret
.up_proj:
    inc qword [rel extra_projectiles]
    ret
.up_shield:
    inc qword [rel shield_count]
    ret

; ==================== HELPER: TRIGGER LEVEL-UP CHOICES ====================
trigger_levelup_choices:
    push rbp
    mov rbp, rsp
    sub rsp, 32

    ; Choice 1
    call xorshift32
    xor edx, edx
    mov ecx, 5
    div ecx
    mov [rel upgrade_choice_1], edx

    ; Choice 2 (distinct)
.c2:
    call xorshift32
    xor edx, edx
    mov ecx, 5
    div ecx
    cmp edx, [rel upgrade_choice_1]
    je .c2
    mov [rel upgrade_choice_2], edx

    ; Choice 3 (distinct)
.c3:
    call xorshift32
    xor edx, edx
    mov ecx, 5
    div ecx
    cmp edx, [rel upgrade_choice_1]
    je .c3
    cmp edx, [rel upgrade_choice_2]
    je .c3
    mov [rel upgrade_choice_3], edx

    add rsp, 32
    pop rbp
    ret

; ==================== HELPER: ITOA ====================
itoa:
    push rdi
    push rbx
    mov rbx, 10
    xor ecx, ecx

    test eax, eax
    jnz .loop
    mov byte [rdi], '0'
    mov eax, 1
    jmp .done

.loop:
    test eax, eax
    jz .reverse
    xor edx, edx
    div rbx
    add dl, '0'
    push rdx
    inc ecx
    jmp .loop

.reverse:
    mov eax, ecx
.rev_loop:
    test ecx, ecx
    jz .done
    pop rdx
    mov [rdi], dl
    inc rdi
    dec ecx
    jmp .rev_loop
.done:
    pop rbx
    pop rdi
    ret

; ==================== HELPER: TEXT WRITER ====================
draw_lbl_val:
    ; rcx = x, rdx = y, r8 = lbl_ptr, r9 = lbl_len, [rsp+40] = val
    push rbp
    mov rbp, rsp
    sub rsp, 64

    mov [rbp - 8], rcx          ; x
    mov [rbp - 16], rdx         ; y
    mov [rbp - 32], r9          ; save lbl_len

    ; Draw Label
    mov rcx, [rel hdcMem]
    mov edx, [rbp - 8]          ; x
    mov [rsp + 32], r9          ; 5th param = lbl_len
    mov r9, r8                  ; 4th param = lbl_ptr
    mov r8d, [rbp - 16]         ; y
    call [rel p_TextOutA]

    ; Convert Value
    mov eax, [rbp + 56]         ; 6th parameter (val)
    lea rdi, [rbp - 48]         ; buffer on stack
    call itoa
    mov [rbp - 24], eax         ; length of number

    ; Draw Value
    mov ecx, [rbp - 32]         ; retrieve saved lbl_len
    imul ecx, 8                 ; offset for value
    add ecx, [rbp - 8]          ; x + offset
    mov edx, ecx                ; x
    mov r8d, [rbp - 16]         ; y
    lea r9, [rbp - 48]          ; val string
    mov eax, [rbp - 24]         ; val length
    mov [rsp + 32], rax         ; 5th param = val length
    mov rcx, [rel hdcMem]
    call [rel p_TextOutA]

    add rsp, 64
    pop rbp
    ret

; ==================== RENDER FRAME ====================
render_frame:
    push rbp
    mov rbp, rsp
    sub rsp, 48

    ; 1. Clear memory DC to black
    mov rcx, [rel hdcMem]
    xor edx, edx
    xor r8d, r8d
    mov r9d, 800
    mov dword [rsp + 32], 600
    mov dword [rsp + 40], 0x00000042 ; BLACKNESS
    call [rel p_PatBlt]

    ; 2. Draw Entities
    mov ecx, 1
.draw_loop:
    cmp ecx, 100
    jae .draw_done
    imul rsi, rcx, 28
    lea rax, [rel entities]
    add rsi, rax
    mov al, [rsi + 16]          ; type
    test al, al
    jz .next_draw

    push rcx
    ; Get brush and pen color index based on type
    ; Color index: 0=White, 1=Red, 2=Green, 3=Blue, 4=Yellow, 5=Magenta, 6=Orange, 7=Black
    mov edx, 0                  ; default White
    cmp al, 2
    je .c_red
    cmp al, 3
    je .c_blue
    cmp al, 4
    je .c_yellow
    cmp al, 5
    je .c_magenta
    cmp al, 6
    je .c_white
    cmp al, 7
    je .c_orange
    jmp .apply_color
.c_red:     mov edx, 1; jmp .apply_color
.c_blue:    mov edx, 3; jmp .apply_color
.c_yellow:  mov edx, 4; jmp .apply_color
.c_magenta: mov edx, 5; jmp .apply_color
.c_white:   mov edx, 0; jmp .apply_color
.c_orange:  mov edx, 6; jmp .apply_color

.apply_color:
    mov rcx, [rel hdcMem]
    lea rax, [rel hBrushes]
    mov rdx, [rax + rdx*8]
    call [rel p_SelectObject]

    pop rcx
    push rcx
    mov edx, 0                  ; default white pen
    cmp al, 2
    je .p_red
    cmp al, 3
    je .p_blue
    cmp al, 4
    je .p_yellow
    cmp al, 5
    je .p_magenta
    cmp al, 6
    je .p_white
    cmp al, 7
    je .p_orange
    jmp .apply_pen
.p_red:     mov edx, 1; jmp .apply_pen
.p_blue:    mov edx, 3; jmp .apply_pen
.p_yellow:  mov edx, 4; jmp .apply_pen
.p_magenta: mov edx, 5; jmp .apply_pen
.p_white:   mov edx, 0; jmp .apply_pen
.p_orange:  mov edx, 6; jmp .apply_pen

.apply_pen:
    mov rcx, [rel hdcMem]
    lea rax, [rel hPens]
    mov rdx, [rax + rdx*8]
    call [rel p_SelectObject]

    pop rcx
    mov al, [rsi + 16]          ; restore type
    cmp al, 6
    jge .draw_line_type

    ; Draw shape (circle/rectangle)
    mov r8d, [rsi + 0]          ; X
    mov r9d, [rsi + 4]          ; Y
    mov r10d, 8                 ; radius default (enemies)
    cmp al, 3
    jne .not_t
    mov r10d, 15                ; larger tank radius
.not_t:
    cmp al, 4
    jne .not_run
    mov r10d, 6                 ; smaller runner radius
.not_run:
    ; Ellipse/Rectangle calculations
    mov edx, r8d
    sub edx, r10d               ; Left
    mov ebx, r9d
    sub ebx, r10d               ; Top
    mov r8d, r8d
    add r8d, r10d               ; Right
    mov r9d, r9d
    add r9d, r10d               ; Bottom

    push rcx
    sub rsp, 40
    mov rcx, [rel hdcMem]
    mov [rsp + 32], r9d         ; Bottom
    mov r9d, r8d                ; Right
    mov r8d, ebx                ; Top
    ; edx is already Left
    cmp byte [rsi + 16], 2      ; Basic enemy -> Rectangle
    je .do_rect
    cmp byte [rsi + 16], 3      ; Tank -> Rectangle
    je .do_rect
    cmp byte [rsi + 16], 4      ; Runner -> Rectangle
    je .do_rect
    cmp byte [rsi + 16], 5      ; Shooter -> Rectangle
    je .do_rect

    call [rel p_Ellipse]
    jmp .shape_done
.do_rect:
    call [rel p_Rectangle]
.shape_done:
    add rsp, 40
    pop rcx
    jmp .next_draw

.draw_line_type:
    ; Projectile: Line
    mov r8d, [rsi + 0]          ; X
    mov r9d, [rsi + 4]          ; Y
    mov r10d, [rsi + 8]         ; vx
    mov r11d, [rsi + 12]        ; vy

    mov edx, r8d
    sub edx, r10d               ; X - vx
    mov ebx, r9d
    sub ebx, r11d               ; Y - vy

    push rcx
    mov rcx, [rel hdcMem]
    mov r8d, ebx
    xor r9d, r9d                ; NULL
    call [rel p_MoveToEx]

    mov rcx, [rel hdcMem]
    mov edx, [rsi + 0]          ; X
    mov r8d, [rsi + 4]          ; Y
    call [rel p_LineTo]
    pop rcx

.next_draw:
    inc ecx
    jmp .draw_loop
.draw_done:

    ; Draw Player (type = 1) at index 0 (select green color 2)
    lea rsi, [rel entities]
    mov rcx, [rel hdcMem]
    lea rax, [rel hBrushes]
    mov rdx, [rax + 2*8]

    call [rel p_SelectObject]
    mov rcx, [rel hdcMem]
    lea rax, [rel hPens]
    mov rdx, [rax + 2*8]
    call [rel p_SelectObject]

    mov r8d, [rsi + 0]          ; X
    mov r9d, [rsi + 4]          ; Y
    mov edx, r8d
    sub edx, 10
    mov ebx, r9d
    sub ebx, 10
    add r8d, 10
    add r9d, 10

    sub rsp, 48
    mov rcx, [rel hdcMem]
    mov r10d, r9d
    mov r9d, r8d
    mov r8d, ebx
    mov [rsp + 32], r10d
    call [rel p_Ellipse]
    add rsp, 48

    ; Draw player shield indicator if shield_count > 0
    mov rax, [rel shield_count]
    test rax, rax
    jz .skip_shield_draw

    ; Select light blue/white pen
    mov rcx, [rel hdcMem]
    lea rax, [rel hPens]
    mov rdx, [rax + 0*8]        ; White
    call [rel p_SelectObject]
    ; Hollow brush
    mov rcx, [rel hdcMem]
    lea rax, [rel hBrushes]
    mov rdx, [rax + 7*8]        ; Black / Hollow
    call [rel p_SelectObject]

    mov r8d, [rsi + 0]
    mov r9d, [rsi + 4]
    mov edx, r8d
    sub edx, 16
    mov ebx, r9d
    sub ebx, 16
    add r8d, 16
    add r9d, 16

    sub rsp, 48
    mov rcx, [rel hdcMem]
    mov r10d, r9d
    mov r9d, r8d
    mov r8d, ebx
    mov [rsp + 32], r10d
    call [rel p_Ellipse]
    add rsp, 48
.skip_shield_draw:

    ; 3. Draw Text HUD
    mov rcx, [rel hdcMem]
    mov edx, 0x00FFFFFF         ; Text color white
    call [rel p_SetTextColor]

    mov rcx, [rel hdcMem]
    mov edx, 1                  ; Background TRANSPARENT
    call [rel p_SetBkMode]

    ; Score
    sub rsp, 48
    mov rcx, 10                 ; X
    mov rdx, 10                 ; Y
    lea r8, [rel score_lbl]
    mov r9d, 7                  ; lbl_len
    mov rax, [rel score]        ; val
    mov [rsp + 32], r8
    mov [rsp + 40], rax
    call draw_lbl_val
    add rsp, 48



    ; Wave
    sub rsp, 48
    mov rcx, 350
    mov rdx, 10
    lea r8, [rel wave_lbl]
    mov r9d, 6
    mov rax, [rel wave]
    mov [rsp + 32], r8
    mov [rsp + 40], rax
    call draw_lbl_val
    add rsp, 48

    ; Level
    sub rsp, 48
    mov rcx, 650
    mov rdx, 10
    lea r8, [rel level_lbl]
    mov r9d, 7
    mov rax, [rel level]
    mov [rsp + 32], r8
    mov [rsp + 40], rax
    call draw_lbl_val
    add rsp, 48

    ; HP
    sub rsp, 48
    mov rcx, 10
    mov rdx, 550
    lea r8, [rel hp_lbl]
    mov r9d, 4
    movzx rax, byte [rel entities + 17] ; HP at index 0
    mov [rsp + 32], r8
    mov [rsp + 40], rax
    call draw_lbl_val
    add rsp, 48

    ; Shield
    sub rsp, 48
    mov rcx, 150
    mov rdx, 550
    lea r8, [rel shield_lbl]
    mov r9d, 8
    mov rax, [rel shield_count]
    mov [rsp + 32], r8
    mov [rsp + 40], rax
    call draw_lbl_val
    add rsp, 48

    ; 4. Level-up Screen
    mov rax, [rel game_state]
    cmp rax, 1
    jne .skip_levelup_draw

    ; Draw central dialog box
    mov rcx, [rel hdcMem]
    lea rax, [rel hBrushes]
    mov rdx, [rax + 7*8]        ; Black
    call [rel p_SelectObject]
    mov rcx, [rel hdcMem]
    lea rax, [rel hPens]
    mov rdx, [rax + 0*8]        ; White
    call [rel p_SelectObject]

    sub rsp, 48
    mov rcx, [rel hdcMem]
    mov edx, 200
    mov r8d, 120
    mov r9d, 600
    mov dword [rsp + 32], 480
    call [rel p_Rectangle]
    add rsp, 48

    ; Print headers
    mov rcx, [rel hdcMem]
    mov edx, 250
    mov r8d, 150
    lea r9, [rel levelup_hdr]
    mov qword [rsp + 32], 26    ; length
    call [rel p_TextOutA]

    ; Print Choice 1
    mov rcx, [rel hdcMem]
    mov edx, 250
    mov r8d, 220
    lea r9, [rel choice1_prefix]
    mov qword [rsp + 32], 3
    call [rel p_TextOutA]

    mov ebx, [rel upgrade_choice_1]
    lea rax, [rel opt_strings]
    mov rsi, [rax + rbx*8]
    ; Find length of option string
    mov rdi, rsi
    xor eax, eax
.opt1_len:
    cmp byte [rdi + rax], 0
    je .opt1_len_done
    inc rax
    jmp .opt1_len
.opt1_len_done:
    mov rcx, [rel hdcMem]
    mov edx, 280
    mov r8d, 220
    mov r9, rsi
    mov [rsp + 32], rax
    call [rel p_TextOutA]

    ; Print Choice 2
    mov rcx, [rel hdcMem]
    mov edx, 250
    mov r8d, 280
    lea r9, [rel choice2_prefix]
    mov qword [rsp + 32], 3
    call [rel p_TextOutA]

    mov ebx, [rel upgrade_choice_2]
    lea rax, [rel opt_strings]
    mov rsi, [rax + rbx*8]
    mov rdi, rsi
    xor eax, eax
.opt2_len:
    cmp byte [rdi + rax], 0
    je .opt2_len_done
    inc rax
    jmp .opt2_len
.opt2_len_done:
    mov rcx, [rel hdcMem]
    mov edx, 280
    mov r8d, 280
    mov r9, rsi
    mov [rsp + 32], rax
    call [rel p_TextOutA]

    ; Print Choice 3
    mov rcx, [rel hdcMem]
    mov edx, 250
    mov r8d, 340
    lea r9, [rel choice3_prefix]
    mov qword [rsp + 32], 3
    call [rel p_TextOutA]

    mov ebx, [rel upgrade_choice_3]
    lea rax, [rel opt_strings]
    mov rsi, [rax + rbx*8]
    mov rdi, rsi
    xor eax, eax
.opt3_len:
    cmp byte [rdi + rax], 0
    je .opt3_len_done
    inc rax
    jmp .opt3_len
.opt3_len_done:
    mov rcx, [rel hdcMem]
    mov edx, 280
    mov r8d, 340
    mov r9, rsi
    mov [rsp + 32], rax
    call [rel p_TextOutA]

    ; Print Press 1, 2, 3 footer
    mov rcx, [rel hdcMem]
    mov edx, 250
    mov r8d, 420
    lea r9, [rel choice_footer]
    mov qword [rsp + 32], 19
    call [rel p_TextOutA]

.skip_levelup_draw:

    ; 5. Game Over Screen
    mov rax, [rel game_state]
    cmp rax, 2
    jne .skip_gameover_draw

    ; Draw central dialog box
    mov rcx, [rel hdcMem]
    lea rax, [rel hBrushes]
    mov rdx, [rax + 7*8]        ; Black
    call [rel p_SelectObject]
    mov rcx, [rel hdcMem]
    lea rax, [rel hPens]
    mov rdx, [rax + 1*8]        ; Red border
    call [rel p_SelectObject]

    sub rsp, 48
    mov rcx, [rel hdcMem]
    mov edx, 200
    mov r8d, 150
    mov r9d, 600
    mov dword [rsp + 32], 400
    call [rel p_Rectangle]
    add rsp, 48

    ; Print GAME OVER
    mov rcx, [rel hdcMem]
    mov edx, 340
    mov r8d, 200
    lea r9, [rel gameover_hdr]
    mov qword [rsp + 32], 9
    call [rel p_TextOutA]

    ; Print Final Score
    sub rsp, 48
    mov rcx, 300
    mov rdx, 270
    lea r8, [rel gameover_score]
    mov r9d, 13
    mov rax, [rel score]
    mov [rsp + 32], r8
    mov [rsp + 40], rax
    call draw_lbl_val
    add rsp, 48

    ; Print footer
    mov rcx, [rel hdcMem]
    mov edx, 290
    mov r8d, 340
    lea r9, [rel gameover_footer]
    mov qword [rsp + 32], 21
    call [rel p_TextOutA]

.skip_gameover_draw:

    ; Present double buffer on screen
    sub rsp, 80
    mov rcx, [rel hdc]
    xor edx, edx
    xor r8d, r8d
    mov r9d, 800
    mov dword [rsp + 32], 600
    mov rax, [rel hdcMem]
    mov [rsp + 40], rax
    mov dword [rsp + 48], 0
    mov dword [rsp + 56], 0
    mov dword [rsp + 64], 0x00CC0020 ; SRCCOPY
    call [rel p_BitBlt]
    add rsp, 80



    add rsp, 48
    pop rbp
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

    mov eax, [r9 + 136]         ; eax = Export Directory RVA
    test eax, eax
    jz .not_found
    lea r10, [rbx + rax]        ; r10 = Export Directory

    mov r11d, [r10 + 0x18]      ; r11d = NumberOfNames
    mov edi, [r10 + 0x20]       ; edi = AddressOfNames RVA
    lea r9, [rbx + rdi]         ; r9 = AddressOfNames absolute

    xor ecx, ecx                ; ecx = Name Index
.loop:
    cmp ecx, r11d
    jae .not_found

    mov edi, [r9 + rcx*4]      ; edi = Name RVA
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

; ==================== RNG: XORSHIFT32 ====================
xorshift32:
    mov eax, [rel rng_state]
    mov ecx, eax
    shl ecx, 13
    xor eax, ecx
    mov ecx, eax
    shr ecx, 17
    xor eax, ecx
    mov ecx, eax
    shl ecx, 5
    xor eax, ecx
    mov [rel rng_state], eax
    ret

; ==================== DATA SECTION ====================
align 8
ntdll_base:         dq 0
kernel32_base:      dq 0
user32_base:        dq 0
gdi32_base:         dq 0
hwnd:               dq 0
hdc:                dq 0
hdcMem:             dq 0
hbmMem:             dq 0

p_LdrLoadDll:       dq 0
p_Sleep:            dq 0
p_RegisterClassA:   dq 0
p_CreateWindowExA:  dq 0
p_DefWindowProcA:   dq 0
p_PeekMessageA:     dq 0
p_TranslateMessage: dq 0
p_DispatchMessageA: dq 0
p_GetDC:            dq 0
p_ReleaseDC:        dq 0
p_GetAsyncKeyState: dq 0
p_PostQuitMessage:  dq 0
p_ShowCursor:       dq 0

p_CreateCompatibleDC:     dq 0
p_CreateCompatibleBitmap: dq 0
p_SelectObject:           dq 0
p_DeleteObject:           dq 0
p_DeleteDC:               dq 0
p_PatBlt:                 dq 0
p_CreateSolidBrush:       dq 0
p_CreatePen:              dq 0
p_Rectangle:              dq 0
p_Ellipse:                dq 0
p_MoveToEx:               dq 0
p_LineTo:                 dq 0
p_SetTextColor:           dq 0
p_SetBkMode:              dq 0
p_TextOutA:               dq 0
p_BitBlt:                 dq 0

cycles_per_frame:   dq 50000000 ; default
frame_start:        dq 0
rng_state:          dd 1

game_running:       dq 1
game_state:         dq 0        ; 0=Play, 1=Level-up, 2=Game Over

score:              dq 0
level:              dq 1
kills:              dq 0
wave:               dq 1

player_speed:       dq 4
player_damage:      db 1
attack_cooldown_rate: dq 30
extra_projectiles:  dq 0
shield_count:       dq 0

wave_timer:         dq 1800     ; 30s at 60fps
spawn_timer:        dq 0
spawn_cooldown:     dq 60       ; 1s default spawn rate

upgrade_choice_1:   dd 0
upgrade_choice_2:   dd 0
upgrade_choice_3:   dd 0

class_name:         db 'AscendClass', 0
window_name:        db 'Ascend', 0

; GDI Colors Array (COLORREF 0x00BBGGRR)
colors:
    dd 0x00FFFFFF               ; 0: White (HUD / projectiles)
    dd 0x000000FF               ; 1: Red (Basic enemy / UI border)
    dd 0x0000FF00               ; 2: Green (Player)
    dd 0x00FF0000               ; 3: Blue (Tank enemy)
    dd 0x0000FFFF               ; 4: Yellow (Runner enemy)
    dd 0x00FF00FF               ; 5: Magenta (Shooter enemy)
    dd 0x0000A5FF               ; 6: Orange (Enemy projectiles)
    dd 0x00000000               ; 7: Black (Background / UI panels)

score_lbl:          db 'SCORE: '
wave_lbl:           db 'WAVE: '
level_lbl:          db 'LEVEL: '
hp_lbl:             db 'HP: '
shield_lbl:         db 'SHIELD: '

levelup_hdr:        db 'LEVEL UP! SELECT UPGRADE:'
choice1_prefix:     db '1: '
choice2_prefix:     db '2: '
choice3_prefix:     db '3: '
choice_footer:      db 'PRESS KEY 1, 2 OR 3'

opt_speed:          db 'SPEED UP (+1)', 0
opt_damage:         db 'DAMAGE UP (+1)', 0
opt_cooldown:       db 'ATTACK COOLDOWN (-20%)', 0
opt_proj:           db 'EXTRA PROJECTILE (+1)', 0
opt_shield:         db 'SHIELD BARRIER (+1)', 0

gameover_hdr:       db 'GAME OVER'
gameover_score:     db 'FINAL SCORE: '
gameover_footer:    db 'PRESS ESC KEY TO EXIT'

; Unicode strings for DLL loading
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

; Pad code section to exactly 8192 bytes on disk (making total file 8192 bytes)
    times 8192 - ($ - $$) db 0

; ==================== BSS SECTION (VIRTUAL ONLY, ZEROES) ====================
; Memory mapping from 8192 onwards in memory (starts at RVA 0x2000)
section .bss
wndclass:           resb 72
msg:                resb 48
hBrushes:           resq 8
hPens:              resq 8
opt_strings:        resq 5
entities:           resb 100 * 28
