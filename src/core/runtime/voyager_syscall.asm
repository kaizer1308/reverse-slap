.CODE

; NTSTATUS do_syscall_4(uint32_t ssn /*rcx*/, uint8_t* stub /*rdx*/,
;                       uint64_t a1 /*r8*/, uint64_t a2 /*r9*/,
;                       uint64_t a3 /*[rsp+28h]*/, uint64_t a4 /*[rsp+30h]*/)
; Executes `syscall` via the supplied ntdll stub (`syscall; ret`), so the
; stub's `ret` returns straight to our caller with the NTSTATUS in eax.
PUBLIC do_syscall_4
do_syscall_4 PROC
    mov     eax, ecx            ; eax = syscall number
    mov     r11, rdx            ; r11 = stub address (volatile, syscall-safe)
    mov     r10, r8             ; win64 syscalls take arg1 in r10
    mov     rdx, r9             ; arg2
    mov     r8,  qword ptr [rsp+28h]  ; arg3
    mov     r9,  qword ptr [rsp+30h]  ; arg4
    mov     rcx, r10            ; parity: some stubs/probes inspect rcx
    jmp     r11                 ; syscall; ret -> back to our caller
do_syscall_4 ENDP

END
