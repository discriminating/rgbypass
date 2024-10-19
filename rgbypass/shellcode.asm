.model flat, stdcall

.code
PUBLIC SHELLCODE

SHELLCODE PROC

    NOP
    PUSH 0
    PUSH 0
    PUSH 00FFFFFFh  ; Address of the DLL path
    MOV EAX, 00000000h  ; Address of LoadLibraryExA
    CALL EAX
    RET

SHELLCODE ENDP

END
