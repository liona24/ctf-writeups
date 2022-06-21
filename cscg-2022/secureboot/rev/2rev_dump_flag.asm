[bits 16]
[org 0x7c00]

    ; read disk
    mov ax, 0x0202
    xor cx, cx
    inc cl
    ; mov cl, 0x01 ; start at sector 1
    ; mov ch, 0x00 ; cylinder 0
    ; xor dh, dh ; head 0
    mov dx, 0x0082
    ; mov dl, 0x80    ; first drive
    ; mov dl, 0x81    ; secnd drive
    ; mov dl, 0x82    ; third drive

    mov bx, 0x9000  ; load disk at 0x9000
    int 0x13      ; BIOS interrupt, read disk

dump:
    ; Put 0x0e to ah, which stands for "Write Character in TTY mode" when issuing a BIOS Video Services interrupt 0x10
    mov ah, 0x0e
    mov si, bx
    ; Dump 0x100 bytes flat
    mov bx, 0x100
dump_loop:
    ; Load byte at address si to al
    lodsb

    dec bx
    je halt

    ; Issue a BIOS interrupt 0x10 for video services
    int 0x10
    jne dump_loop

halt:
    hlt
    je halt

; Fill remaining space of the 512 bytes minus our instrunctions, with 00 bytes
; $ - address of the current instruction
; $$ - address of the start of the image .text section we're executing this code in
times 510 - ($-$$) db 0
; Bootloader magic number
dw 0xaa55
