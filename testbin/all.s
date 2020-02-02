global _start
section .text

_start:

add rax, 1
add r12, 1
xor rbx, 1
xor r12, 1

mov rax, 0xdeadbeef
mov rax, 0xdeadbeefdead
mov rax, 0xdeadbeefdeadbeef
mov rax, 0xabcdef012345678
mov rax, rax
mov rax, rbx
mov rbx, rax
mov rax, 1
mov r12, 1
mov r12, 2
mov r12, 0xdeadbeef
mov r12, r8
mov r12, r9
mov rax, r12
mov r12, rax

section .data
msg: db '7'
