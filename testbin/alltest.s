global _start
section .text

_start:

mov rax, 1
mov rbx, 1
mov rax, rbx
mov rbx, [msg]
mov rax, [msg]
mov [msg], rax

section .data
msg: db '7'
