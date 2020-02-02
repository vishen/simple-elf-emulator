global _start

section .text

_start:
mov rax, 1
mov rdi, 2
mov rsi, msg
mov rdx, 1
syscall

mov rax, 60
xor rdi, rdi
syscall

section .data
msg: db '7'
