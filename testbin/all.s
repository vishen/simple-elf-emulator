global _start
section .text

_start:

mov rbx, [msg]
mov rax, [msg]
add rbx, 1
mov [msg], rbx

mov rax, 1
mov rdi, 1
mov rsi, msg
mov rdx, 1
syscall

mov rax, 60
xor rdi, rdi
syscall

section .data
msg: db '7'
