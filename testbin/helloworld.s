global    _start

section   .text
_start:   mov       rax, 1                  ; system call for write
          mov       rdi, 1                  ; file handle 1 is stdout
          mov       rsi, message            ; address of string to output
          mov       rdx, 14                 ; number of bytes
          syscall                           ; invoke operating system to do the write
		  mov       rax, 1                  ; system call for write
          mov       rdi, 1                  ; file handle 1 is stdout
          mov       rsi, message1            ; address of string to output
          mov       rdx, 16                 ; number of bytes
          syscall                           ; invoke operating system to do the write
          mov       rsi, message2            ; address of string to output
          mov       rdx, 16                 ; number of bytes
          syscall                           ; invoke operating system to do the write
          mov       rax, 60                 ; system call for exit
          mov       rdi, 104                ; exit code 0
          syscall                           ; invoke operating system to exit

          section   .data
message:  db        "Hello, Worldy", 10      ; note the newline at the end
message1:  db        "Hello, Jonathan", 10      ; note the newline at the end
message2:  db        "Hello, Computer", 10      ; note the newline at the end
