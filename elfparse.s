# elfparse.s - GNU ELF64 Parser
#
# Usage: elfparse [file]
#
# (C) Copyright 2024 Travis Montoya <trav@hexproof.sh>
#
# This program is free software: you can redistribute it and/or modify it under 
# the terms of the GNU General Public License as published by the Free Software 
# Foundation, either version 3 of the License, or (at your option) any later 
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT 
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS 
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along with 
# this program. If not, see <https://www.gnu.org/licenses/>.

# ------------ Constants ------------

.set STDOUT,     1
.set O_RDONLY,   0

# syscalls
.set __NR_read,  0
.set __NR_write, 1
.set __NR_open,  2
.set __NR_close, 3
.set __NR_fstat, 5
.set __NR_lseek, 8
.set __NR_exit,  60

# ELF constants
.set EI_MAG0,        0
.set ELFMAG0,        0x7f
.set EI_MAG1,        1
.set ELFMAG1,        'E'
.set EI_MAG2,        2
.set ELFMAG2,        'L'
.set EI_MAG3,        3
.set ELFMAG3,        'F'

.set EI_CLASS,       4         # File class byte index
.set ELFCLASSNONE,   0         # Invalid class
.set ELFCLASS32,     1         # 32-bit objects
.set ELFCLASS64,     2         # 64-bit objects

.set EI_DATA,        5         # Data encoding byte index
.set ELFDATANONE,    0         # Invalid data encoding
.set ELFDATA2LSB,    1         # 2's complement, little endian
.set ELFDATA2MSB,    2         # 2's complement, big endian
.set ELFDATANUM,     3

.set EI_VERSION,     6         # File version byte index

.set EI_OSABI,       7
.set ELFOSABI_NONE,  0
.set ELFOSABI_GNU,   3
.set ELFOSABI_LINUX, 3

.set EI_ABIVERSION,  8

.set ET_REL,         1
.set ET_EXEC,        2
.set ET_DYN,         3

# ------------ ELF Structures ------------
 
.struct 0
elf64_ehdr:
    .struct elf64_ehdr
    e_ident:        .space 16
    e_type:         .space 2
    e_machine:      .space 2
    e_version:      .space 4
    e_entry:        .space 8
    e_phoff:        .space 8
    e_shoff:        .space 8
    e_flags:        .space 4
    e_ehsize:       .space 2
    e_phentsize:    .space 2
    e_phnum:        .space 2
    e_shentsize:    .space 2
    e_shnum:        .space 2
    e_shstrndx:     .space 2
    .align 8
elf64_ehdr_size:

.struct 0
elf64_phdr:
    .struct elf64_phdr
    p_type:         .space 4
    p_flags:        .space 4
    p_offset:       .space 8
    p_vaddr:        .space 8
    p_paddr:        .space 8
    p_filesz:       .space 8
    p_memsz:        .space 8
    p_align:        .space 8
    .align 8
elf64_phdr_size:

.struct 0
elf64_shdr:
    .struct elf64_shdr
    sh_name:        .space 4
    sh_type:        .space 4
    sh_flags:       .space 8
    sh_addr:        .space 8
    sh_offset:      .space 8
    sh_size:        .space 8
    sh_link:        .space 4
    sh_info:        .space 4
    sh_addralign:   .space 8
    sh_entsize:     .space 8
    .align 8
elf64_shdr_size:

# ------------ Data ------------
    .section .data

elfparse_usage:
    .ascii "GNU ELF64 Parser\n"
    .ascii "usage: elfparse [file]\n\0"


elfparse_verify_valid:
    .ascii "Binary is a valid 64-BIT ELF file\n\0"

# Errors
elfparse_invalid_file:
    .ascii "Error: Unable to open file\n\0"

elfverify_read_error:
    .ascii "Error: Unable to read ELF64 header\n\0"

    .section .bss
    .align 8

ehdr:
    .space elf64_ehdr_size

phdr:
    .space elf64_phdr_size

shdr:
    .space elf64_shdr_size

elfobj: 
    .quad 0

# ------------ Text ------------
    .globl _start
    .section .text

_start:
    mov    (%rsp), %rbx         # %rsp = argc
    cmp    $2, %rbx             # We should have atleast 1 command line arg
    jl     .L_elfparse_usage 

.L_elfparse_args:
    # We only need the first argument which specifies a file name to parse
    # this puts the address of argv[1] in %rdi
    mov    16(%rsp), %rdi
    
    # __NR_open
    mov    $O_RDONLY, %rsi
    mov    $0, %rdx
    mov    $__NR_open, %rax
    syscall

    cmp   $0, %rax
    jl    .L_elfparse_error

    mov   %rax, elfobj

    # Verify that the file is a 64-bit ELF file
    mov    %rax, %rdi          # Move the handle into %rdi
    call   verify_elf64_file
    cmp    $0, %rax
    jne    .L_elfparse_verify_error

    jmp    .L_elfparse_exit
.L_elfparse_error:
    lea    elfparse_invalid_file, %rdi
    call   print_str
    jmp    .L_elfparse_exit

.L_elfparse_verify_error:
    lea    elfverify_read_error, %rdi
    call   print_str
    jmp    .L_elfparse_exit

.L_elfparse_usage:
    lea    elfparse_usage, %rdi
    call   print_str
   
.L_elfparse_exit:
    # Call the exit syscall
    # exit(0)
    xor    %rdi, %rdi
    mov    $__NR_exit, %rax
    syscall
  
# ------------ Elf Parser Functions  ------------ 
print_str:
   # Print a string to STDOUT = 1
   # %rdi holds the address of the string
   #
   # We need to find the length of the string first and then print using
   # syscall __NR_write (sys_write) 
   xor     %rcx, %rcx
.L_strlen:
   movb    (%rdi, %rcx), %al
   test    %al, %al
   jz      .L_write
   inc     %rcx
   jmp     .L_strlen
.L_write:
   # At this point %rcx holds the length of the null terminated string
   mov     %rcx, %rdx
   mov     %rdi, %rsi
   mov     $STDOUT, %rdi
   mov     $__NR_write, %rax
   syscall
   ret

verify_elf64_file:
   # We will read in the ehdr and verify portions of e_ident
   # %rdi contains our file handle
   mov     %rdi, %rbx
   lea     ehdr, %rsi
   mov     $elf64_ehdr_size, %rdx
   mov     $__NR_read, %rax   
   syscall

   cmp     $elf64_ehdr_size, %rax
   jne     .L_verify_error

   # Verify magic bytes "\177ELF"
   lea     ehdr, %rcx
   cmpb    $ELFMAG0, elf64_ehdr + e_ident + EI_MAG0(%rcx)
   jne     .L_verify_error
   cmpb    $ELFMAG1, elf64_ehdr + e_ident + EI_MAG1(%rcx)
   jne     .L_verify_error
   cmpb    $ELFMAG2, elf64_ehdr + e_ident + EI_MAG2(%rcx)
   jne     .L_verify_error
   cmpb    $ELFMAG3, elf64_ehdr + e_ident + EI_MAG3(%rcx)
   jne     .L_verify_error

   # This is an ELF64 utility that uses ELF64 headers so
   # we need to make sure this is ELFCLASS64
   cmpb    $ELFCLASS64, elf64_ehdr + e_ident + EI_CLASS(%rcx)
   jne     .L_verify_error

   lea     elfparse_verify_valid, %rdi
   call    print_str
   mov     $0, %rax
   ret
.L_verify_error:
   mov     $-1, %rax
   ret
