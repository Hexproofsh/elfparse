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

.set STDOUT,         1
.set O_RDONLY,       0

.set SYS_MMAP,       9
.set PROT_READ,      1
.set PROT_WRITE,     2
.set MAP_PRIVATE,    2
.set MAP_ANONYMOUS,  0x20

# syscalls
.set __NR_read,      0
.set __NR_write,     1
.set __NR_open,      2
.set __NR_close,     3
.set __NR_fstat,     5
.set __NR_lseek,     8
.set __NR_mmap,      9
.set __NR_munmap,    11
.set __NR_exit,      60

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
.set ELFOSABI_NETBSD, 2 
.set ELFOSABI_FREEBSD, 9
.set ELFOSABI_OPENBSD, 12
.set ELFOSABI_GNU,   3
.set ELFOSABI_LINUX, 3

.set EI_ABIVERSION,  8

.set ET_NONE,        0
.set ET_REL,         1
.set ET_EXEC,        2
.set ET_DYN,         3
.set ET_CORE,        4

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

# ------------ Initialized data ------------
    .section .data

elfparse_usage:
    .ascii "GNU ELF64 Parser\n"
    .asciz "usage: elfparse [file]\n"

elfparse_verify_valid:
    .asciz "Binary is a valid 64-BIT ELF file\n"

# ELF parser output messages
elfparse_str_ehdr:   .asciz "\nELF Header:\n"
elfparse_str_entry:  .asciz "  Entry Point: 0x"
elfparse_str_type:   .asciz "\n  Type: "
elfparse_str_class:  .asciz "\n  Class: "
elfparse_str_data:   .asciz "\n  Data: "
elfparse_str_abi:    .asciz "\n  ABI: "
elfparse_str_abiver: .asciz "\n  ABI Version: "
elfparse_str_filever: .asciz "\n  File Version: "
elfparse_str_phdroff: .asciz "\n  Program header offset: 0x"
elfparse_str_shdroff: .asciz "\n  Section header offset: 0x"
elfparse_str_ehdrsiz: .asciz "\n  ELF header size (bytes): "
elfparse_str_phdrsiz: .asciz "\n  Program header size (bytes): "
elfparse_str_phdrcnt: .asciz "\n  Program header count: "
elfparse_str_shdrsiz:  .asciz "\n  Section header size (bytes): "
elfparse_str_shdrcnt:  .asciz "\n  Section header count: "
elfparse_str_shdrstrtbl: .asciz "\n  Section header string table index: "

elfparse_str_abi_none:    .asciz "UNIX System V ABI"
elfparse_str_abi_netbsd:  .asciz "NetBSD"
elfparse_str_abi_linux:   .asciz "GNU\Linux"
elfparse_str_abi_freebsd: .asciz "FreeBSD"
elfparse_str_abi_openbsd: .asciz "OpenBSD"

elfparse_str_data_none:   .asciz "Invalid data encoding"
elfparse_str_data_2LSB:   .asciz "2's complement, little endian"
elfparse_str_data_2MSB:   .asciz "2's complement, big endian"

elfparse_str_class_32:    .asciz "ELF32"
elfparse_str_class_64:    .asciz "ELF64"
elfparse_str_class_none:  .asciz "Invalid type"

elfparse_str_type_none: .asciz "No file type"
elfparse_str_type_rel:  .asciz "Relocatable file"
elfparse_str_type_exec: .asciz "Executable file"
elfparse_str_type_dyn:  .asciz "Shared object file"
elfparse_str_type_core: .asciz "Core file"
elfparse_str_type_unkn: .asciz "Unknown"

# Errors
elfparse_invalid_file:
    .asciz "Error: Unable to open file\n"

elfverify_read_error:
    .asciz "Error: Unable to read ELF64 header\n"

# These are initialized in .bss
.lcomm ehdr, elf64_ehdr_size
.lcomm phdr, elf64_phdr_size
.lcomm phdr_size, 8
.lcomm shdr, elf64_shdr_size
.lcomm shdr_size, 8

.lcomm elfobj, 8
.lcomm hexbuff, 16
.lcomm intbuff, 21

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
    #
    # This will iterate through all the functions to parse and print the
    # elf headers. See functions section for more information.
    mov    16(%rsp), %rdi

    call   load_elf64_file
    cmp    $0, %rax
    jne    .L_elfparse_error

    # Print ehdr
    call   parse_elf64_ehdr

.L_elfparse_exit:
    mov    phdr, %r10
    test   %r10, %r10
    jz     .L_exit_next
    mov    phdr, %rdi
    mov    phdr_size, %rsi
    mov    $__NR_munmap, %rax
    syscall
.L_exit_next:
    mov    shdr, %r10
    test   %r10, %r10
    jz     .L_exit_final
    mov    shdr, %rdi
    mov    shdr_size, %rsi
    mov    $__NR_munmap, %rax
    syscall
.L_exit_final: 
    # Call the exit syscall
    # exit(0)
    xor    %rdi, %rdi
    mov    $__NR_exit, %rax
    syscall

# ------------ Print statements to STDOUT  ------------
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
    jmp    .L_elfparse_exit
 
# ------------ Elf Parser Functions  ------------ 
# Each function should return:
# success: %rax = 0
# failure: %rax = -1
#
# This is checked in the main .L_elfparse_args
# loop that iterates through the functions and
# prints error messages based on the return value 
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

uint64_to_hex:
   # Converts our uint64_t addresses to a string
   # %rsi the address to convert
   # %rdi the output buffer
   push    %rbp
   mov     %rsp, %rbp
   push    %rbx              # We'll use %rbx, so preserve it

   mov     $15, %ecx          # Start with the rightmost character
   mov     %rsi, %rax         # Copy input value to %rax

.L_convert:
   mov     %rax, %rdx
   and     $0xf, %rdx         # Get least significant nibble
   cmp     $10, %rdx
   jae     .L_letter

   add     $'0', %rdx         # Convert to ASCII number
   jmp     .L_save

.L_letter:
   add    $('A' - 10), %rdx  # Convert to ASCII letter (A-F)

.L_save:
   mov     %dl, (%rdi, %rcx)  # Store ASCII char in buffer
   shr     $4, %rax           # Shift out the processed nibble
   dec     %ecx
   jns     .L_convert      # Continue if not done with all 16 nibbles

   pop     %rbx
   pop     %rbp
   ret

uint64_to_ascii:
    # Convert unsigned 64-bit integer to ASCII
    # Input: %rax = integer value, %rsi = buffer pointer
    push %rbp
    mov %rsp, %rbp
    push %rbx
    push %r12
    mov %rsi, %rbx       # Save original buffer pointer
    mov $10, %rcx
    add $20, %rsi        # Move to end of buffer
    mov %rsi, %r12       # Save end of buffer pointer

    # Null-terminate the string
    movb $0, (%rsi)

.convert_loop:
    xor %rdx, %rdx
    div %rcx             # Divide rax by 10
    add $'0', %dl        # Convert remainder to ASCII
    dec %rsi
    mov %dl, (%rsi)      # Store ASCII char
    test %rax, %rax
    jnz .convert_loop

    # Move the string to the beginning of the buffer if necessary
    cmp %rbx, %rsi
    je .done

    # Inline string move
    mov %rsi, %rcx       # Source
    mov %rbx, %rdx       # Destination
.move_loop:
    movb (%rcx), %al
    movb %al, (%rdx)
    inc %rcx
    inc %rdx
    cmp %r12, %rcx
    jle .move_loop

.done:
    pop %r12
    pop %rbx
    pop %rbp
    ret

load_elf64_file:
   # Read in the ehdr, phdr and shdr of the binary
   # %rdi contains the address of the file name
   #
   # If this function succeeds the elfobj variable
   # will be a valid file handle and this returns
   # success (0) else we return failrue (-1) and
   # elfobj is invalid. 
   push    %rbp
   mov     %rsp, %rbp
   push    %rsi

   # __NR_open
   mov     $O_RDONLY, %rsi
   xor     %rdx, %rdx
   mov     $__NR_open, %rax
   syscall
   cmp     $0, %rax
   jl      .L_load_error

   mov     %rax, elfobj                 # save file handle to elfobj

   # Read in ehdr
   mov     %rax, %rdi
   lea     ehdr, %rsi
   mov     $elf64_ehdr_size, %rdx
   mov     $__NR_read, %rax
   syscall
   cmp     $elf64_ehdr_size, %rax
   jne     .L_load_error

   call    verify_elf64_file
   cmp     $0, %rax
   jne     .L_load_error

   # We have loaded ehdr and verified that the file is a valid
   # ELF64 file. We need to mmap our phdr and shdr values now.
   movzwq  ehdr + e_phnum, %rsi
   imul    $elf64_phdr_size, %rsi      # Basically e_phnum * sizeof(Elf64_Phdr)
   push    %rsi                        # Save the size for reading to the address
   mov     %rsi, phdr_size

   mov     %rsi, %rdx
   xor     %rdi, %rdi
   mov     $(PROT_READ | PROT_WRITE), %rsi
   mov     $(MAP_PRIVATE | MAP_ANONYMOUS), %r10
   mov     $-1, %r8
   xor     %r9, %r9
   mov     $__NR_mmap, %rax
   syscall

   cmp     $-1, %rax
   je      .L_load_error

   mov     %rax, phdr

   # Read in the program headers to the allocated memory
   mov     elfobj, %rdi
   lea     phdr, %rsi
   pop     %rdx
   mov     $__NR_read, %rax
   syscall
   
   movzwq  ehdr + e_shnum, %rsi
   imul    $elf64_shdr_size, %rsi
   push    %rsi
   mov     %rsi, shdr_size

   mov     %rsi, %rdx
   xor     %rdi, %rdi
   mov     $(PROT_READ | PROT_WRITE), %rsi
   mov     $(MAP_PRIVATE | MAP_ANONYMOUS), %r10
   mov     $-1, %r8
   xor     %r9, %r9
   mov     $__NR_mmap, %rax
   syscall

   cmp     $-1, %rax
   je      .L_load_error

   mov     %rax, shdr
 
   # Read section headers to the allocated memopry
   mov     elfobj, %rdi
   lea     shdr, %rsi
   pop     %rdx
   mov     $__NR_read, %rax
   syscall

   #Close our file 
   #close(unsigned int fd)
   mov elfobj, %rdi
   mov $__NR_close, %rax
   syscall
   
   mov     $0, %rax
   jmp     .L_load_cleanup
.L_load_error:
   mov     $-1, %rax
.L_load_cleanup:
   pop     %rdi
   mov     %rbp, %rsp
   pop     %rbp
   ret

verify_elf64_file:
   # We will read in the ehdr and verify portions of e_ident
   # ehdr is already loaded by load_elf64_file
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

parse_elf64_ehdr:
   # Print the different fields of the Elf64_Ehdr structure
   # ehdr has already been read in by verify_elf64_file
   lea     elfparse_str_ehdr, %rdi
   call    print_str
   
   lea     elfparse_str_entry, %rdi
   call    print_str

   # Convert the address to a printable hex string
   # %rsi contains our e_entry offset
   # %rdi is our buffer
   mov     ehdr + e_entry, %rsi
   lea     hexbuff, %rdi
   call    uint64_to_hex
   lea     hexbuff, %rdi
   call    print_str

   # Print the e_ident[EI_CLASS] entry
   # Really don't need this as we verify it IS a 64 BIT ELF
   # in verify_elf64_file
   lea     elfparse_str_class, %rdi
   call    print_str

   xor     %rsi, %rsi
   mov     ehdr + e_ident + EI_CLASS, %rsi
   cmp     $ELFCLASSNONE, %sil
   je      .L_class_none
   cmp     $ELFCLASS32, %sil
   je      .L_class_32
   cmp     $ELFCLASS64, %sil
   je      .L_class_64

   jmp     .L_print_type
.L_class_none:
   lea     elfparse_str_class_none, %rdi
   jmp     .L_print_class
.L_class_32:
   lea     elfparse_str_class_32, %rdi
   jmp     .L_print_class
.L_class_64:
   lea     elfparse_str_class_64, %rdi

.L_print_class:
   call    print_str
.L_print_type:
   
   # Print the e_type entry
   lea     elfparse_str_type, %rdi
   call    print_str

   xor     %rsi, %rsi
   mov     ehdr + e_type, %rsi
   cmp     $ET_NONE, %sil
   je      .L_type_none
   cmp     $ET_REL, %sil
   je      .L_type_rel
   cmp     $ET_EXEC, %sil
   je      .L_type_exec
   cmp     $ET_DYN, %sil
   je      .L_type_dyn
   cmp     $ET_CORE, %sil
   je      .L_type_core

   jmp     .L_print_data

.L_type_none:
   lea     elfparse_str_type_none, %rdi
   jmp     .L_print_parsed_type
.L_type_rel:
   lea     elfparse_str_type_rel, %rdi
   jmp     .L_print_parsed_type
.L_type_exec:
   lea     elfparse_str_type_exec, %rdi
   jmp     .L_print_parsed_type
.L_type_dyn:
   lea     elfparse_str_type_dyn, %rdi
   jmp     .L_print_parsed_type
.L_type_core:
   lea     elfparse_str_type_core, %rdi

.L_print_parsed_type:
   call    print_str
.L_print_data:

   # Print the e_ident[EI_DATA] entry
   lea     elfparse_str_data, %rdi
   call    print_str

   xor     %rsi, %rsi
   mov     ehdr + e_ident + EI_DATA, %rsi
   cmp     $ELFDATANONE, %sil
   je      .L_data_none
   cmp     $ELFDATA2LSB, %sil
   je      .L_data_2LSB
   cmp     $ELFDATA2MSB, %sil
   je      .L_data_2MSB

   jmp     .L_print_abi

.L_data_none:
   lea     elfparse_str_data_none, %rdi
   jmp     .L_print_parsed_data
.L_data_2LSB:
   lea     elfparse_str_data_2LSB, %rdi
   jmp     .L_print_parsed_data
.L_data_2MSB:
   lea     elfparse_str_data_2MSB, %rdi

.L_print_parsed_data:
   call    print_str
.L_print_abi:
  
   # Print the e_ident[EI_OSABI] entry
   lea     elfparse_str_abi, %rdi
   call    print_str

   xor     %rsi, %rsi
   mov     ehdr + e_ident + EI_OSABI, %rsi
   cmp     $ELFOSABI_NONE, %sil
   je      .L_abi_none
   cmp     $ELFOSABI_NETBSD, %sil
   je      .L_abi_netbsd
   cmp     $ELFOSABI_LINUX, %sil
   je      .L_abi_linux
   cmp     $ELFOSABI_FREEBSD, %sil
   je      .L_abi_freebsd
   cmp     $ELFOSABI_OPENBSD, %sil
   je      .L_abi_openbsd

   jmp     .L_print_abi_version

.L_abi_none:
   lea     elfparse_str_abi_none, %rdi
   jmp     .L_print_parsed_abi
.L_abi_netbsd:
   lea     elfparse_str_abi_netbsd, %rdi
   jmp     .L_print_parsed_abi
.L_abi_linux:
   lea     elfparse_str_abi_linux, %rdi
   jmp     .L_print_parsed_abi
.L_abi_freebsd:
   lea     elfparse_str_abi_freebsd, %rdi
   jmp     .L_print_parsed_abi
.L_abi_openbsd:
   lea     elfparse_str_abi_openbsd, %rdi

.L_print_parsed_abi:
   call    print_str

.L_print_abi_version:
   
   # Print ABI Version
   lea     elfparse_str_abiver, %rdi
   call    print_str

   xor     %rax, %rax
   movzbq  ehdr + e_ident + EI_ABIVERSION, %rax
   lea     intbuff, %rsi
   call    uint64_to_ascii
   lea     intbuff, %rdi
   call    print_str     

.L_print_file_version:

   lea     elfparse_str_filever, %rdi
   call    print_str

   xor     %rax, %rax
   movzbq  ehdr + e_ident + EI_VERSION, %rax
   lea     intbuff, %rsi
   call    uint64_to_ascii
   lea     intbuff, %rdi
   call    print_str

.L_print_phdr_offset:
 
   lea     elfparse_str_phdroff, %rdi
   call    print_str

   mov     ehdr + e_phoff, %rsi
   lea     hexbuff, %rdi
   call    uint64_to_hex
   lea     hexbuff, %rdi
   call    print_str

.L_print_shdr_offset:
   
   lea     elfparse_str_shdroff, %rdi
   call    print_str

   mov     ehdr + e_shoff, %rsi
   lea     hexbuff, %rdi
   call    uint64_to_hex
   lea     hexbuff, %rdi
   call    print_str

.L_print_ehdr_size:

   lea     elfparse_str_ehdrsiz, %rdi
   call    print_str

   xor     %rax, %rax
   movzbq  ehdr + e_ehsize, %rax
   lea     intbuff, %rsi
   call    uint64_to_ascii
   lea     intbuff, %rdi
   call    print_str

.L_print_phdr_size:

   lea     elfparse_str_phdrsiz, %rdi
   call    print_str

   xor     %rax, %rax
   movzbq  ehdr + e_phentsize, %rax
   lea     intbuff, %rsi
   call    uint64_to_ascii
   lea     intbuff, %rdi
   call    print_str

.L_print_phdr_count:

   lea     elfparse_str_phdrcnt, %rdi
   call    print_str

   xor     %rax, %rax
   movzbq  ehdr + e_phnum, %rax
   lea     intbuff, %rsi
   call    uint64_to_ascii
   lea     intbuff, %rdi
   call    print_str

.L_print_shdr_size:

   lea     elfparse_str_shdrsiz, %rdi
   call    print_str

   xor     %rax, %rax
   movzbq  ehdr + e_shentsize, %rax
   lea     intbuff, %rsi
   call    uint64_to_ascii
   lea     intbuff, %rdi
   call    print_str

.L_print_shdr_count:

   lea     elfparse_str_shdrcnt, %rdi
   call    print_str

   xor     %rax, %rax
   movzbq  ehdr + e_shnum, %rax
   lea     intbuff, %rsi
   call    uint64_to_ascii
   lea     intbuff, %rdi
   call    print_str

.L_print_strtbl_index:

   lea     elfparse_str_shdrstrtbl, %rdi
   call    print_str

   xor     %rax, %rax
   movzbq  ehdr + e_shstrndx, %rax
   lea     intbuff, %rsi
   call    uint64_to_ascii
   lea     intbuff, %rdi
   call    print_str

   mov     $0, %rax
   ret
