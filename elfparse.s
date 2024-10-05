# -----------------------------------------------------------------------------
# elfparse.s - GNU ELF64 Parser
#
# Usage: elfparse <option(s)> [file]
#
# Assemble: as --elf64 -o elfparse.o elfparse.s
#           ld -o elfparse elfparse.o
#
# or just run make
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
#
# You should have received a copy of the GNU General Public License along with 
# this program. If not, see <https://www.gnu.org/licenses/>.
# -----------------------------------------------------------------------------
.title               "elfparse.s"
.version             "1"

# ------------ Constants ------------

.set STDOUT,         1
.set O_RDONLY,       0

.set PROT_READ,      1
.set PROT_WRITE,     2
.set MAP_PRIVATE,    2
.set MAP_ANONYMOUS,  0x20

# syscalls
.set __NR_read,      0
.set __NR_write,     1
.set __NR_open,      2
.set __NR_close,     3
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

.set PT_LOAD,        1
.set PT_DYNAMIC,     2
.set PT_INTERP,      3
.set PT_NOTE,        4
.set PT_PHDR,        6

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

.struct 0
elf64_sym:
    .struct elf64_sym
    st_name:  .space 4
    st_info:  .space 1
    st_other: .space 1 
    st_shndx: .space 2
    st_value: .space 8
    st_size:  .space 8
elf64_sym_size:

# ------------ Initialized data ------------

    .section .data

elfparse_usage:
    .ascii "GNU ELF64 Parser\n"
    .ascii "usage: elfparse <option(s)> [file]\n"
    .ascii "  -a            all - prints header, program headers, sections, symbol table\n"
    .ascii "  -h            prints the elf header\n"
    .ascii "  -p            prints program header information\n"
    .ascii "  -s            prints section names and addresses\n"
    .ascii "  -y            prints the symbol table\n"
    .ascii "  -v            print the version information of elfparse\n\n"
    .ascii "When using '-a' or '-v' it cannot be combined with other arguments\n\ni"
    .asciz "See 'COPYING' for licensing information. elfparse (C) Copyright 2024 hexproof.sh\n"

# Program options for parsing the command line
option_a: .asciz "-a"
option_h: .asciz "-h"
option_p: .asciz "-p"
option_s: .asciz "-s"
option_d: .asciz "-d"
option_y: .asciz "-y"
option_v: .asciz "-v"

elfparse_version:
    .ascii "GNU ELF64 parser (elfparse) version 1.01\n"
    .ascii "(C) Copyright 2024 hexproof.sh\n"
    .ascii "This program is free software; you may redistribute it under the terms of\n"
    .ascii "the GNU General Public License version 3 or (at your option) any later version.\n"
    .asciz "This program has absolutely no warranty.\n"

elfparse_verify_valid:
    .asciz "Binary is a valid 64-BIT ELF file\n"

# EHDR messages
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

# ABI messages
elfparse_str_abi_none:    .asciz "UNIX System V ABI"
elfparse_str_abi_netbsd:  .asciz "NetBSD"
elfparse_str_abi_linux:   .asciz "GNU\Linux"
elfparse_str_abi_freebsd: .asciz "FreeBSD"
elfparse_str_abi_openbsd: .asciz "OpenBSD"

# EI_DATA messages
elfparse_str_data_none:   .asciz "Invalid data encoding"
elfparse_str_data_2LSB:   .asciz "2's complement, little endian"
elfparse_str_data_2MSB:   .asciz "2's complement, big endian"

# EI_CLASS messages
elfparse_str_class_32:    .asciz "ELF32"
elfparse_str_class_64:    .asciz "ELF64"
elfparse_str_class_none:  .asciz "Invalid type"

# e_type messages
elfparse_str_type_none: .asciz "No file type"
elfparse_str_type_rel:  .asciz "Relocatable file"
elfparse_str_type_exec: .asciz "Executable file"
elfparse_str_type_dyn:  .asciz "Shared object file"
elfparse_str_type_core: .asciz "Core file"
elfparse_str_type_unkn: .asciz "Unknown"

# Program header messages
elfparse_str_phdr:      .asciz "\nProgram headers:"
elfparse_str_ptloadtxt: .asciz "\n  .text    0x"
elfparse_str_ptloaddat: .asciz "\n  .data    0x"
elfparse_str_progseg:   .asciz "\n  Program segment: 0x"
elfparse_str_dynseg:    .asciz "\n  Dynamic segment: 0x"
elfparse_str_noteseg:   .asciz "\n  Note segment: 0x"
elfparse_str_interp:    .asciz "\n  Interpreter: "

# Section header messages. We use *shdr_beg to begin the line to give the
# section name some space and then *shdr_space to print before the p_vaddr
elfparse_str_shdr:       .asciz "\nSection headers:"
elfparse_str_shdr_beg:   .asciz "\n  "
elfparse_str_shdr_space: .asciz "    0x"

elfparse_str_sym:        .asciz "\nSymbol table:"

# Errors
elfparse_invalid_file:
    .asciz "Error: Unable to open file\n"

elfverify_read_error:
    .asciz "Error: Unable to read ELF64 header\n"

elfparse_invalid_option:
    .asciz "\nError: Invalid option detected or in wrong position: "

elfparse_see_usage:
    .asciz "\nRun 'elfparse' without any arguments to see usage\n"

# ------------ Uninitialized data ------------

.lcomm shstrtab,    8
.lcomm elfobj,      8
.lcomm hexbuff,     17
.lcomm intbuff,     21
.lcomm interp_path, 256

# We don't mmap ehdr, but phdr, shdr are pointers returned from mmap
.lcomm ehdr, elf64_ehdr_size

.align 8
.lcomm phdr,      8
.lcomm phdr_size, 8

.align 8
.lcomm shdr,      8
.lcomm shdr_size, 8

# ------------ Text ------------

    .globl _start
    .section .text

_start:
    mov    (%rsp), %r12                     # %rsp = argc
    cmp    $2, %r12
    je     .L_check_arg_version

    cmp    $3, %r12                         # We should have atleast 2 command line arg
    jl     .L_elfparse_usage 
    jmp    .L_elfparse_args

.L_check_arg_version:
   lea     16(%rsp), %r13
   mov     (%r13), %rdi
   lea     option_v, %rsi
   call    str_cmp
   test    %eax, %eax
   jz      .L_print_version
   jmp     .L_elfparse_usage
.L_elfparse_args:
    # Our usage allows us to specifiy any of the arguments in any order to print out
    # various info about the ELF file. The only exception is -a can be the only option
    # as it just prints out all the information.
    #
    # This will iterate through all the functions to parse and print the
    # elf headers. See functions section for more information.
    lea    16(%rsp), %r13                   # Pointer to the first argument argv[1]
    mov    %r12, %rax
    dec    %rax
    mov    8(%rsp, %rax, 8), %rdi           # Pointer to the last argument, filename

    # The options are processed on the file, so we need to be able to load the data we need first
    # and then loop through all the options.
    call   load_elf64_file
    test   %rax, %rax
    jl     .L_elfparse_error

    # Load the symbol table
    call   load_shstrtab
    test   %rax, %rax
    jl     .L_elfparse_error

    cmp    $3, %r12                         # If we have more than 3 arguments jump to parsing the valid
    jg     .L_init_opt_parsing              # ones that can have more than one argument. Option -a and -d
                                            # cannot be combined with other arguments.
    mov    (%r13), %rdi
    lea    option_a, %rsi
    call   str_cmp
    test   %eax, %eax
    jz     .L_print_all_data

.L_init_opt_parsing:
    dec    %r12                             # We don't need to parse the filename
    mov    $1, %r15                         # %r15 will hold the option counter and we use $1 to bypass program name    
.L_parse_options:
    cmp    %r12, %r15
    je     .L_elfparse_exit

    mov    (%r13), %rdi
    call   .L_process_options

.L_next_option:
    add    $8, %r13                         # Increment to the next address for the next argument
    inc    %r15                 
    jmp    .L_parse_options
.L_process_options:
    mov    %rdi, %r10                       # Save the original argument pointer in %r10
    lea    option_h, %rsi
    call   str_cmp
    test   %eax, %eax
    jz     .L_print_ehdr_data

    mov    %r10, %rdi
    lea    option_p, %rsi
    call   str_cmp
    test   %eax, %eax
    jz     .L_print_phdr_data

    mov    %r10, %rdi
    push   %rdi
    lea    option_s, %rsi
    call   str_cmp
    test   %eax, %eax
    jz     .L_print_shdr_data

    mov    %r10, %rdi
    push   %rdi
    lea    option_y, %rsi
    call   str_cmp
    test   %eax, %eax
    jz     .L_print_symbols

    jmp    .L_elfparse_option_error

.L_print_ehdr_data:
    call   parse_elf64_ehdr
    jmp    .L_next_option
.L_print_phdr_data:
    call   parse_elf64_phdr
    jmp    .L_next_option
.L_print_shdr_data:
    call   parse_elf64_sections
    jmp    .L_next_option
.L_print_all_data:
    # Print ehdr
    call   parse_elf64_ehdr
    cmp    $0, %rax
    jl     .L_elfparse_exit

    # Print all phdr[x] names/addresses. This also calls the function to
    # print out sectio headers information.
    call   parse_elf64_phdr
    cmp    $0, %rax
    jl     .L_elfparse_exit
   
    # Print section information
    call   parse_elf64_sections
    jmp    .L_elfparse_exit
.L_print_symbols:
    call   parse_elf64_sym
    jmp    .L_next_option
.L_print_version:
    lea    elfparse_version, %rdi
    call   print_str
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
    mov    elfobj, %rdi
    mov    $__NR_close, %rax
    syscall
    
    # Call the exit syscall
    # exit(0)
    xor    %rdi, %rdi
    mov    $__NR_exit, %rax
    syscall

# ------------ Print statements to STDOUT  ------------

# This should be an area to improve. Error handling.
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

.L_elfparse_option_error:
    lea    elfparse_invalid_option, %rdi
    call   print_str
    mov    %r10, %rdi
    call   print_str
    lea    elfparse_see_usage, %rdi
    call   print_str
    jmp    .L_elfparse_exit

# ------------ Elf Parser Functions  ------------ 

# Read in the ehdr, phdr and shdr of the binary
# %rdi contains the address of the file name
#
# If this function succeeds the elfobj variable
# will be a valid file handle and this returns
# success (0) else we return failrue (-1) and
# elfobj is invalid. 
#
# This could have been written better, especially since I overcomplicated it by
# mmap/reading each section separately. We should have just fstat the file and
# mapped the entire file to memory.
load_elf64_file:
    push    %rbp
    mov     %rsp, %rbp
    push    %rsi

    mov     $O_RDONLY, %rsi
    xor     %rdx, %rdx
    mov     $__NR_open, %rax
    syscall
    cmp     $0, %rax
    jl      .L_load_error

    mov     %rax, elfobj                    # save file handle to elfobj

    # Read in ehdr. The reason we are not using MMAP for the ehdr is because we know
    # there is only a single header so we don't need to allocate memory for X amount
    # of headers. So we directly read it to the space we have allocated in .bss for it
    mov     %rax, %rdi
    lea     ehdr, %rsi
    mov     $elf64_ehdr_size, %rdx
    mov     $__NR_read, %rax
    syscall
    cmp     $elf64_ehdr_size, %rax
    jne     .L_load_error

    # Since we have loaded theehdr, before doing any more operations we go ahead and verify
    # that this is a valid ELF64 binary. See function header for verify_elf64_file for what
    # verification it does
    call    verify_elf64_file
    cmp     $0, %rax
    jne     .L_load_error

    # mmap for program headers
    movzwq  ehdr + e_phnum, %rsi
    imul    $elf64_phdr_size, %rsi          # e_phnum * sizeof(Elf64_Phdr)
    mov     %rsi, phdr_size
    xor     %rdi, %rdi                
    mov     $(PROT_READ | PROT_WRITE), %rdx
    mov     $(MAP_PRIVATE | MAP_ANONYMOUS), %r10
    mov     $-1, %r8
    xor     %r9, %r9
    mov     $__NR_mmap, %rax
    syscall
    cmp     $-1, %rax
    je      .L_load_error
    mov     %rax, phdr

    # Read program headers
    mov     elfobj, %rdi
    mov     phdr, %rsi                 
    mov     phdr_size, %rdx
    mov     $__NR_read, %rax
    syscall
    cmp     phdr_size, %rax             
    jne     .L_load_error

    # Save current file position
    mov     elfobj, %rdi
    xor     %rsi, %rsi
    mov     $1, %rdx                        # SEEK_CUR
    mov     $__NR_lseek, %rax
    syscall
    push    %rax                            # Save current position

    # Seek to section header offset
    mov     elfobj, %rdi
    mov     ehdr + e_shoff, %rsi
    xor     %rdx, %rdx                      # SEEK_SET
    mov     $__NR_lseek, %rax
    syscall

    # mmap for section headers
    movzwq  ehdr + e_shnum, %rsi
    imul    $elf64_shdr_size, %rsi
    mov     %rsi, shdr_size
    xor     %rdi, %rdi                 
    mov     $(PROT_READ | PROT_WRITE), %rdx
    mov     $(MAP_PRIVATE | MAP_ANONYMOUS), %r10
    mov     $-1, %r8
    xor     %r9, %r9
    mov     $__NR_mmap, %rax
    syscall
    cmp     $-1, %rax
    je      .L_load_error
    mov     %rax, shdr

    # Read section headers
    mov     elfobj, %rdi
    mov     shdr, %rsi                  
    mov     shdr_size, %rdx
    mov     $__NR_read, %rax
    syscall
    cmp     shdr_size, %rax           
    jne     .L_load_error

    mov     elfobj, %rdi
    pop     %rsi
    xor     %rdx, %rdx  
    mov     $__NR_lseek, %rax
    syscall

    xor     %rax, %rax
    jmp     .L_load_cleanup

.L_load_error:
    mov     $-1, %rax

.L_load_cleanup:
    pop     %rdi
    mov     %rbp, %rsp
    pop     %rbp
    ret

# We preload the string table. We need this for printing
# the section information.
# No input. This just must be called AFTER load_elf64_file
load_shstrtab:
    push   %rbp
    mov    %rsp, %rbp
    push   %r13
    push   %r12

    movzw  ehdr + e_shstrndx, %rax
    imul   $elf64_shdr_size, %rax
    mov    shdr, %rdx
    add    %rax, %rdx

    mov    sh_offset(%rdx), %r13
    mov    sh_size(%rdx), %r12

    xor    %rdi, %rdi
    mov    %r12, %rsi
    mov    $(PROT_READ | PROT_WRITE), %rdx
    mov    $(MAP_PRIVATE | MAP_ANONYMOUS), %r10
    mov    $-1, %r8
    xor    %r9, %r9
    mov    $__NR_mmap, %rax
    syscall

    cmp    $-1, %rax
    je     .L_mmap_error
    mov    %rax, shstrtab

    # Seek to the string table offset
    mov    elfobj, %rdi
    mov    %r13, %rsi                       # Use sh_offset for seeking
    xor    %rdx, %rdx
    mov    $__NR_lseek, %rax
    syscall

    # Read the string table
    mov    elfobj, %rdi
    mov    shstrtab, %rsi
    mov    %r12, %rdx                       # Use sh_size for reading
    mov    $__NR_read, %rax
    syscall

    cmp    %r12, %rax
    jne    .L_read_error

    mov    shstrtab, %rax
    jmp    .L_cleanup

.L_mmap_error:
.L_read_error:
    mov    $-1, %rax

.L_cleanup:
    pop    %r12
    pop    %r13
    mov    %rbp, %rsp
    pop    %rbp
    ret

# We will read in the ehdr and verify portions of e_ident
# ehdr is already loaded by load_elf64_file
# Verify magic bytes "\177ELF" and EI_CLASS being ELFCLASS64. We do this because
# we are only dealing with elf64_* headers.
#
# This is called from inside load_elf64_file
verify_elf64_file:
   lea     ehdr, %rcx
   cmpb    $ELFMAG0, elf64_ehdr + e_ident + EI_MAG0(%rcx)
   jne     .L_verify_error
   cmpb    $ELFMAG1, elf64_ehdr + e_ident + EI_MAG1(%rcx)
   jne     .L_verify_error
   cmpb    $ELFMAG2, elf64_ehdr + e_ident + EI_MAG2(%rcx)
   jne     .L_verify_error
   cmpb    $ELFMAG3, elf64_ehdr + e_ident + EI_MAG3(%rcx)
   jne     .L_verify_error

   cmpb    $ELFCLASS64, elf64_ehdr + e_ident + EI_CLASS(%rcx)
   jne     .L_verify_error

   lea     elfparse_verify_valid, %rdi
   call    print_str

   xor     %rax, %rax
   ret
.L_verify_error:
   mov     $-1, %rax
   ret

# Parse the elf64_ehdr structure. This structure gives us further information
# for processing the rest of the file. 
#
# This is called from the main .L_elfparse_args section. elf64_load_file must
# already have been called.
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

   # Print the EI_VERSION of e_ident (File version)
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

   xor     %rax, %rax
   ret

# Parse the Program header information. Iterate each phdr
# and print out sections and offset. PT_INTERP we print
# the interpreter
parse_elf64_phdr:
   lea     elfparse_str_phdr, %rdi
   call    print_str
   xor     %rcx, %rcx                       # our index into phdr
   movzw   ehdr + e_phnum, %rbx             # holds e_phnum value
.L_loop_section:
   cmp     %rcx, %rbx
   je      .L_exit_parse_phdr
   
   mov     %rcx, %rax                       # below we are essentially doing phdr[X].p_type where X = %rcx
   imul    $elf64_phdr_size, %rax
   mov     phdr, %rdx
   add     %rax, %rdx
   mov     p_type(%rdx), %eax
   
   cmp     $PT_LOAD, %eax
   je      .L_print_ptload
   cmp     $PT_PHDR, %eax
   je      .L_print_ptphdr
   cmp     $PT_DYNAMIC, %eax
   je      .L_print_ptdyn
   cmp     $PT_NOTE, %eax
   je      .L_print_ptnote
   cmp     $PT_INTERP, %eax
   je      .L_print_ptinterp
   
   # Any other section we just loop
   inc     %rcx
   jmp     .L_loop_section

.L_print_phdr_addr:
   # This prints out the phdr[i].p_vaddr
   mov     p_vaddr(%rdx), %rsi
   lea     hexbuff, %rdi
   call    uint64_to_hex
   lea     hexbuff, %rdi
   call    print_str
   inc     %rcx
   jmp     .L_loop_section

.L_print_ptload:
   # Print out PT_LOAD .text and .data segment addresses
   mov     p_offset(%rdx), %r10
   test    %r10, %r10
   jz      .L_ptload_text
   lea     elfparse_str_ptloaddat, %rdi
   call    print_str
   jmp     .L_print_phdr_addr

.L_ptload_text:
   lea     elfparse_str_ptloadtxt, %rdi
   call    print_str
   jmp     .L_print_phdr_addr

.L_print_ptdyn:
   lea     elfparse_str_dynseg, %rdi
   call    print_str
   jmp     .L_print_phdr_addr

.L_print_ptnote:
   lea     elfparse_str_noteseg, %rdi
   call    print_str
   jmp     .L_print_phdr_addr

.L_print_ptinterp:
   # If there is a PT_INTERP we print the interpreter
   lea     elfparse_str_interp, %rdi
   call    print_str

   push    %rcx
   push    %rdx
   mov     p_offset(%rdx), %rsi

   mov     elfobj, %rdi        
   xor     %rdx, %rdx            
   mov     $__NR_lseek, %rax    
   syscall

   pop     %rdx
   mov     elfobj, %rdi         
   lea     interp_path, %rsi     
   mov     p_filesz(%rdx), %rdx  
   mov     $__NR_read, %rax      
   syscall

   mov     %rax, %rcx            
   movb    $0, interp_path(%rcx) 

   lea     interp_path, %rdi
   call    print_str

   pop     %rcx
   inc     %rcx
   jmp     .L_loop_section

.L_print_ptphdr:
   lea     elfparse_str_progseg, %rdi
   call    print_str
   jmp     .L_print_phdr_addr

.L_exit_parse_phdr:
   xor     %rax, %rax
   ret

# Print out the section names and addresses in the supplied ELF file
# load_elf64_file and load_shstrtab must have already been called
# 
# The variable shstrtab holds the symbol table
parse_elf64_sections:
   lea     elfparse_str_shdr, %rdi
   call    print_str

   xor     %rbx, %rbx
   movzwl  ehdr + e_shnum, %ebx
   mov     $1, %rcx

.L_loop_sections:
   cmp     %ebx, %ecx
   je      .L_exit_parse_sections

   lea     elfparse_str_shdr_beg, %rdi
   call    print_str

   mov     %rcx, %rax
   imul    $elf64_shdr_size, %rax
   mov     shdr, %rdx
   add     %rax, %rdx

   mov     shstrtab, %rdi

   mov     sh_name(%rdx), %esi
   add     %rsi, %rdi

   # Print section name
   call    print_str

   # Print address
   lea     elfparse_str_shdr_space, %rdi
   call    print_str

   mov     sh_addr(%rdx), %rsi
   lea     hexbuff, %rdi
   call    uint64_to_hex
   lea     hexbuff, %rdi
   call    print_str
    
   inc     %rcx
   jmp     .L_loop_sections
 
.L_exit_parse_sections:
   xor     %rax, %rax
   ret

parse_elf64_sym:
   lea     elfparse_str_sym, %rdi
   call    print_str
   xor     %rax, %rax
   ret

# ---------- Utility Functions ----------

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
    push   %rcx
    push   %rax
    push   %rdx

    xor    %rcx, %rcx
.L_strlen:
    movb   (%rdi, %rcx), %al
    test   %al, %al
    jz     .L_write
    inc    %rcx
    jmp    .L_strlen
.L_write:
    # At this point %rcx holds the length of the null terminated string
    mov    %rcx, %rdx
    mov    %rdi, %rsi
    mov    $STDOUT, %rdi
    mov    $__NR_write, %rax
    syscall

    pop    %rdx
    pop    %rax
    pop    %rcx
    ret

# String comparison utility function
# %rcx is length to check, we use 2 because all options are 2 letters
# %rdi string1
# %rsi string2
# %rax is return
str_cmp:
    push    %rcx
    cld
    mov     $2, %rcx
    repe    cmpsb
    jne     .L_str_cmp_ne
    xor     %rax, %rax
    pop     %rcx
    ret
.L_str_cmp_ne:
    pop     %rcx
    mov     $-1, %rax
    ret

# label is misleading its uint64_to_hex_string
# Converts our uint64_t addresses to a string
# %rsi the address to convert
# %rdi the output buffer
uint64_to_hex:
    push   %rbp
    mov    %rsp, %rbp
    push   %rbx
    push   %rdx
    push   %rcx
    push   %rax
    push   %rdi

    mov    $15, %ecx                        # Start with the rightmost character
    mov    %rsi, %rax

.L_convert:
    mov    %rax, %rdx
    and    $0xf, %rdx                       # Get least significant nibble
    cmp    $10, %rdx
    jae    .L_letter

    add    $'0', %rdx                       # Convert to ASCII number
    jmp    .L_save

.L_letter:
    add    $('A' - 10), %rdx                # Convert to ASCII letter (A-F)

.L_save:
    mov    %dl, (%rdi, %rcx)                # Store ASCII char in buffer
    shr    $4, %rax                         # Shift out the processed nibble
    dec    %ecx
    jns    .L_convert

    pop    %rdi
    pop    %rax
    pop    %rcx
    pop    %rdx
    pop    %rbx
    pop    %rbp
    ret

# Convert unsigned 64-bit integer to ASCII
# %rax = integer
# %rsi = buffer pointer
uint64_to_ascii:
    push   %rbp
    mov    %rsp, %rbp
    push   %rbx
    push   %r12
    mov    %rsi, %rbx                       # Save original buffer pointer
    mov    $10, %rcx
    add    $20, %rsi                        # Move to end of buffer
    mov    %rsi, %r12                       # Save end of buffer pointer

    # Null-terminate the string
    movb   $0, (%rsi)

.L_convert_digit:
    xor    %rdx, %rdx
    div    %rcx                             # Divide rax by 10
    add    $'0', %dl                        # Convert remainder to ASCII
    dec    %rsi
    mov    %dl, (%rsi)                      # Store ASCII char
    test   %rax, %rax
    jnz    .L_convert_digit

    # Move the string to the beginning of the buffer if necessary
    cmp    %rbx, %rsi
    je     .L_done_to_ascii

    # Inline string move
    mov    %rsi, %rcx                       # Source
    mov    %rbx, %rdx                       # Destination
.L_strcpy:
    movb   (%rcx), %al
    movb   %al, (%rdx)
    inc    %rcx
    inc    %rdx
    cmp    %r12, %rcx
    jle    .L_strcpy

.L_done_to_ascii:
    pop    %r12
    pop    %rbx
    pop    %rbp
    ret
