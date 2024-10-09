elfparse
=========

A simple ELF64 parser written in assembly that will output EHDR, PHDR and section information.

Usage:
```
GNU ELF64 Parser
usage: elfparse <option(s)> [file]
  -a            all - prints header, program headers, sections, symbol table
  -h            prints the elf header
  -p            prints program header information
  -s            prints section names and addresses
  -y            prints the symbol table
  -v            print the version information of elfparse

When using '-a' or '-v' it cannot be combined with other arguments

See 'COPYING' for licensing information. elfparse (C) Copyright 2024 hexproof.sh
```

Example output:

```
$ ./elfparse camel
Binary is a valid 64-BIT ELF file

ELF Header:
  Entry Point: 0x00000000000010A0
  Class: ELF64
  Type: Shared object file
  Data: 2's complement, little endian
  ABI: UNIX System V ABI
  ABI Version: 0
  File Version: 1
  Program header offset: 0x0000000000000040
  Section header offset: 0x0000000000003700
  ELF header size (bytes): 64
  Program header size (bytes): 56
  Program header count: 13
  Section header size (bytes): 64
  Section header count: 31
  Section header string table index: 30
Program headers:
  Program segment: 0x0000000000000040
  Interpreter: /lib64/ld-linux-x86-64.so.2
  .text    0x0000000000000000
  .data    0x0000000000001000
  .data    0x0000000000002000
  .data    0x0000000000003DA8
  Dynamic segment: 0x0000000000003DB8
  Note segment: 0x0000000000000338
  Note segment: 0x0000000000000368
Section headers:
  .interp    0x0000000000000318
  .note.gnu.property    0x0000000000000338
  .note.gnu.build-id    0x0000000000000368
  .note.ABI-tag    0x000000000000038C
  .gnu.hash    0x00000000000003B0
  .dynsym    0x00000000000003D8
  .dynstr    0x00000000000004B0
  .gnu.version    0x0000000000000562
  .gnu.version_r    0x0000000000000578
  .rela.dyn    0x00000000000005B8
  .rela.plt    0x0000000000000678
  .init    0x0000000000001000
  .plt    0x0000000000001020
  .plt.got    0x0000000000001060
  .plt.sec    0x0000000000001070
  .text    0x00000000000010A0
  .fini    0x0000000000001250
  .rodata    0x0000000000002000
  .eh_frame_hdr    0x0000000000002008
  .eh_frame    0x0000000000002040
  .init_array    0x0000000000003DA8
  .fini_array    0x0000000000003DB0
  .dynamic    0x0000000000003DB8
  .got    0x0000000000003FA8
  .data    0x0000000000004000
  .bss    0x0000000000004010
  .comment    0x0000000000000000
  .symtab    0x0000000000000000
  .strtab    0x0000000000000000
  .shstrtab    0x0000000000000000
```
