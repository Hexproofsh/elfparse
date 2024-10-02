elfparse
=========

A simple ELF64 parser written in assembly that will output EHDR, PHDR and section information.

Usage:
```
GNU ELF64 Parser
usage: elfparse [file]
```
Current printing the Elf64_Ehdr information:

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
  Interpreter: /lib64/ld-linux-x86-64.so.2
  .text    0x00000000000007C0
  .data    0x0000000000001000
  .data    0x0000000000002000
  .data    0x0000000000003DA8
  Dynamic segment: 0x0000000000003DB8
  Note segment: 0x0000000000000338
  Note segment: 0x0000000000000368
Section headers:
```
