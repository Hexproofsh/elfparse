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
  Entry Point: 0x0000000000401000
  Class: ELF64
  Type: Executable file
  Data: 2's complement, little endian
  ABI: UNIX System V ABI
  ABI Version: 0
  File Version: 1
  Program header offset: 0x00000000000000401
  Section header offset: 0x00000000000037C01
  ELF header size (bytes): 64
  Program header size (bytes): 56
  Program header count: 3
  Section header size (bytes): 64
  Section header count: 7
  Section header string table index: 6
```
