from pwn import *
import re

io = remote("software-18.challs.olicyber.it", 13001)

io.sendlineafter(b'per iniziare ...', b'')
for i in range(100):
    ret = io.recvline().decode()
    n = int(re.findall(r'(0x[0-9a-f]+)', ret)[0], 16)
    m = re.findall(r'(\d+)-bit', ret)[0]
    if m == '32':
        to_send = p32(n)
    else:
        to_send = p64(n)
    io.sendafter(b'Result :', to_send)

io.interactive()