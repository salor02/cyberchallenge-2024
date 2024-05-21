import string
import time
from pwn import *

HOST = 'gtn1.challs.cyberchallenge.it'
PORT = 9060

conn = remote(HOST, PORT)

data = conn.recvline_contains(b'=').decode()
m = int(data.split(' = ')[1])
data = conn.recvline_contains(b'=').decode()
c = int(data.split(' = ')[1])
data = conn.recvline_contains(b'=').decode()
n = int(data.split(' = ')[1])
data = conn.recvline_contains(b'=').decode()
s = int(data.split(' = ')[1])
print(f'{m}\n{c}\n{n}\n{s}\n')
data = conn.recvuntil(b'v[0] = ').decode()

prev_guess = s

for _ in range(50):
    guess = (prev_guess * m + c) % n
    print(f'[SENDING] {guess}')
    to_send = str(guess)
    conn.sendline(bytes(to_send.encode()))
    data = conn.recv().decode()
    prev_guess = guess
    print(data)

