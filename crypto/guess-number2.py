import string
import time
from pwn import *

HOST = 'gtn2.challs.cyberchallenge.it'
PORT = 9061

conn = remote(HOST, PORT)

data = conn.recvline_contains(b'=').decode()
m = int(data.split(' = ')[1])
data = conn.recvline_contains(b'=').decode()
n = int(data.split(' = ')[1])
data = conn.recvline_contains(b'=').decode()
x0 = int(data.split(' = ')[1])
data = conn.recvline_contains(b'=').decode()
x1 = int(data.split(' = ')[1])
print(f'{m}\n{n}\n{x0}\n{x1}\n')
data = conn.recv().decode()

c = (x1 - x0 * m) % n
prev_guess = x1

for _ in range(50):
    guess = (prev_guess * m + c) % n
    print(f'[SENDING] {guess}')
    to_send = str(guess)
    conn.sendline(bytes(to_send.encode()))
    data = conn.recv().decode()
    prev_guess = guess
    print(data)

