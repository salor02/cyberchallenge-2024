import string
import time
from pwn import *

HOST = 'gtn3.challs.cyberchallenge.it'
PORT = 9062

conn = remote(HOST, PORT)

data = conn.recvline_contains(b'=').decode()
n = int(data.split(' = ')[1])
data = conn.recvline_contains(b'=').decode()
x0 = int(data.split(' = ')[1])
data = conn.recvline_contains(b'=').decode()
x1 = int(data.split(' = ')[1])
data = conn.recvline_contains(b'=').decode()
x2 = int(data.split(' = ')[1])
print(f'{n}\n{x0}\n{x1}\n{x2}\n')
data = conn.recv().decode()

m = ((x2 - x1) * pow((x1 - x0), -1, n)) % n
print(f'm = {m}')
c = (x1 - x0 * m) % n
print(f'c = {c}')
prev_guess = x2

for _ in range(50):
    guess = (prev_guess * m + c) % n
    print(f'[SENDING] {guess}')
    to_send = str(guess)
    conn.sendline(bytes(to_send.encode()))
    data = conn.recv().decode()
    prev_guess = guess
    print(data)

