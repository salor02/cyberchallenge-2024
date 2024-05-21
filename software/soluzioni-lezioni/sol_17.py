#!/usr/bin/env python3

# Importa la libreria di pwntools
from pwn import *


def main():
    '''
    remote(hostname, port) apre una socket e ritorna un object
    che può essere usato per inviare e ricevere dati sulla socket  
    '''
    HOST = "software-17.challs.olicyber.it"
    PORT = 13000
    r = remote(HOST, PORT)

    r.sendlineafter(b'per iniziare ...', b'')
    for i in range(10):
        ret = r.recvlines(2)[1].decode()
        n = sum(eval(ret))
        r.sendlineafter(b'Somma?', str(n).encode())

    # permette di interagire con la connessione direttamente dalla shell
    r.interactive()

    # chiude la socket
    r.close()


if __name__ == "__main__":
    main()
