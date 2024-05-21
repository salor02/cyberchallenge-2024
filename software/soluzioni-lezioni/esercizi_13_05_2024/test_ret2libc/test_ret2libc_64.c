// compilare con
// gcc -g -no-pie -fno-stack-protector -o test_ret2libc_64 test_ret2libc_64.c
#include <stdio.h>
#include <stdlib.h>

void usefulFunction() {
    asm("pop %rdi; ret");
}

void pwnme() {
    char buf[100];
    gets(buf);
}

int main(int argc, char ** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    system("echo Non riuscirai mai ad eseguire /bin/sh");
    pwnme();
    return 0;
}