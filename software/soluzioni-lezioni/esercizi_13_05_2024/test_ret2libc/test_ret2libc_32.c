// compilare con
// gcc -m32 -g -no-pie -fno-stack-protector -o test_ret2libc_32 test_ret2libc_32.c
#include <stdio.h>
#include <stdlib.h>

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