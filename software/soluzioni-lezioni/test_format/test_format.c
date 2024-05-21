// per 64 bit, compilare con
// gcc -g -no-pie -fno-stack-protector -z execstack -o test_format_64 test_format.c
// per 32 bit, compilare con
// gcc -m32 -g -no-pie -fno-stack-protector -z execstack -o test_format_32 test_format.c

#include <stdio.h>

int main(int argc, char *argv[]) {
    setvbuf(stdout, NULL, _IONBF, 0);
    char buf[100];
    puts("Enter a string: ");
    fgets(buf, 100, stdin);
    printf(buf);
}