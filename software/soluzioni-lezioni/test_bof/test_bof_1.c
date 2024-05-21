// compilare con gcc -no-pie -g -fno-stack-protector -z execstack -o test_bof_1 test_bof_1.c
#include <stdio.h>
#include <string.h>

int main(int argc, char* argv[]) {
    setvbuf(stdout, NULL, _IONBF, 0);
    int variable;
    char buffer[10];

    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }

    variable = 0;
    strcpy(buffer, argv[1]);
    if (variable == 0x41424344) {
        printf("You win!\n");
    } else {
        printf("Try again, you got %x\n", variable);
    }

}