// per 32 bit, compilare con
// gcc -m32 -g -no-pie -fno-stack-protector -z execstack -o test_bof_2_32 test_bof_2.c
// per 64 bit, compilare con
// gcc -g -no-pie -fno-stack-protector -z execstack -o test_bof_2_64 test_bof_2.c
#include <stdio.h>

void highSecurityFunction() {
    printf("You win!\n");
}

void lowSecurityFunction() {
    char buffer[10];

    printf("Enter some text: ");
    scanf("%s", buffer);
    printf("You entered: %s\n", buffer);
}

int main(int argc, char* argv[]) {
    setvbuf(stdout, NULL, _IONBF, 0);
    lowSecurityFunction();
    return 0;
}