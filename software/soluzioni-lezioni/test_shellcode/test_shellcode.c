// compilare con gcc -g -no-pie -fno-stack-protector -z execstack -o test_shellcode test_shellcode.c
# include <stdio.h>

void usefulFunction() {
    asm("jmp *%rsp");
}

int main(int argc, char *argv[]) {
    setvbuf(stdout, NULL, _IONBF, 0);
    char buffer[100];
    printf("Enter some text: ");
    scanf("%s", buffer);
    printf("You entered: %s\n", buffer);
    
}