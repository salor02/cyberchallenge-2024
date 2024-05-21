// compilare con
// gcc -g -no-pie -o test_plt test_plt.c
#include <stdio.h>

int main(int argc, char ** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("hello");
    puts("world");
}