#include <stdio.h>

int fun1(int a, int b) {
    return a > b;
}

void fun2() {

}


int main(void) {
    while (1) {
        int a = 1, b = 2;
        printf("fun1(%i, %i): %i\n", a, b, fun1(a, b));
        printf("fun1 @ %llx: ", fun1);
        for (int i = 0; i < (long) fun2 - (long) fun1; i++) {
            printf("%hhx ", ((char *) fun1)[i]);
        }
        printf("\n");
        sleep(1);
    }
}
