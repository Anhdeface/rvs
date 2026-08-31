#include <stdio.h>
#include <stdlib.h>

int calc_factorial(int n) {
    int res = 1;
    for (int i = 1; i <= n; i++) {
        res *= i;
    }
    return res;
}

int calc_fibonacci(int n) {
    if (n <= 0) return 0;
    if (n == 1) return 1;
    return calc_fibonacci(n - 1) + calc_fibonacci(n - 2);
}

int calc_collatz_steps(int n) {
    int steps = 0;
    while (n > 1) {
        if (n % 2 == 0) {
            n = n / 2;
        } else {
            n = 3 * n + 1;
        }
        steps++;
    }
    return steps;
}

int calc_dispatch(int op, int a, int b) {
    switch (op) {
        case 1: return a + b;
        case 2: return a - b;
        case 3: return a * b;
        case 4: return (b != 0) ? (a / b) : 0;
        default: return -1;
    }
}

int main(int argc, char **argv) {
    int f5 = calc_factorial(5);        // 120
    int fib7 = calc_fibonacci(7);      // 13
    int col6 = calc_collatz_steps(6);  // 8 steps
    int disp = calc_dispatch(3, 6, 7); // 42

    printf("Factorial(5) = %d\n", f5);
    printf("Fibonacci(7) = %d\n", fib7);
    printf("Collatz(6) = %d\n", col6);
    printf("Dispatch(3,6,7) = %d\n", disp);

    if (f5 == 120 && fib7 == 13 && col6 == 8 && disp == 42) {
        printf("CALC_SUCCESS: All calculations matched\n");
        return 0;
    }

    printf("CALC_FAILED\n");
    return 1;
}
