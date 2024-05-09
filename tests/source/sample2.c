// gcc -c .\sample2.c -s -o sample2.o
// gcc -s -shared -o sample2.dll sample2.o
#include <stdio.h>

__declspec(dllexport) double Add(double a, double b) {
    return a + b;
}

__declspec(dllexport) double Subtract(double a, double b) {
    return a - b;
}

__declspec(dllexport) double Multiply(double a, double b) {
    return a * b;
}

__declspec(dllexport) double Divide(double a, double b) {
    if (b == 0) {
        return 0; 
    }
    return a / b;
}
