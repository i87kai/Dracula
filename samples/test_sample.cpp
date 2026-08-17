#include <iostream>
#include <vector>
#include <numeric>

// Simple test binary that executes arithmetic, loops, and memory operations
int main() {
    volatile int sum = 0;
    for (int i = 1; i <= 10; ++i) {
        sum += i * i;
    }
    std::cout << "Computed sum: " << sum << std::endl;
    return sum;
}
