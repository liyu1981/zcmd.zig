#include <unistd.h>

void main() {
    int ret_value = 0xfdfc;  // 65532

    asm volatile(
        "mov w0, %w[ret_value]\n"  // move ret_value to w0
        "mov x16, #0x1\n"          // move 0x1 to x16, syscall no. 1 = exit
        "svc #0x80\n"              // arm64 system call [x16]
        "ret"
        : [ret_value] "=r"(ret_value)  // Input operand constraint for the variable
        // :                              // No output operand constraints
        // : "x16"                        // List of clobbered registers
    );
}
