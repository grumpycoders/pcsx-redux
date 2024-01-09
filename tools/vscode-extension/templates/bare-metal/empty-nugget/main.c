#include "third_party/nugget/common/syscalls/syscalls.h"

int main() {
    ramsyscall_printf("Hello world!\\n");
    while (1)
        ;
}
