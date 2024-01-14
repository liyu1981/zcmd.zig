#include <signal.h>

int main() {
    raise(SIGTSTP);
}
