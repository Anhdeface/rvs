#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Ensure functions are not inlined so backtrace has predictable frames */
__attribute__((noinline))
void trigger_null_deref(void) {
    fprintf(stderr, "[crash_target] Entering trigger_null_deref()...\n");
    volatile int *null_ptr = NULL;
    /* Predictable NULL pointer dereference triggering SIGSEGV (signal 11) */
    *null_ptr = 0xdeadbeef;
}

__attribute__((noinline))
void inner_fault_worker(int code) {
    if (code == 1337) {
        trigger_null_deref();
    } else {
        printf("[crash_target] Clean worker code: %d\n", code);
    }
}

__attribute__((noinline))
void dispatch_execution(int trigger) {
    inner_fault_worker(trigger);
}

int main(int argc, char **argv) {
    /* If argument 'safe' is passed, exit cleanly without crashing */
    if (argc > 1 && strcmp(argv[1], "safe") == 0) {
        printf("[crash_target] SAFE_EXECUTION_COMPLETED\n");
        return 0;
    }

    /* Default behavior or 'crash' argument: trigger deterministic SIGSEGV */
    printf("[crash_target] Initiating predictable crash sequence...\n");
    fflush(stdout);
    dispatch_execution(1337);

    return 0;
}
