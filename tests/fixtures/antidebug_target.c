#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>

__attribute__((noinline))
int check_proc_tracerpid(void) {
    FILE *fp = fopen("/proc/self/status", "r");
    if (!fp) {
        return 0;
    }

    char line[256];
    int tracer_pid = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            tracer_pid = atoi(line + 10);
            break;
        }
    }
    fclose(fp);

    return (tracer_pid > 0) ? 1 : 0;
}

__attribute__((noinline))
int check_ptrace_traceme(void) {
    /* If a debugger is already attached, PTRACE_TRACEME will fail and return < 0 */
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) {
        return 1;
    }
    return 0;
}

__attribute__((noinline))
int is_debugger_present(void) {
    /* Check TracerPid first, then ptrace(PTRACE_TRACEME) */
    if (check_proc_tracerpid()) {
        return 1;
    }
    if (check_ptrace_traceme()) {
        return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    printf("[antidebug_target] Starting anti-analysis security verification...\n");
    fflush(stdout);

    if (is_debugger_present()) {
        printf("DEBUGGER_DETECTED\n");
        fflush(stdout);
        return 1;
    }

    printf("ACCESS_GRANTED_FLAG{rvs_dynamic_antidebug_bypassed_2026}\n");
    fflush(stdout);
    return 0;
}
