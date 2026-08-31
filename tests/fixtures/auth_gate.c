#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int check_master_password(const char *pwd) {
    if (strcmp(pwd, "K3Y-V4L1D-2026") == 0) {
        return 1;
    }
    return 0;
}

int check_admin_pin(int pin) {
    if (pin == 7788) {
        return 1;
    }
    return 0;
}

int check_access_level(int level) {
    if (level >= 3) {
        return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    const char *pwd = (argc > 1) ? argv[1] : "WRONG_PASSWORD";
    int pin = (argc > 2) ? atoi(argv[2]) : 0;
    int level = (argc > 3) ? atoi(argv[3]) : 1;

    if (!check_master_password(pwd)) {
        printf("AUTH_FAIL: Bad Password\n");
        return 1;
    }
    if (!check_admin_pin(pin)) {
        printf("AUTH_FAIL: Bad PIN\n");
        return 2;
    }
    if (!check_access_level(level)) {
        printf("AUTH_FAIL: Insufficient Level\n");
        return 3;
    }

    printf("AUTH_SUCCESS: Access Granted\n");
    return 0;
}
