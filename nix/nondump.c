#define _GNU_SOURCE
#include <sys/prctl.h>

__attribute__((constructor)) static void secret_broker_nondump(void) {
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
}
