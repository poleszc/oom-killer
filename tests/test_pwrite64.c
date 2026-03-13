#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>

int main() {
    int fd = open("/dev/null", O_WRONLY);
    char buf[1] = {0};

    for (int i = 0; i < 500; i++)
        pwrite64(fd, buf, 1, (off_t)i);

    sleep(999999);
    return 0;
}
