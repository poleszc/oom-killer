// test_fds.c
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

int main() {
    for (int i = 0; i < 200; i++) {
        int fd = open("/dev/null", O_RDONLY);
        if (fd < 0) perror("open");
    }
    sleep(999999);
    return 0;
}

