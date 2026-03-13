#include <unistd.h>
#include <fcntl.h>

int main() {
    int fd = open("/dev/zero", O_RDONLY);
    char buf[4096];

    for (int i = 0; i < 3000; i++)
        read(fd, buf, sizeof(buf));

    sleep(999999);
    return 0;
}

