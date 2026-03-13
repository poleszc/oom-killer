#include <unistd.h>
#include <fcntl.h>

int main() {
    int fd = open("/dev/null", O_WRONLY);
    char buf[1] = {0};

    for (int i = 0; i < 500; i++)
        write(fd, buf, 1);

    sleep(999999);
    return 0;
}

