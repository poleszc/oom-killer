#include <unistd.h>
#include <fcntl.h>

int main() {
    int rfd = open("/dev/zero", O_RDONLY);
    int wfd = open("/dev/null", O_WRONLY);
    char rbuf[1];
    char wbuf[1] = {0};

    for (int i = 0; i < 10; i++)
        read(rfd, rbuf, 1);

    for (int i = 0; i < 10; i++)
        write(wfd, wbuf, 1);

    sleep(999999);
    return 0;
}
