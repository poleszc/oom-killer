#include <unistd.h>
#include <fcntl.h>
#include <sys/uio.h>

int main() {
    int fd = open("/dev/zero", O_RDONLY);
    char buf1[4096];
    char buf2[4096];
    struct iovec iov[2];

    iov[0].iov_base = buf1;
    iov[0].iov_len = sizeof(buf1);
    iov[1].iov_base = buf2;
    iov[1].iov_len = sizeof(buf2);
    for (int i = 0; i < 1500; i++)
        readv(fd, iov, 2);

    sleep(999999);
    return 0;
}
