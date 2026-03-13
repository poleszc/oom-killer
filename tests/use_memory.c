#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>

int main(void)
{
    size_t size = 1024ULL * 1024ULL * 1024ULL; /* 1 GB */
    size_t pagesz = sysconf(_SC_PAGESIZE);
    char *p = malloc(size);
    if (!p) {
        perror("malloc");
        return 1;
    }

    /* Touch one byte per page to ensure allocation */
    for (size_t off = 0; off < size; off += pagesz) {
        p[off] = 1;
    }

    printf("Allocated 1GB at %p, pid=%d\n", (void *)p, (int)getpid());
    fflush(stdout);

    /* Keep the process alive so the allocation remains resident */
    for (;;)
        pause();

    return 0;
}
