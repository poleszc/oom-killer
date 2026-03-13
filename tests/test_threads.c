#include <pthread.h>
#include <unistd.h>
#include <stdio.h>

void* thread_fn(void *arg) {
    while (1) sleep(1);
    return NULL;
}

int main() {
    pthread_t t;
    for (int i = 0; i < 150; i++) {
        if (pthread_create(&t, NULL, thread_fn, NULL) != 0)
            perror("pthread_create");
    }
    sleep(999999);
    return 0;
}

