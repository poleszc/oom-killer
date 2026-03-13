#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

SEC("kprobe/do_nanosleep")
int handle(void *ctx)
{
    struct task_struct *task = (void *)bpf_get_current_task();
    int pid = BPF_CORE_READ(task, tgid);
    char comm[16];
    BPF_CORE_READ_STR_INTO(&comm, task, comm);

    bpf_printk("PID %d (%s) is sleeping", pid, comm);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";