#define __TARGET_ARCH_x86
#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


char LICENSE[] SEC("license") = "GPL";

#define WRITE_COUNT_UPPER_BOUND      100
#define FD_COUNT_UPPER_BOUND         100
#define THREAD_COUNT_UPPER_BOUND     100
#define RAND_COUNT_UPPER_BOUND       100
#define TCP_PACKET_COUNT_UPPER_BOUND (1000)
#define READ_UPPER_BOUND             (1024ULL * 1024 * 10)

// ======== GLOBAL =========
/**
 * @brief The overall state for one process.
 */
typedef struct ProcessInfo {
	// Count of open file descriptors.
	__u64 open_fds;
	// Count of file writes.
	__u64 write_count;
	// Number of read bytes.
	__u64 read_bytes;
	// Number of spawned threads.
	__u64 thread_count;
	// Number of called rands.
	__u64 rand_count;
	// Number of sent TCP packages.
	__u64 tcp_packet_count;
} ProcessInfo;

/**
 * @brief ProcessInfo per PID.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 512 * 2);
	__type(key, __u32);
	__type(value, ProcessInfo);
} process_map SEC(".maps");

// RAM used by the process.
static __u64 ram_used = 0;

/**
 * @brief Whether a process has a `oomp` substring in its name.
 */
inline bool isOomp() {
	char comm[16];
	bpf_get_current_comm(&comm, sizeof(comm));

	for (int i = 0; i <= 16 - 4; i++)
		if (comm[i] == 'o' && comm[i + 1] == 'o' && comm[i + 2] == 'm' && comm[i + 3] == 'p')
			return true;
	return false;
}

// ======== HELPERS =========
inline void checkPolicyAndKill(u32 pid, ProcessInfo* stats) {
	if (ram_used < (1024ULL * 1024 * 1024)) return;
	if (!isOomp()) return;

	bpf_printk("Check policy and kill");

	bool kill = false;
	if (stats->write_count >= WRITE_COUNT_UPPER_BOUND) kill = true;
	if (stats->open_fds >= FD_COUNT_UPPER_BOUND) kill = true;
	if (stats->rand_count >= RAND_COUNT_UPPER_BOUND) kill = true;
	if (stats->thread_count >= THREAD_COUNT_UPPER_BOUND) kill = true;
	if (stats->tcp_packet_count >= TCP_PACKET_COUNT_UPPER_BOUND) kill = true;
	if (stats->read_bytes >= READ_UPPER_BOUND) kill = true;

	if (kill) bpf_send_signal(9);
	return;
}


// ======== HOOKS =========

SEC("kretprobe/si_meminfo")

int BPF_KRETPROBE(si_meminfo_exit, struct sysinfo* info) {
	// bpf_printk("SI_MEMINFO");
	u64 total_ram;
	u64 free_ram;
	u64 mem_unit;

	bpf_probe_read_kernel(&total_ram, sizeof(total_ram), &info->totalram);
	bpf_probe_read_kernel(&free_ram, sizeof(free_ram), &info->freeram);
	bpf_probe_read_kernel(&mem_unit, sizeof(mem_unit), &info->mem_unit);

	total_ram = (total_ram - free_ram) * mem_unit;
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")

int handleWrite(struct trace_event_raw_sys_enter* ctx) {
	u32          pid = bpf_get_current_pid_tgid() >> 32;
	ProcessInfo *process_stats, init_val = { 0 };

	if (isOomp()) bpf_printk("Write detected for PID %d", pid);

	process_stats = bpf_map_lookup_elem(&process_map, &pid);
	if (!process_stats) {
		bpf_map_update_elem(&process_map, &pid, &init_val, BPF_ANY);
		process_stats = bpf_map_lookup_elem(&process_map, &pid);
	}

	if (process_stats) {
		process_stats->write_count++;
		checkPolicyAndKill(pid, process_stats);
	}
	return 0;
}
