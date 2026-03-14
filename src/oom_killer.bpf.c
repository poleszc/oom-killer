#define __TARGET_ARCH_x86
#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


#define OOMP_LOG(fmt, ...)                            \
	do {                                              \
		if (isOomp()) bpf_printk(fmt, ##__VA_ARGS__); \
	} while (0)

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
__always_inline void checkPolicyAndKill(u32 pid, ProcessInfo* stats) {
	// if (ram_used < (1024ULL * 1024 * 1024)) return;
	if (!isOomp()) return;

	OOMP_LOG("Check policy and kill");

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


// ======== MEMORY =========

SEC("kretprobe/si_meminfo")

int BPF_KRETPROBE(si_meminfo_exit, struct sysinfo* info) {
	OOMP_LOG("ram used: %d\n", ram_used);
	u64 total_ram;
	u64 free_ram;
	u64 mem_unit;

	bpf_probe_read_kernel(&total_ram, sizeof(total_ram), &info->totalram);
	bpf_probe_read_kernel(&free_ram, sizeof(free_ram), &info->freeram);
	bpf_probe_read_kernel(&mem_unit, sizeof(mem_unit), &info->mem_unit);

	ram_used = (total_ram - free_ram) * mem_unit;
	return 0;
}

// ======== WRITES =========

static __always_inline __u32 getCurrentProcessPid() { return bpf_get_current_pid_tgid() >> 32; }

// Macro cause verifier gets confused when it's a function
#define GET_PROCESS_STATS(PID)                                       \
	ProcessInfo *process_stats, init_val = { 0 };                    \
	process_stats = bpf_map_lookup_elem(&process_map, &PID);         \
	if (!process_stats) {                                            \
		bpf_map_update_elem(&process_map, &pid, &init_val, BPF_ANY); \
		process_stats = bpf_map_lookup_elem(&process_map, &PID);     \
	}                                                                \
	if (!process_stats) return 0

// static __always_inline ProcessInfo* getProcessStatistics(__u32 pid) {
// 	ProcessInfo *process_stats, init_val = { 0 };
// 	process_stats = bpf_map_lookup_elem(&process_map, &pid);
// 	if (!process_stats) {
// 		bpf_map_update_elem(&process_map, &pid, &init_val, BPF_ANY);
// 		process_stats = bpf_map_lookup_elem(&process_map, &pid);
// 	}
// 	if (!process_stats) return 0;
// 	return process_stats;
// }

__always_inline int doHandleWrite(struct trace_event_raw_sys_enter* ctx) {
	u32 pid = getCurrentProcessPid();
	GET_PROCESS_STATS(pid);

	process_stats->write_count++;
	checkPolicyAndKill(pid, process_stats);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")

int handleWrite(struct trace_event_raw_sys_enter* ctx) { return doHandleWrite(ctx); }

SEC("tracepoint/syscalls/sys_enter_pwrite64")

int handlePWrite64(struct trace_event_raw_sys_enter* ctx) { return doHandleWrite(ctx); }


// ======== READS =========
// TODO: readV?
SEC("tracepoint/syscalls/sys_enter_read")

int handleRead(struct trace_event_raw_sys_enter* ctx) {
	__u32  pid       = getCurrentProcessPid();
	size_t read_size = ctx->args[2];
	GET_PROCESS_STATS(pid);
	process_stats->read_bytes += read_size;
	checkPolicyAndKill(pid, process_stats);
	return 0;
}

// ======== FILE DESCRIPTORS =========

static __always_inline int doHandleOpenExit(struct trace_event_raw_sys_exit* ctx) {
	// Don't count the FD if an error occurred.
	if (ctx->ret <= 0) return 0;
	__u32 pid = getCurrentProcessPid();
	GET_PROCESS_STATS(pid);

	process_stats->open_fds++;
	checkPolicyAndKill(pid, process_stats);
	return 0;
}


SEC("tracepoint/syscalls/sys_exit_openat")
int handleOpenFDExit(struct trace_event_raw_sys_exit* ctx) { return doHandleOpenExit(ctx); }

SEC("tracepoint/syscalls/sys_exit_socket")
int handleOpenSocketExit(struct trace_event_raw_sys_exit* ctx) { return doHandleOpenExit(ctx); }

SEC("tracepoint/syscalls/sys_enter_close")
int handleCloseEnter(struct trace_event_raw_sys_enter* ctx) {
	__u32 pid = getCurrentProcessPid();
	GET_PROCESS_STATS(pid);

	if (process_stats->open_fds > 0) process_stats->open_fds--;
	return 0;
}

static __always_inline int doHandleCloneExit(struct trace_event_raw_sys_exit* ctx) {
	// Don't count if the syscall failed or we're a child process.
	if (ctx->ret <= 0) return 0;

	__u32 pid = getCurrentProcessPid();
	GET_PROCESS_STATS(pid);

	process_stats->thread_count++;
	checkPolicyAndKill(pid, process_stats);
	return 0;
}


SEC("tracepoint/syscalls/sys_exit_clone")

int handleCloneExit(struct trace_event_raw_sys_exit* ctx) { return doHandleCloneExit(ctx); }

SEC("tracepoint/syscalls/sys_exit_clone3")

int handleClone3Exit(struct trace_event_raw_sys_exit* ctx) { return doHandleCloneExit(ctx); }
