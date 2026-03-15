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
#define TCP_PACKET_COUNT_UPPER_BOUND 1000
#define READ_UPPER_BOUND             (1024ULL * 1024 * 10)

// ======================= GLOBAL =======================
/**
 * @brief The overall state for one process.
 */
typedef struct ProcessInfo {
	// Number of open file descriptors.
	u64 open_fds;
	// Number of file writes.
	u64 write_count;
	// Number of read bytes.
	u64 read_bytes;
	// Number of spawned threads.
	u64 thread_count;
	// Number of called rands.
	u64 rand_count;
	// Number of sent TCP packages.
	u64 tcp_packet_count;
} ProcessInfo;

/**
 * @brief ProcessInfo per PID.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, u32);
	__type(value, ProcessInfo);
} process_map SEC(".maps");

// RAM used by the process.
static __u64 ram_used = 0;

// ======================= HELPERS =======================
#define OOMP_LOG(fmt, ...)                                   \
	do {                                                     \
		if (isOompProcess()) bpf_printk(fmt, ##__VA_ARGS__); \
	} while (0)

/**
 * @brief Whether a process has a `oomp` substring in its name.
 */
static __always_inline bool isOompProcess() {
	char comm[16] = {};
	bpf_get_current_comm(&comm, sizeof(comm));

	for (int i = 0; i <= 16 - 4; i++)
		if (comm[i] == 'o' && comm[i + 1] == 'o' && comm[i + 2] == 'm' && comm[i + 3] == 'p')
			return true;
	return false;
}

/**
 * @brief Get the PID of the current process.
 */
static __always_inline u32 getCurrentProcessPid() { return bpf_get_current_pid_tgid() >> 32; }

/**
 * @brief Get the statistics of the specified process or insert new statistics of the process didn't
 * exist in the map yet.
 */
static __always_inline ProcessInfo* getOrCreateProcessStats(u32 pid) {
	ProcessInfo* stats = bpf_map_lookup_elem(&process_map, &pid);
	if (!stats) {
		ProcessInfo init = { 0 };
		bpf_map_update_elem(&process_map, &pid, &init, BPF_NOEXIST);
		stats = bpf_map_lookup_elem(&process_map, &pid);
	}
	return stats;
}

static __always_inline void checkPolicyAndKill(u32 pid, ProcessInfo* stats) {
	// if (ram_used < (1024ULL * 1024 * 1024)) return;
	if (!isOompProcess()) return;

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

#define UPDATE_STATS(FIELD, AMOUNT)                        \
	do {                                                   \
		if (!isOompProcess()) return 0;                    \
		u32          pid   = getCurrentProcessPid();       \
		ProcessInfo* stats = getOrCreateProcessStats(pid); \
		if (!stats) return 0;                              \
		__sync_fetch_and_add(&stats->FIELD, AMOUNT);       \
		checkPolicyAndKill(pid, stats);                    \
	} while (0)

#define DEFINE_TRACEPOINT_EXIT_HANDLER(TRACEPOINT_NAME, FIELD_NAME, AMOUNT) \
	SEC("tracepoint/syscalls/" #TRACEPOINT_NAME)                            \
	int handle_##TRACEPOINT_NAME(struct trace_event_raw_sys_exit* ctx) {        \
		if (ctx->ret > 0) UPDATE_STATS(FIELD_NAME, AMOUNT);                 \
		return 0;                                                           \
	}

// ======================= MEMORY =======================
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

// ======================= WRITES =======================
DEFINE_TRACEPOINT_EXIT_HANDLER(sys_exit_write, write_count, 1);
DEFINE_TRACEPOINT_EXIT_HANDLER(sys_exit_pwrite64, write_count, 1);

// ======================= READS =======================
DEFINE_TRACEPOINT_EXIT_HANDLER(sys_exit_read, read_bytes, ctx->ret);
DEFINE_TRACEPOINT_EXIT_HANDLER(sys_exit_readv, read_bytes, ctx->ret);
DEFINE_TRACEPOINT_EXIT_HANDLER(sys_exit_preadv, read_bytes, ctx->ret);

// ======================= THREADS =======================
// Don't count if the syscall failed or we're a child process.
DEFINE_TRACEPOINT_EXIT_HANDLER(sys_exit_clone, thread_count, 1);
DEFINE_TRACEPOINT_EXIT_HANDLER(sys_exit_clone3, thread_count, 1);

// ======================= FILE DESCRIPTORS =======================
DEFINE_TRACEPOINT_EXIT_HANDLER(sys_exit_openat, open_fds, 1);
DEFINE_TRACEPOINT_EXIT_HANDLER(sys_exit_socket, open_fds, 1);

SEC("tracepoint/syscalls/sys_enter_close")
int handleCloseEnter(struct trace_event_raw_sys_enter* ctx) {
	if (!isOompProcess()) return 0;
	u32          pid           = getCurrentProcessPid();
	ProcessInfo* process_stats = getOrCreateProcessStats(pid);
	if (!process_stats) return 0;

	if (process_stats->open_fds > 0) __sync_fetch_and_sub(&process_stats->open_fds, 1);
	return 0;
}


// ======================= TCP =======================
SEC("tracepoint/syscalls/sys_enter_sendto")
int handleSendToEnter(struct trace_event_raw_sys_enter* ctx) {
	void* buf      = (void*) ctx->args[1];
	u8    protocol = 0;
	if (bpf_probe_read_user(&protocol, sizeof(protocol), buf + 9) == 0 && protocol == 6)
		UPDATE_STATS(tcp_packet_count, 1);
	return 0;
}

// ======================= RAND =======================
// https://github.com/cloudflare/ebpf_exporter/blob/master/examples/uprobe.bpf.c
// ldd /bin/ls | grep libc
SEC("uprobe/libc.so.6:rand")
int handleRand(struct pt_regs* ctx) {
	UPDATE_STATS(rand_count, 1);
	return 0;
}
