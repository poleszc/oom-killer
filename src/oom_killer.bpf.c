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
#define READ_UPPER_BOUND             (1024ULL * 1024 * 10)    // 10 MB
#define RAM_THRESHOLD                (1024ULL * 1024 * 1024)  // 1 GB
#define TCP_PROTOCOL_TYPE            6
#define PROTOCOL_TYPE_OFFSET         9

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

/**
 * @brief One element map storing the current ram usage.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} ram_used_map SEC(".maps");

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
	u32  key      = 0;
	u64* ram_used = bpf_map_lookup_elem(&ram_used_map, &key);
	if (!ram_used) return;

	if (*ram_used < RAM_THRESHOLD) return;
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

/**
 * @brief Helper macro for updating process statistics @p FIELD by a given @p AMOUNT.
 * Performs additional bound checks if @p AMOUNT is negative, so the count can't get negative.
 * @note `if (!stats)` does not need to be here, but the verifier gest confused otherwise.
 */
#define UPDATE_STATS(FIELD, AMOUNT)                                                     \
	do {                                                                                \
		if (!isOompProcess()) return 0;                                                 \
		u32          pid   = getCurrentProcessPid();                                    \
		ProcessInfo* stats = getOrCreateProcessStats(pid);                              \
		if (!stats) return 0;                                                           \
		if (AMOUNT < 0) {                                                               \
			if (stats->FIELD > 0) { __sync_fetch_and_sub(&stats->FIELD, -1 * AMOUNT); } \
		} else {                                                                        \
			__sync_fetch_and_add(&stats->FIELD, AMOUNT);                                \
		}                                                                               \
		checkPolicyAndKill(pid, stats);                                                 \
	} while (0)

/**
 * @brief Helper macro to register for the @p TRACEPOINT_NAME exit tracepoint, update the
 * appropriate @p FIELD_NAME in the process statistics map by a given @p AMOUNT only if the return
 * value compares to 0 with the given @p RET_VAL_CMP.
 */
#define DEFINE_TRACEPOINT_EXIT_HANDLER(TRACEPOINT_NAME, FIELD_NAME, AMOUNT, RET_VAL_CMP) \
	SEC("tracepoint/syscalls/" #TRACEPOINT_NAME)                                         \
	int handle_##TRACEPOINT_NAME(struct trace_event_raw_sys_exit* ctx) {                 \
		if (ctx->ret RET_VAL_CMP 0) UPDATE_STATS(FIELD_NAME, AMOUNT);                    \
		return 0;                                                                        \
	}

// ======================= MEMORY =======================

/**
 * @brief A map storing pointer to `sysinfo` structures.
 * The problem is, that we have access to the `sysinfo` struct at entry, but it's filled with data
 * during execution. When exiting `meminfo` we only have access to the return code, thus we save the
 * passed pointer to `sysinfo` and then read it's contents on exit.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u32);
	__type(value, u64);
} sysinfo_ptr_map SEC(".maps");


SEC("kprobe/si_meminfo")
int BPF_KPROBE(si_meminfo_enter, struct sysinfo* info) {
	u32 tid  = bpf_get_current_pid_tgid();
	u64 addr = (u64) info;
	// Save the argument pointer.
	bpf_map_update_elem(&sysinfo_ptr_map, &tid, &addr, BPF_ANY);
	return 0;
}

SEC("kretprobe/si_meminfo")
int BPF_KRETPROBE(si_meminfo_exit) {
	u32  tid      = bpf_get_current_pid_tgid();
	u64* addr_ptr = bpf_map_lookup_elem(&sysinfo_ptr_map, &tid);
	if (!addr_ptr) return 0;

	// Now that `sysinfo` is filled with data after `meminfo` executed, we retrieve it.
	struct sysinfo* info = (struct sysinfo*) *addr_ptr;

	u64 total_ram = 0, free_ram = 0, mem_unit = 0;
	total_ram = BPF_CORE_READ(info, totalram);
	free_ram  = BPF_CORE_READ(info, freeram);
	mem_unit  = BPF_CORE_READ(info, mem_unit);

	u64 ram_used = (total_ram - free_ram) * mem_unit;

	// Update the global ram usage.
	u32 key = 0;
	bpf_map_update_elem(&ram_used_map, &key, &ram_used, BPF_ANY);

	bpf_map_delete_elem(&sysinfo_ptr_map, &tid);

	return 0;
}

// Some of those are not needed to pass the tests, but I added them for the killer to be more solid.
// ======================= WRITES =======================
DEFINE_TRACEPOINT_EXIT_HANDLER(sys_exit_write, write_count, 1, >);
DEFINE_TRACEPOINT_EXIT_HANDLER(sys_exit_pwrite64, write_count, 1, >);
DEFINE_TRACEPOINT_EXIT_HANDLER(sys_exit_writev, write_count, 1, >);
DEFINE_TRACEPOINT_EXIT_HANDLER(sys_exit_pwritev, write_count, 1, >);
DEFINE_TRACEPOINT_EXIT_HANDLER(sys_exit_pwritev2, write_count, 1, >);

// ======================= READS =======================
DEFINE_TRACEPOINT_EXIT_HANDLER(sys_exit_read, read_bytes, ctx->ret, >);
DEFINE_TRACEPOINT_EXIT_HANDLER(sys_exit_readv, read_bytes, ctx->ret, >);
DEFINE_TRACEPOINT_EXIT_HANDLER(sys_exit_pread64, read_bytes, ctx->ret, >);
DEFINE_TRACEPOINT_EXIT_HANDLER(sys_exit_preadv, read_bytes, ctx->ret, >);
DEFINE_TRACEPOINT_EXIT_HANDLER(sys_exit_preadv2, read_bytes, ctx->ret, >);

// ======================= THREADS =======================
// Don't count if the syscall failed or we're a child process -> ctx->ret > 0
DEFINE_TRACEPOINT_EXIT_HANDLER(sys_exit_clone, thread_count, 1, >);
DEFINE_TRACEPOINT_EXIT_HANDLER(sys_exit_clone3, thread_count, 1, >);

// ======================= FILE DESCRIPTORS =======================
DEFINE_TRACEPOINT_EXIT_HANDLER(sys_exit_openat, open_fds, 1, >);

DEFINE_TRACEPOINT_EXIT_HANDLER(sys_exit_open, open_fds, 1, >);
DEFINE_TRACEPOINT_EXIT_HANDLER(sys_exit_creat, open_fds, 1, >);
DEFINE_TRACEPOINT_EXIT_HANDLER(sys_exit_socket, open_fds, 1, >);
DEFINE_TRACEPOINT_EXIT_HANDLER(sys_exit_accept, open_fds, 1, >);
DEFINE_TRACEPOINT_EXIT_HANDLER(sys_exit_accept4, open_fds, 1, >);
DEFINE_TRACEPOINT_EXIT_HANDLER(sys_exit_dup, open_fds, 1, >);
DEFINE_TRACEPOINT_EXIT_HANDLER(sys_exit_dup2, open_fds, 1, >);
DEFINE_TRACEPOINT_EXIT_HANDLER(sys_exit_dup3, open_fds, 1, >);
// Pipe creates two fds. Returns 0 on success.
DEFINE_TRACEPOINT_EXIT_HANDLER(sys_exit_pipe, open_fds, 2, ==);
DEFINE_TRACEPOINT_EXIT_HANDLER(sys_exit_pipe2, open_fds, 2, ==);

DEFINE_TRACEPOINT_EXIT_HANDLER(sys_exit_close, open_fds, -1, ==);

// ======================= TCP =======================
SEC("tracepoint/syscalls/sys_enter_sendto")
int handleSendToEnter(struct trace_event_raw_sys_enter* ctx) {
	void* buf = (void*) ctx->args[1];
	// Read the protocol type from the header.
	// https://en.wikipedia.org/wiki/IPv4#Header
	u8 protocol = 0;
	if (bpf_probe_read_user(&protocol, sizeof(protocol), buf + PROTOCOL_TYPE_OFFSET) == 0
	    && protocol == TCP_PROTOCOL_TYPE)
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
