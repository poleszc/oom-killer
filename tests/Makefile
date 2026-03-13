CC = gcc
CFLAGS = -O2 -g -pthread


TARGETS = oomp_test_fds oomp_test_threads oomp_test_reads oomp_test_readv oomp_test_rw_below oomp_test_writes oomp_test_pwrite64 oomp_test_packets oomp_test_packets_udp oomp_test_rand
EXTRA_TARGETS = oomp_test_use_memory

all: $(TARGETS) $(EXTRA_TARGETS)

oomp_test_fds: test_fds.c
	$(CC) $(CFLAGS) test_fds.c -o oomp_test_fds

oomp_test_threads: test_threads.c
	$(CC) $(CFLAGS) test_threads.c -o oomp_test_threads

oomp_test_reads: test_reads.c
	$(CC) $(CFLAGS) test_reads.c -o oomp_test_reads

oomp_test_readv: test_readv.c
	$(CC) $(CFLAGS) test_readv.c -o oomp_test_readv

oomp_test_rw_below: test_rw_below.c
	$(CC) $(CFLAGS) test_rw_below.c -o oomp_test_rw_below

oomp_test_writes: test_writes.c
	$(CC) $(CFLAGS) test_writes.c -o oomp_test_writes

oomp_test_pwrite64: test_pwrite64.c
	$(CC) $(CFLAGS) test_pwrite64.c -o oomp_test_pwrite64

oomp_test_packets: test_packets.c
	$(CC) $(CFLAGS) test_packets.c -o oomp_test_packets
	sudo setcap cap_net_raw+ep oomp_test_packets

oomp_test_packets_udp: test_packets_udp.c
	$(CC) $(CFLAGS) test_packets_udp.c -o oomp_test_packets_udp

oomp_test_rand: test_rand.c
	$(CC) $(CFLAGS) test_rand.c -o oomp_test_rand

/* Build-only helper: allocate 1GB of memory (not part of test run list) */
oomp_test_use_memory: use_memory.c
	$(CC) $(CFLAGS) use_memory.c -o oomp_test_use_memory

test: $(TARGETS)
	@echo "Running OOM test programs..."
	@killed=0; \
    	alive=""; \
	for prog in $(TARGETS); do \
		echo "Starting $$prog..."; \
		./$$prog & \
		pid=$$!; \
		sleep 3; \
		if kill -0 $$pid 2>/dev/null; then \
			echo "  $$prog is STILL ALIVE (pid $$pid)"; \
			alive="$$alive $$prog"; \
		else \
			echo "  $$prog WAS KILLED"; \
			killed=$$((killed+1)); \
		fi; \
	done; \
	echo ""; \
	echo "==================== SUMMARY ===================="; \
	echo "Killed: $$killed"; \
	if [ -n "$$alive" ]; then \
		echo "Still alive: $$alive"; \
	else \
	echo "Still alive: none"; \
	fi; \
	echo "================================================="; \
	echo ""; \
	echo "Cleaning up remaining processes..."; \
	for prog in $(TARGETS); do \
		pids=$$(pgrep -f "^.*$$prog$$"); \
		if [ -n "$$pids" ]; then \
			echo "Killing $$prog ($$pids)"; \
			kill -9 $$pids 2>/dev/null || true; \
		fi; \
	done

clean:
	rm -f $(TARGETS) $(EXTRA_TARGETS)

