#include "oom_killer.skel.h"

#include <stdio.h>
#include <sys/sysinfo.h>
#include <unistd.h>

int main() {
	struct oom_killer* skel = oom_killer__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open/load BPF object\n");
		return 1;
	}

	if (oom_killer__attach(skel)) {
		fprintf(stderr, "Failed to attach BPF program\n");
		goto cleanup;
	}

	for (;;) {
		struct sysinfo sys_info;
		sysinfo(&sys_info);
		printf(
			"Userspace says RAM used: %lu\n",
			(sys_info.totalram - sys_info.freeram) * sys_info.mem_unit
		);

		sleep(1);
	}

cleanup:
	oom_killer__destroy(skel);
	return 0;
}
