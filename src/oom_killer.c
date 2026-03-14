#include "omm_killer.skel.h"

#include <stdio.h>
#include <sys/sysinfo.h>
#include <unistd.h>

int main() {
	struct omm_killer* skel = omm_killer__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open/load BPF object\n");
		return 1;
	}

	if (omm_killer__attach(skel)) {
		fprintf(stderr, "Failed to attach BPF program\n");
		goto cleanup;
	}

	printf("OMM Killer running\n");
	for (;;) {
		struct sysinfo sys_info;
		sysinfo(&sys_info);

		sleep(1);
	}


	pause();

cleanup:
	omm_killer__destroy(skel);
	return 0;
}
