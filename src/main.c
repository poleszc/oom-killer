#include "omm_killer.skel.h"

#include <unistd.h>

int main() {
	struct omm_killer* skel;
	int                err = 0;

	skel = omm_killer__open();
	if (!skel) goto cleanup;

	err = omm_killer__load(skel);
	if (err) goto cleanup;

	err = omm_killer__attach(skel);
	if (err) goto cleanup;

	pause();

cleanup:
	omm_killer__destroy(skel);
	return err;
}
