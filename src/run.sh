clang --target=bpf -g -Og -c  omm_killer.bpf.c -o omm_killer.bpf.o
sudo bpftool gen skeleton  omm_killer.bpf.o name omm_killer > omm_killer.skel.h

gcc omm_killer.c -o omm_killer -lbpf -lelf -lz