echo "Compiling BPF"
clang --target=bpf -g -Og -c  omm_killer.bpf.c -o omm_killer.bpf.o

echo "Generating skeleton"
sudo bpftool gen skeleton  omm_killer.bpf.o name omm_killer > omm_killer.skel.h

echo "Compiling loader"
gcc omm_killer.c -o omm_killer -lbpf -lelf -lz

sudo ./omm_killer