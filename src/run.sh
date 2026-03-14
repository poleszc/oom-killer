echo "Compiling BPF"
clang --target=bpf -g -Og -c  oom_killer.bpf.c -o oom_killer.bpf.o

echo "Generating skeleton"
sudo bpftool gen skeleton  oom_killer.bpf.o name oom_killer > oom_killer.skel.h

echo "Compiling loader"
gcc oom_killer.c -o oom_killer -lbpf -lelf -lz

sudo ./oom_killer