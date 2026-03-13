# OOM Killer

## Compile BPF:
```
clang --target=bpf -g -Og -c  omm_killer.bpf.c -o omm_killer.bpf.o
```
## Generate skeleton:
```
bpftool gen skeleton  example.bpf.o name example > example.skel.h
```