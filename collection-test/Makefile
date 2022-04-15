CLANG = clang

CFLAGS = -O2 -target bpf

PROGRAM = collection-test

all: 

collection: clean vmlinux.h bpf_helpers.h generate
	go build -o $(PROGRAM) main.go bpf_bpfel.go

generate:
	go generate

vmlinux.h: 
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

bpf_helpers.h: bpf_helper_defs.h
	cp /usr/include/bpf/bpf_helpers.h ./bpf_helpers.h

bpf_helper_defs.h:
	cp /usr/include/bpf/bpf_helper_defs.h ./bpf_helper_defs.h

clean:
	rm -f bpf_helper_defs.h bpf_helpers.h vmlinux.h sock1.kern.o bpf_bpfel.* bpf_bpfeb.* $(PROGRAM)