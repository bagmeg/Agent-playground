#include "vmlinux.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "GPL";

struct event {
	// struct __sk_buff skbaddr;
    // struct sock		skaddr;
    int				state;
    __u16			sport;
    __u16			dport;
    __u16			family;
    __u8			saddr[4];
    __u8			daddr[4];
    __u8			saddr_v6[16];
    __u8			daddr_v6[16];
} info = {};

struct bpf_map_def SEC("maps") events = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(struct event),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") kprobe_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u64),
	.max_entries = 1,
};

struct tcp_entry {
	__u64	        _unused;
	const void *	skbaddr;
    const void *	skaddr;
    int				state;
    __u16			sport;
    __u16			dport;
    __u16			family;
    __u8			saddr[4];
    __u8			daddr[4];
    __u8			saddr_v6[16];
    __u8			daddr_v6[16];
};

// const struct event *unused __attribute__((unused));

SEC("tracepoint/tcp_retransmit_skb")
int tcp_probe(struct tcp_entry* args) {
	// struct event info = {};
	struct event *valp;
	u32 key = 0;

	bpf_probe_read(&info.saddr, sizeof(info.saddr), &args->saddr);
	bpf_probe_read(&info.daddr, sizeof(info.daddr), &args->daddr);
	bpf_probe_read(&info.sport, sizeof(info.sport), &args->sport);
	bpf_probe_read(&info.dport, sizeof(info.dport), &args->dport);

	valp = bpf_map_lookup_elem(&events, &key);
	bpf_map_update_elem(&events, &key, &info, BPF_ANY);

	return 0;
}

SEC("tracepoint/sys_enter_execve")
int kprobe_execve() {
	u32 key     = 0;
	u64 initval = 1, *valp;

	valp = bpf_map_lookup_elem(&kprobe_map, &key);
	if (!valp) {
		bpf_map_update_elem(&kprobe_map, &key, &initval, BPF_ANY);
		return 0;
	}
	__sync_fetch_and_add(valp, 1);

	return 0;
}