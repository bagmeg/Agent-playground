//go:build linux
// +build linux

// This program demonstrates attaching an eBPF program to a kernel symbol.
// The eBPF program will be attached to the start of the sys_execve
// kernel function and prints out the number of times it has been called
// every second.
package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc $BPF_CLANG -cflags $BPF_CFLAGS -type event bpf collection_test.c -- -I../headers

func main() {
	fn := "tcp_retransmit_skb"
	fn2 := "sys_enter_execve"

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("tcp", "tcp_retransmit_skb", objs.TcpProbe)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer tp.Close()

	tp2, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.KprobeExecve)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer tp2.Close()

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	log.Println("Waiting for events..")

	const mapKey uint32 = 0
	const mapKey2 uint32 = 0

	fmt.Printf("bpfObject: \n%+v\n", objs)
	for range ticker.C {
		// var value uint64
		var value bpfEvent
		var value2 uint64
		// if err := objs.Events.Lookup(mapKey, &value); err != nil {
		if err := objs.bpfMaps.Events.Lookup(mapKey, &value); err != nil {
			log.Fatalf("reading map: %v", err)
		}
		log.Printf("%s called %v %v %v %v\n", fn, value.Saddr, value.Daddr, value.Sport, value.Dport)
		if err := objs.bpfMaps.KprobeMap.Lookup(mapKey2, &value2); err != nil {
			log.Fatal("reading map: %v", err)
		}
		log.Printf("%s called %d times\n", fn2, value2)
	}
}

func IntToIP(ip uint32) string {
	result := make(net.IP, 4)
	result[0] = byte(ip)
	result[1] = byte(ip >> 8)
	result[2] = byte(ip >> 16)
	result[3] = byte(ip >> 24)
	return result.String()
}
