package bpf2go

// go run github.com/cilium/ebpf/cmd/bpf2go --help
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --go-package bpf2go -cc clang --cflags "-O0 -g" --cflags -D__x86_64__ MsgMonitor ../msg_monitor_bpf/msg_monitor_4.c
