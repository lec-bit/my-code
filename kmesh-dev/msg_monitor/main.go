package main

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"msg_monitor/bpf2go"
	"net/http"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// /*

// #include "msg_monitor_bpf/common.h"
// */
// import "C"

// type SockDataArgs C.struct_sock_data_args_s

var opts ebpf.CollectionOptions
var object bpf2go.MsgMonitorObjects
var Cgroup2Path = "/sys/fs/cgroup/msg_monitor"
var key uint64
var key2 uint64
var value uint64
var iovlen uint64

type conn_id_s struct {
	tgid int // process id
	fd   int
}

type l7Direction int

const (
	l7Egress l7Direction = iota
	l7Ingress
	l7DirectUnknown
)

type connectionDataV4 struct {
	Iov    [1024]byte
	IovLen uint64
}

// 辅助函数检测消息类型
func detectMessageType(data []byte) string {
	if bytes.HasPrefix(data, []byte("HTTP/")) {
		return "response"
	}
	for _, method := range []string{"GET", "POST", "PUT", "DELETE"} {
		if bytes.HasPrefix(data, []byte(method)) {
			return "request"
		}
	}
	return "unknown"
}

func parseHTTPHeader(data []byte) (*http.Request, error) {
	reader := bufio.NewReader(bytes.NewReader(data))
	req, err := http.ReadRequest(reader)
	if err != nil {
		return nil, err
	}
	return req, nil
}

type KeyValue struct {
	Key   string
	Value string
}

func extractHeaders(header http.Header) []KeyValue {
	var headers []KeyValue
	for key, values := range header {

		value := ""
		for _, v := range values {
			if value != "" {
				value += ", "
			}
			value += v
		}
		headers = append(headers, KeyValue{Key: key, Value: value})
	}
	return headers
}

func main() {
	spec, err := bpf2go.LoadMsgMonitor()
	if err != nil || spec == nil {
		fmt.Printf("LoadMsgMonitor failed:%v", err)
		return
	}

	if err = spec.LoadAndAssign(&object, &opts); err != nil {
		fmt.Printf("LoadAndAssign failed:%+v", err)
		return
	}

	_, err = link.Kprobe("tcp_sendmsg", object.BpfTcpSendmsg, nil)
	if err != nil {
		fmt.Printf("tcp_sendmsg failed:%v", err)
		return
	}

	_, err = link.Kprobe("tcp_recvmsg", object.BpfTcpRecvmsg, nil)
	if err != nil {
		fmt.Printf("tcp_recvmsg  failed:%v", err)
		return
	}

	MapOfHttpProbe := object.MsgMonitorMaps.MapOfHttpProbe
	reader, err := ringbuf.NewReader(MapOfHttpProbe)
	if err != nil {
		fmt.Errorf("open metric notify ringbuf map FAILED, err: %v", err)
		return
	}
	defer func() {
		if err := reader.Close(); err != nil {
			fmt.Errorf("ringbuf reader Close FAILED, err: %v", err)
		}
	}()

	for {
		select {
		default:
			log.Printf("MetricController HTTP accesslog\r\n\n")

			rec := ringbuf.Record{}
			if err := reader.ReadInto(&rec); err != nil {
				log.Fatalf("ringbuf reader FAILED to read, err: %v", err)
				continue
			}

			if len(rec.RawSample) != int(unsafe.Sizeof(connectionDataV4{})) {
				log.Fatalf("wrong length %v of a msg, should be %v", len(rec.RawSample), int(unsafe.Sizeof(connectionDataV4{})))
				continue
			}
			rawData := rec.RawSample
			info := (*connectionDataV4)(unsafe.Pointer(&rawData[0]))

			if detectMessageType(info.Iov[:]) == "request" {
				httpHeader, err := parseHTTPHeader(info.Iov[:])
				if err != nil {
					log.Fatalf("parseHTTPHeader failed, err: %v", err)
				}

				proto := httpHeader.Proto
				path := httpHeader.URL.Path
				log.Printf("proto:%s\n path:%s", proto, path)
				headers := extractHeaders(httpHeader.Header)
				for _, h := range headers {
					log.Printf("%s: %s\n", h.Key, h.Value)
				}
			}
		}
	}
}
