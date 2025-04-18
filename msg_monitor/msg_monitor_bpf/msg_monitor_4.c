#include "vmlinux.h"
#include "common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define bpf_section(NAME) __attribute__((section(NAME), used))

#define KPROBE(func, type) \
    bpf_section("kprobe/" #func) \
    int bpf_##func(struct type *ctx)

#define MAX_IOVEC 4
#define __MAX_CONCURRENCY   1000
#define IPV6_ADDR_LEN 16
#define CONN_DATA_MAX_SIZE 1024

struct http_probe_info {
    char data[CONN_DATA_MAX_SIZE];
    __u64 iov_len;
};

#ifndef bpf_memcpy
#define bpf_memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

// direction
enum {
    INVALID_DIRECTION = 0,
    INBOUND = 1,
    OUTBOUND = 2,
};

#define READ_KERN(ptr)                                                         \
    ({                                                                         \
        typeof(ptr) _val;                                                      \
        __builtin_memset((void *)&_val, 0, sizeof(_val));                      \
        bpf_core_read((void *)&_val, sizeof(_val), &ptr);                      \
        _val;                                                                  \
    })

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 * 1024 /* 8 KB */);
} map_of_http_probe SEC(".maps");

int bpf_read_kern(void *dst, const void *src, int size)
{
    int ret = 0;
    if (size <= 0) {
        return -1;
    }
    ret = bpf_probe_read_kernel(dst, size, src);
    if (ret != 0) {
        bpf_printk("bpf_read_kern error: %d\n", ret);
        return -1;
    }
    return 0;
}


KPROBE(tcp_sendmsg, pt_regs)
{
    struct sock *l_sock = (struct sock *)PT_REGS_PARM1(ctx);
    struct msghdr *const msg = (struct msghdr *)PT_REGS_PARM2(ctx);
    __u64 iov_len = 0;


    int ret = 0;
    struct http_probe_info *info = NULL;
    struct iovec *iov_ptr = NULL;
    char iov_base[256] = {};
    __u64 tmp_iov_len = 0;


    if (l_sock == NULL) {
        bpf_printk("l_sock is NULL\n");
        return 0;
    }

    if (bpf_core_field_exists(msg->msg_iter.__iov))
        iov_ptr = (struct iovec *)READ_KERN(msg->msg_iter.__iov);
    else if (bpf_core_field_exists(msg->msg_iter.kvec))
        iov_ptr = (struct iovec *)READ_KERN(msg->msg_iter.kvec);

    if (iov_ptr == NULL) {
        bpf_printk("iov_ptr is NULL\n");
    }

    ret = bpf_probe_read_user(&iov_len, sizeof(__u64), &iov_ptr->iov_len);
    if (ret != 0) {
        bpf_printk("3 ret:%d\n", ret);
        return 0;
    }
    
    if (iov_len < 0) {
        return 0;
    }

    tmp_iov_len = 256;
    ret = bpf_probe_read_user(iov_base, tmp_iov_len, &iov_ptr->iov_base);
    if (ret != 0) {
        bpf_printk("5 ret:%d\n", ret);
        return 0;
    }

    if (__builtin_memcmp(iov_base, "GET", 3) == 0 || 
        __builtin_memcmp(iov_base, "POST", 4) == 0 ||
        __builtin_memcmp(iov_base, "PUT", 3) == 0 ||
        __builtin_memcmp(iov_base, "DELETE", 6) == 0 ||
        __builtin_memcmp(iov_base, "HEAD", 4) == 0 ||
        __builtin_memcmp(iov_base, "OPTIONS", 7) == 0 ||
        __builtin_memcmp(iov_base, "PATCH", 5) == 0 ||
        __builtin_memcmp(iov_base, "HTTP", 4) == 0)
    {
    //     bpf_printk("iov.iov_base:  %s\n", iov_base);
    // }

    // if (__builtin_memcmp(iov_base, "GET", 3) == 0)
    // {

        u32 src_ip4 = BPF_CORE_READ(l_sock, __sk_common.skc_rcv_saddr);
        u16 src_port = bpf_ntohs(READ_KERN(l_sock->__sk_common.skc_num));
        u32 dst_ip4 = READ_KERN(l_sock->__sk_common.skc_daddr);
        u16 dst_port = bpf_ntohs(READ_KERN(l_sock->__sk_common.skc_dport));
        bpf_printk("src_ip4:%u, src_port:%d\n", src_ip4, src_port);
        bpf_printk("dst_ip4:%u, dst_port:%d\n", dst_ip4, dst_port);

        bpf_printk("iov_base is true\n");
        bpf_printk("really iov_len is %d\n", iov_len);
        bpf_printk("iov.iov_base:  %s\n", iov_base);

        info = bpf_ringbuf_reserve(&map_of_http_probe, sizeof(struct http_probe_info), 0);
        if (info == NULL) {
            bpf_printk("info is NULL");
            return 0;
        }
        if (iov_len > CONN_DATA_MAX_SIZE)
            iov_len = CONN_DATA_MAX_SIZE;
        bpf_probe_read_user(info->data, iov_len, &iov_ptr->iov_base);
        info->iov_len = iov_len;
        bpf_ringbuf_submit(info, 0);
    }
    return 1;
}

KPROBE(tcp_recvmsg, pt_regs)
{
    struct sock *l_sock = (struct sock *)PT_REGS_PARM1(ctx);
    struct msghdr *const msg = (struct msghdr *)PT_REGS_PARM2(ctx);
    struct iovec *iov_ptr = NULL;
    __u64 iov_len = 0;
    __u64 tmp_iov_len = 0;
    char iov_base[256] = {};
    int ret = 0;
    struct http_probe_info *info = NULL;

    if (l_sock == NULL) {
        bpf_printk("l_sock is NULL\n");
        return 0;
    }

    //bpf_printk("tcp_recvmsg\n");
    if (bpf_core_field_exists(msg->msg_iter.__iov))
        iov_ptr = (struct iovec *)READ_KERN(msg->msg_iter.__iov);
    else if (bpf_core_field_exists(msg->msg_iter.kvec))
        iov_ptr = (struct iovec *)READ_KERN(msg->msg_iter.kvec);

    if (iov_ptr == NULL) {
        bpf_printk("iov_ptr is NULL\n");
        return 0;
    }

    tmp_iov_len = 256;
    ret = bpf_probe_read(iov_base, tmp_iov_len, &iov_ptr->iov_base);
    if (ret != 0) {
        bpf_printk("recvmsg 5 ret:%d\n", ret);
        return 0;
    }
    ret = bpf_probe_read(&iov_len, sizeof(__u64), &iov_ptr->iov_len);
    if (ret != 0) {
        bpf_printk("recvmsg 3 ret:%d\n", ret);
        return 0;
    }

    //bpf_printk("recvmsg iov.iov_base:  %s\n", iov_base);
    if (__builtin_memcmp(iov_base, "GET", 3) == 0 || 
        __builtin_memcmp(iov_base, "POST", 4) == 0 ||
        __builtin_memcmp(iov_base, "PUT", 3) == 0 ||
        __builtin_memcmp(iov_base, "DELETE", 6) == 0 ||
        __builtin_memcmp(iov_base, "HEAD", 4) == 0 ||
        __builtin_memcmp(iov_base, "OPTIONS", 7) == 0 ||
        __builtin_memcmp(iov_base, "PATCH", 5) == 0 ||
        __builtin_memcmp(iov_base, "HTTP", 4) == 0)
    {
        u32 src_ip4 = READ_KERN(l_sock->__sk_common.skc_rcv_saddr);
        u16 src_port = bpf_ntohs(READ_KERN(l_sock->__sk_common.skc_num));
        u32 dst_ip4 = READ_KERN(l_sock->__sk_common.skc_daddr);
        u16 dst_port = bpf_ntohs(READ_KERN(l_sock->__sk_common.skc_dport));
        bpf_printk("src_ip4:%u, src_port:%d\n", src_ip4, src_port);
        bpf_printk("dst_ip4:%u, dst_port:%d\n", dst_ip4, dst_port);
        bpf_printk("recvmsg iov.iov_len: %d\n", iov_len);
        bpf_printk("recvmsg iov.iov_base:  %s\n", iov_base);
    }
    return 1;
}
char __license[] SEC("license") = "Dual BSD/GPL";