#include <linux/types.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/icmp.h>
#include <sys/cdefs.h>


#define DESTANETION_IP (0xC0A800C2) // 192.168.0.194 в хекс-формате
#define SOURCE_IP      (0xC0A80001) // 192.168.0.1   в хекс-формате
#define TARGET_IP      (0x7F000001) // 127.0.0.1     в хекс-формате
#define TARGET_IFINDEX (2)          // Индекс нового интерфейса

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 10);
    __type(key, __u32);
    __type(value, __u32);
} ip_black_list SEC(".maps");

static __always_inline __u16 csum_fold_helper(__u32 csum) {
    __u32 sum = csum;
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}

static __always_inline __u16 ipv4_csum(__u32 csum, struct iphdr *iph) {
    csum = bpf_csum_diff(0, 0, (__be32 *)iph, sizeof(*iph), csum);
    return csum_fold_helper(csum);
}

static __always_inline __u16 icmp_csum_diff(__u16 old_csum, __u16 old_val, __u16 new_val) {
    __u32 csum = (~old_csum & 0xffff) + (~old_val & 0xffff) + new_val;
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return ~csum;
}

static __always_inline void print_ip(const char* msg, __u32 ip) {
    bpf_printk("%s %d.%d.%d.%d", msg ? msg : "",
                                (ip & 0xFF000000) >> 24,
                                (ip & 0x00FF0000) >> 16,
                                (ip & 0x0000FF00) >> 8,
                                (ip & 0x000000FF));
}

SEC("xdp")
int redirect_icmp(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return XDP_PASS;
    }

    __u32 idx = 1;
    __u32* ip = bpf_map_lookup_elem(&ip_black_list, &idx);

    if (ip && *ip == bpf_ntohl(iph->saddr)) {
        print_ip("got black ip:", (*ip));
        return XDP_DROP;
    }

    // bpf_printk("\\----------------------------\\");
    // bpf_printk("iph->saddr: 0x%x", iph->saddr);
    // bpf_printk("iph->daddr: 0x%x", iph->daddr);
    // bpf_printk("\\----------------------------\\");

    if (iph->saddr == bpf_htonl(SOURCE_IP)) {

        if (iph->protocol == IPPROTO_ICMP) {
            struct icmphdr *icmph = (struct icmphdr *)((void *)iph + (iph->ihl * 4));

            if ((void *)(icmph + 1) > data_end) {
                return XDP_PASS;
            }

            // Подменяем IP-адрес назначения
            __u32 old_daddr = iph->daddr;
            iph->daddr = bpf_htonl(TARGET_IP);

            // Пересчитываем контрольную сумму IP-заголовка
            iph->check = 0;
            iph->check = ipv4_csum(0, iph);

            // Пересчитываем контрольную сумму ICMP-заголовка
            __u16 old_csum = icmph->checksum;
            icmph->checksum = 0;
            icmph->checksum = icmp_csum_diff(old_csum, old_daddr >> 16, iph->daddr >> 16);
            icmph->checksum = icmp_csum_diff(icmph->checksum, old_daddr & 0xffff, iph->daddr & 0xffff);

            // Перенаправляем пакет на другой интерфейс
            return bpf_redirect(TARGET_IFINDEX, 0);
        }
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";