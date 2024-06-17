#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/icmp.h>

#define NEW_IP_ADDR 0xC0A800C2  // Новый IP-адрес в формате 0xAABBCCDD (например, 10.0.0.2)
// #define NEW_IP_ADDR 0xC0A80001  // Новый IP-адрес в формате 0xAABBCCDD (например, 10.0.0.2)
#define SRC_IP_ADDR 0xC0A800C2
// #define NEW_IP_ADDR 0xC0A800C2  // Новый IP-адрес в формате 0xAABBCCDD (например, 10.0.0.2)
// #define SRC_IP_ADDR 0x7F000001


#define TARGET_IP      (0x7F000001) // 127.0.0.1 в хекс-формате
#define TARGET_IFINDEX (2)        // Индекс нового интерфейса

static inline __u16 csum_fold_helper(__u32 csum) {
    __u32 sum = csum;
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}

static inline __u16 ipv4_csum(__u32 csum, struct iphdr *iph) {
    csum = bpf_csum_diff(0, 0, (__be32 *)iph, sizeof(*iph), csum);
    return csum_fold_helper(csum);
}

static inline __u16 icmp_csum_diff(__u16 old_csum, __u16 old_val, __u16 new_val) {
    __u32 csum = (~old_csum & 0xffff) + (~old_val & 0xffff) + new_val;
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return ~csum;
}
SEC("xdp")
int xdp_redirect_icmp_main(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // bpf_printk("step 1");
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    // bpf_printk("dst mac: %x:%x:%x:%x:%x:%x",
    //     eth->h_dest[0],
    //     eth->h_dest[1],
    //     eth->h_dest[2],
    //     eth->h_dest[3],
    //     eth->h_dest[4],
    //     eth->h_dest[5]);

    // bpf_printk("step 2");
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // bpf_printk("step 3");
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    // bpf_printk("iph->daddr: 0x%x; required addr: 0x%x", iph->daddr, bpf_htonl(0xC0A8006B));
    if ((void *)(iph + 1) > data_end) {
        return XDP_PASS;
    }

    // Проверяем, что пакет пришел на loopback интерфейс (127.0.0.1)
    // bpf_printk("step 4");
    bpf_printk("\\----------------------------\\");
    bpf_printk("iph->saddr: 0x%x", iph->saddr);
    bpf_printk("iph->daddr: 0x%x", iph->daddr);

    if (iph->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmph = (struct icmphdr *)((void *)iph + (iph->ihl * 4));
        if ((void *)(icmph + 1) > data_end) {
            return XDP_PASS;
        }

        bpf_printk("icmp->type: %d", icmph->type);
    }

    bpf_printk("\\----------------------------\\");


    // bpf_printk("iph->protocol: %d", iph->protocol);
    if (iph->saddr == bpf_htonl(0xC0A80001)) {

        bpf_printk("step 5");
        // bpf_printk("iph->daddr: 0x%x; required addr: 0x%x", iph->daddr, bpf_htonl(0xC0A8006B));
        if (iph->protocol == IPPROTO_ICMP) {
        // if (iph->saddr == bpf_htonl(0xC0A800C2)) {
            struct icmphdr *icmph = (struct icmphdr *)((void *)iph + (iph->ihl * 4));
            bpf_printk("step 6");

            if ((void *)(icmph + 1) > data_end) {
                return XDP_PASS;
            }

            bpf_printk("step 7");

            // bpf_printk("change ip-addr");

            //18:c0:4d:0e:a1:38
            // eth->h_dest[0] = 0x38;
            // eth->h_dest[1] = 0xa1;
            // eth->h_dest[2] = 0x0e;
            // eth->h_dest[3] = 0x4d;
            // eth->h_dest[4] = 0xc0;
            // eth->h_dest[5] = 0x18;

            // eth->h_dest[5] = 0x38;
            // eth->h_dest[4] = 0xa1;
            // eth->h_dest[3] = 0x0e;
            // eth->h_dest[2] = 0x4d;
            // eth->h_dest[1] = 0xc0;
            // eth->h_dest[0] = 0x18;

            // // Подменяем IP-адрес назначения
            __u32 old_daddr = iph->daddr;
            iph->daddr = bpf_htonl(TARGET_IP);

            // Пересчитываем контрольную сумму IP-заголовка
            iph->check = 0;
            iph->check = ipv4_csum(0, iph);

            // // Пересчитываем контрольную сумму ICMP-заголовка
            __u16 old_csum = icmph->checksum;
            icmph->checksum = 0;
            icmph->checksum = icmp_csum_diff(old_csum, old_daddr >> 16, iph->daddr >> 16);
            icmph->checksum = icmp_csum_diff(icmph->checksum, old_daddr & 0xffff, iph->daddr & 0xffff);

            // Перенаправляем пакет на другой интерфейс
            return bpf_redirect(1, 0);
            // return XDP_TX;
        }
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";