#include "xdp_redirect_icmp.user.h"

#include <err.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <linux/bpf.h>
#include <linux/if_link.h>

int main(int argc, char **argv) {

    __u32 flags = XDP_FLAGS_SKB_MODE;
    struct xdp_redirect_icmp_bpf *obj;


    obj = xdp_redirect_icmp_bpf__open_and_load();
    if (!obj)
        err(1, "failed to open and/or load BPF object\n");

    bpf_xdp_attach(2, -1, flags, NULL);
    bpf_xdp_attach(2, bpf_program__fd(obj->progs.redirect_icmp), flags, NULL);

cleanup:
    xdp_redirect_icmp_bpf__destroy(obj);
}