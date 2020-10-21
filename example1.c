#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include "xdp_helper.h"


BPF_PERCPU_ARRAY(rxcnt, long, 1);
BPF_ARRAY(sequence, u64, 1);

int xdp_simple_responder(struct xdp_md *ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
    struct ethhdr *eth = data;
    uint32_t key = 0;
    long *value;
    uint64_t nh_off;
    u16 h_proto;
    u32 ipproto;
    u64 zero = 0;
    nh_off = sizeof(*eth);

    if (data + nh_off  > data_end)
        return XDP_DROP;
	value = rxcnt.lookup(&key);
	if (value)
		*value += 1;

	uint64_t *counter = sequence.lookup(&key);
	if(counter)
		lock_xadd(counter, 1);

	h_proto = eth->h_proto;
    bpf_trace_printk("received eth packet \n");
    if (h_proto == htons(ETH_P_ARP)){
        return XDP_PASS;
    }
    else if(h_proto == htons(ETH_P_IP)){
        /*found ip packet*/
        bpf_trace_printk("received IP packet \n");
        struct iphdr *iph = data + nh_off;
		if ((void*)&iph[1] > data_end)
			return 0;

        ipproto = parse_ipv4(data, nh_off, data_end);
        bpf_trace_printk("IP protocol is %d\n", ipproto);
		if(ipproto == 254){ // a custom ip protol packet is found
			swap_eth(data);
			swap_ip(iph);
		}
        return XDP_PASS;

    }
    else{
        //NOT IP nor ARP packet
        return XDP_PASS; /*is it good?*/
    }

    return XDP_DROP;


}

