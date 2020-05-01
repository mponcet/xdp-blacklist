#include <uapi/linux/bpf.h>
#include <linux/kernel.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>

#define KBUILD_MODNAME "foo"

struct ipv4_key {
	u32 addr;
};

BPF_HASH(ipv4_blacklist, struct ipv4_key);

static int ipv4_is_blacklisted(u32 addr)
{
	struct ipv4_key key = { addr };

	if (ipv4_blacklist.lookup(&key))
	    return 1;

	return 0;
}

static struct ethhdr *ethhdr_ptr(struct xdp_md *ctx)
{
	struct ethhdr *ethhdr;

	if (ctx->data + sizeof(*ethhdr) > ctx->data_end)
		return NULL;

	return (struct ethhdr *)(unsigned long)ctx->data;
}

static struct iphdr *iphdr_ptr(struct xdp_md *ctx, struct ethhdr *ethhdr)
{
	struct iphdr *iphdr;

	if (ctx->data + sizeof(struct ethhdr) + sizeof(*iphdr) > ctx->data_end)
		return NULL;

	return (struct iphdr *)(unsigned long)(ctx->data + sizeof(struct ethhdr));
}


int xdp_main(struct xdp_md *ctx)
{
	struct ethhdr *ethhdr;
	struct iphdr *iphdr;

	ethhdr = ethhdr_ptr(ctx);
	if (!ethhdr)
		goto xdp_pass;

	if (ethhdr->h_proto == bpf_htons(ETH_P_IP)) {
		iphdr = iphdr_ptr(ctx, ethhdr);
		if (!iphdr)
			goto xdp_pass;

		if (ipv4_is_blacklisted(iphdr->saddr)) {
			bpf_trace_printk("ip in blacklist: DROP\n");
			return XDP_DROP;
		}
	}

xdp_pass:
	return XDP_PASS;
}
