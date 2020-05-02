#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/kernel.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

struct ipv4_key {
	u32 addr;
};

BPF_HASH(ipv4_blacklist, struct ipv4_key);
BPF_HASH(ipv6_blacklist, struct in6_addr);

static int ipv4_is_blacklisted(u32 addr)
{
	struct ipv4_key key = { addr };

	if (ipv4_blacklist.lookup(&key))
	    return 1;

	return 0;
}

static int ipv6_is_blacklisted(struct in6_addr *addr)
{
	if (ipv6_blacklist.lookup(addr))
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

static struct ipv6hdr *ipv6hdr_ptr(struct xdp_md *ctx, struct ethhdr *ethhdr)
{
	struct ipv6hdr *ipv6hdr;

	if (ctx->data + sizeof(struct ethhdr) + sizeof(*ipv6hdr) > ctx->data_end)
		return NULL;

	return (struct ipv6hdr *)(unsigned long)(ctx->data + sizeof(struct ethhdr));
}

int xdp_main(struct xdp_md *ctx)
{
	struct ethhdr *ethhdr;
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;

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
	} else if (ethhdr->h_proto == bpf_htons(ETH_P_IPV6)) {
		ipv6hdr = ipv6hdr_ptr(ctx, ethhdr);
		if (!ipv6hdr)
			goto xdp_pass;

		if (ipv6_is_blacklisted(&ipv6hdr->saddr)) {
			bpf_trace_printk("ip6 in blacklist: DROP\n");
			return XDP_DROP;
		}
	}

xdp_pass:
	return XDP_PASS;
}
