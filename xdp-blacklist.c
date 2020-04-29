#include <uapi/linux/bpf.h>

#define KBUILD_MODNAME "foo"

int xdp_main(struct xdp_md *ctx)
{
	return XDP_PASS;
}
