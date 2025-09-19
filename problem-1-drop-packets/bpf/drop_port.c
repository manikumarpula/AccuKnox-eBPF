// IMPORTANT: Include the main BPF header first to define essential types.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h> // <-- Add this header for IPPROTO_TCP

// Target port to drop packets on
#define TARGET_PORT 4040

// eBPF program to drop TCP packets on a specific port
SEC("xdp")
int drop_tcp_port(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  struct ethhdr *eth = data;
  if ((void *)eth + sizeof(*eth) > data_end)
    return XDP_PASS;

  if (eth->h_proto != __constant_htons(ETH_P_IP))
    return XDP_PASS;

  struct iphdr *ip = data + sizeof(*eth);
  if ((void *)ip + sizeof(*ip) > data_end)
    return XDP_PASS;

  if (ip->protocol != IPPROTO_TCP)
    return XDP_PASS;

  struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
  if ((void *)tcp + sizeof(*tcp) > data_end)
    return XDP_PASS;

  if (__constant_ntohs(tcp->dest) == TARGET_PORT) {
    return XDP_DROP;
  }

  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";