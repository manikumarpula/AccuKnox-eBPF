#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

// Target port to drop packets on
#define TARGET_PORT 4040

// eBPF program to drop TCP packets on a specific port
SEC("xdp")
int drop_tcp_port(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  // Parse Ethernet header
  struct ethhdr *eth = data;
  if ((void *)eth + sizeof(*eth) > data_end)
    return XDP_PASS;

  // Only process IPv4 packets
  if (eth->h_proto != __constant_htons(ETH_P_IP))
    return XDP_PASS;

  // Parse IP header
  struct iphdr *ip = data + sizeof(*eth);
  if ((void *)ip + sizeof(*ip) > data_end)
    return XDP_PASS;

  // Only process TCP packets
  if (ip->protocol != IPPROTO_TCP)
    return XDP_PASS;

  // Parse TCP header
  struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
  if ((void *)tcp + sizeof(*tcp) > data_end)
    return XDP_PASS;

  // Check if destination port matches target port
  if (__constant_ntohs(tcp->dest) == TARGET_PORT) {
    // Drop the packet
    return XDP_DROP;
  }

  // Allow all other packets
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";