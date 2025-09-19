//go:build ignore

// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_COMM 16

// Map to hold the target TCP port, configured by the user-space loader.
struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __uint(max_entries, 1);
        __type(key, __u32);
        __type(value, __u16);
} target_port_map SEC(".maps");

// Map to hold the target process name, configured by the user-space loader.
struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __uint(max_entries, 1);
        __type(key, __u32);
        __type(value, char[MAX_COMM]);
} target_comm_map SEC(".maps");

// This program is attached to the cgroup/connect4 hook, which is far
// more efficient for this task than parsing every SKB.
SEC("cgroup/connect4")
int block_port(struct bpf_sock_addr *ctx) {
        char comm[MAX_COMM];
        __u32 key = 0;

        // Get the name of the process attempting the connection.
        bpf_get_current_comm(&comm, sizeof(comm));

        // Look up the target process name from the map.
        char *target_comm = bpf_map_lookup_elem(&target_comm_map, &key);
        if (!target_comm) {
                // If the map is not populated, do not interfere.
                return 1; // 1 means BPF_OK (allow)
        }

        // --- CORRECTED LOGIC ---
        // Check if the current process is the one we want to filter.
        for (int i = 0; i < MAX_COMM; i++) {
                if (comm[i] != target_comm[i]) {
                        // This is NOT our target process, so we allow its traffic unconditionally.
                        return 1; // BPF_OK
                }
                // If we reach the null terminator on both, it's a match.
                if (comm[i] == '\0') {
                        break;
                }
        }

        // --- IF WE ARE HERE, THE PROCESS NAME MATCHED ---
        // Now, apply the port filter.

        // Look up the target port from the map.
        __u16 *target_port = bpf_map_lookup_elem(&target_port_map, &key);
        if (!target_port) {
                // Map not populated, so allow.
                return 1; // BPF_OK
        }

        // The port in the context is in network byte order; convert it for comparison.
        if (bpf_ntohs(ctx->user_port) == *target_port) {
                // The process matches and the port is allowed.
                bpf_printk("Allowing %s to connect to port %d\n", comm, *target_port);
                return 1; // BPF_OK
        }

        // The process matches, but the port is NOT allowed.
        bpf_printk("Blocking %s from connecting to port %d\n", comm, bpf_ntohs(ctx->user_port));
        return 0; // 0 means BPF_DROP (deny)
}

char _license[] SEC("license") = "GPL";
