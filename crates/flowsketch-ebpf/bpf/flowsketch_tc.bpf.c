// SPDX-License-Identifier: Apache-2.0
// FlowSketch tc ingress collector: parse metadata, never alter packets.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <linux/types.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

const volatile __u16 FLOWSKETCH_ABI_VERSION = 1;

enum counter_id {
    COUNTER_PACKETS = 0,
    COUNTER_EMITTED = 1,
    COUNTER_RING_DROPS = 2,
    COUNTER_PARSE_ERRORS = 3,
    COUNTER_UNSUPPORTED = 4,
    COUNTER_COUNT = 5,
};

struct flowsketch_event {
    __u64 ts_nanos;
    __u8 src_ip[16];
    __u8 dst_ip[16];
    __u32 bytes;
    __u32 interface_index;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 ip_version;
    __u8 tcp_flags;
    __u8 direction;
};

_Static_assert(sizeof(struct flowsketch_event) == 56, "eBPF event ABI size changed");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024);
} EVENTS SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, COUNTER_COUNT);
    __type(key, __u32);
    __type(value, __u64);
} COUNTERS SEC(".maps");

struct vlan_header {
    __be16 tci;
    __be16 encapsulated_protocol;
};

struct ipv4_header {
    __u8 version_ihl;
    __u8 tos;
    __be16 total_length;
    __be16 identification;
    __be16 fragment_offset;
    __u8 ttl;
    __u8 protocol;
    __be16 checksum;
    __be32 source;
    __be32 destination;
};

struct ipv6_header {
    __be32 version_traffic_flow;
    __be16 payload_length;
    __u8 next_header;
    __u8 hop_limit;
    __u8 source[16];
    __u8 destination[16];
};

struct ipv6_extension {
    __u8 next_header;
    __u8 length;
};

struct ipv6_fragment {
    __u8 next_header;
    __u8 reserved;
    __be16 fragment_offset;
    __be32 identification;
};

struct tcp_minimum {
    __be16 source;
    __be16 destination;
    __be32 sequence;
    __be32 acknowledgement;
    __u8 data_offset;
    __u8 flags;
};

struct udp_header {
    __be16 source;
    __be16 destination;
    __be16 length;
    __be16 checksum;
};

enum parse_result {
    PARSE_OK = 0,
    PARSE_ERROR = 1,
    PARSE_UNSUPPORTED = 2,
};

static __always_inline void increment_counter(__u32 index)
{
    __u64 *value = bpf_map_lookup_elem(&COUNTERS, &index);

    if (value)
        (*value)++;
}

static __always_inline int load_bytes(struct __sk_buff *skb, __u32 offset,
                                      void *destination, __u32 length)
{
    if (offset > skb->len || length > skb->len - offset)
        return -1;
    return bpf_skb_load_bytes(skb, offset, destination, length);
}

static __always_inline int parse_transport(struct __sk_buff *skb, __u32 offset,
                                           __u32 end, __u8 protocol,
                                           struct flowsketch_event *event)
{
    event->protocol = protocol;
    if (protocol == 6) {
        struct tcp_minimum tcp = {};
        __u32 header_length;

        if (offset > end || sizeof(tcp) > end - offset ||
            load_bytes(skb, offset, &tcp, sizeof(tcp)) < 0)
            return PARSE_ERROR;
        header_length = (__u32)(tcp.data_offset >> 4) * 4;
        if (header_length < 20 || header_length > end - offset)
            return PARSE_ERROR;
        event->src_port = bpf_ntohs(tcp.source);
        event->dst_port = bpf_ntohs(tcp.destination);
        event->tcp_flags = tcp.flags;
    } else if (protocol == 17) {
        struct udp_header udp = {};
        __u16 udp_length;

        if (offset > end || sizeof(udp) > end - offset ||
            load_bytes(skb, offset, &udp, sizeof(udp)) < 0)
            return PARSE_ERROR;
        udp_length = bpf_ntohs(udp.length);
        if (udp_length < sizeof(udp) || udp_length > end - offset)
            return PARSE_ERROR;
        event->src_port = bpf_ntohs(udp.source);
        event->dst_port = bpf_ntohs(udp.destination);
    }
    return PARSE_OK;
}

static __always_inline int parse_ipv4(struct __sk_buff *skb, __u32 offset,
                                      struct flowsketch_event *event)
{
    struct ipv4_header ip = {};
    __u32 header_length;
    __u32 total_length;
    __u16 fragment_offset;

    if (load_bytes(skb, offset, &ip, sizeof(ip)) < 0)
        return PARSE_ERROR;
    if ((ip.version_ihl >> 4) != 4)
        return PARSE_ERROR;
    header_length = (__u32)(ip.version_ihl & 0x0f) * 4;
    total_length = bpf_ntohs(ip.total_length);
    if (header_length < sizeof(ip) || total_length < header_length ||
        offset > skb->len || total_length > skb->len - offset)
        return PARSE_ERROR;

    event->ip_version = 4;
    event->bytes = total_length;
    __builtin_memcpy(&event->src_ip[12], &ip.source, sizeof(ip.source));
    __builtin_memcpy(&event->dst_ip[12], &ip.destination, sizeof(ip.destination));
    fragment_offset = bpf_ntohs(ip.fragment_offset);
    if ((fragment_offset & 0x1fff) != 0) {
        event->protocol = ip.protocol;
        return PARSE_OK;
    }
    return parse_transport(skb, offset + header_length, offset + total_length,
                           ip.protocol, event);
}

static __always_inline int is_ipv6_extension(__u8 protocol)
{
    return protocol == 0 || protocol == 43 || protocol == 44 ||
           protocol == 51 || protocol == 60;
}

static __always_inline int parse_ipv6(struct __sk_buff *skb, __u32 offset,
                                      struct flowsketch_event *event)
{
    struct ipv6_header ip = {};
    __u32 payload_length;
    __u32 end;
    __u32 cursor;
    __u8 protocol;

    if (load_bytes(skb, offset, &ip, sizeof(ip)) < 0)
        return PARSE_ERROR;
    if ((bpf_ntohl(ip.version_traffic_flow) >> 28) != 6)
        return PARSE_ERROR;
    payload_length = bpf_ntohs(ip.payload_length);
    if (payload_length == 0)
        return PARSE_UNSUPPORTED; // IPv6 jumbograms are intentionally out of scope.
    if (offset > skb->len || sizeof(ip) + payload_length > skb->len - offset)
        return PARSE_ERROR;

    end = offset + sizeof(ip) + payload_length;
    cursor = offset + sizeof(ip);
    protocol = ip.next_header;
    event->ip_version = 6;
    event->bytes = sizeof(ip) + payload_length;
    __builtin_memcpy(event->src_ip, ip.source, sizeof(ip.source));
    __builtin_memcpy(event->dst_ip, ip.destination, sizeof(ip.destination));

#pragma unroll
    for (int index = 0; index < 6; index++) {
        struct ipv6_extension extension = {};
        __u32 extension_length;

        if (!is_ipv6_extension(protocol))
            break;
        if (protocol == 44) {
            struct ipv6_fragment fragment = {};

            if (cursor > end || sizeof(fragment) > end - cursor ||
                load_bytes(skb, cursor, &fragment, sizeof(fragment)) < 0)
                return PARSE_ERROR;
            protocol = fragment.next_header;
            if ((bpf_ntohs(fragment.fragment_offset) & 0xfff8) != 0) {
                event->protocol = protocol;
                return PARSE_OK;
            }
            cursor += sizeof(fragment);
            continue;
        }
        if (cursor > end || sizeof(extension) > end - cursor ||
            load_bytes(skb, cursor, &extension, sizeof(extension)) < 0)
            return PARSE_ERROR;
        extension_length = protocol == 51
                               ? ((__u32)extension.length + 2) * 4
                               : ((__u32)extension.length + 1) * 8;
        if (extension_length < 8 || extension_length > end - cursor)
            return PARSE_ERROR;
        protocol = extension.next_header;
        cursor += extension_length;
    }
    if (is_ipv6_extension(protocol))
        return PARSE_UNSUPPORTED;
    return parse_transport(skb, cursor, end, protocol, event);
}

SEC("classifier/ingress")
int flowsketch_tc(struct __sk_buff *skb)
{
    struct flowsketch_event event = {};
    struct ethhdr ethernet = {};
    __u16 protocol;
    __u32 offset = sizeof(ethernet);
    int result;

    increment_counter(COUNTER_PACKETS);
    if (FLOWSKETCH_ABI_VERSION != 1) {
        increment_counter(COUNTER_UNSUPPORTED);
        return TC_ACT_OK;
    }
    if (load_bytes(skb, 0, &ethernet, sizeof(ethernet)) < 0) {
        increment_counter(COUNTER_PARSE_ERRORS);
        return TC_ACT_OK;
    }
    protocol = bpf_ntohs(ethernet.h_proto);

#pragma unroll
    for (int index = 0; index < 2; index++) {
        struct vlan_header vlan = {};

        if (protocol != ETH_P_8021Q && protocol != ETH_P_8021AD)
            break;
        if (load_bytes(skb, offset, &vlan, sizeof(vlan)) < 0) {
            increment_counter(COUNTER_PARSE_ERRORS);
            return TC_ACT_OK;
        }
        protocol = bpf_ntohs(vlan.encapsulated_protocol);
        offset += sizeof(vlan);
    }

    event.ts_nanos = bpf_ktime_get_ns();
    event.interface_index = skb->ifindex;
    event.direction = 1; // flowsketch_ebpf::direction::INGRESS
    if (protocol == ETH_P_IP)
        result = parse_ipv4(skb, offset, &event);
    else if (protocol == ETH_P_IPV6)
        result = parse_ipv6(skb, offset, &event);
    else
        result = PARSE_UNSUPPORTED;

    if (result == PARSE_ERROR) {
        increment_counter(COUNTER_PARSE_ERRORS);
        return TC_ACT_OK;
    }
    if (result == PARSE_UNSUPPORTED) {
        increment_counter(COUNTER_UNSUPPORTED);
        return TC_ACT_OK;
    }
    if (bpf_ringbuf_output(&EVENTS, &event, sizeof(event), 0) < 0)
        increment_counter(COUNTER_RING_DROPS);
    else
        increment_counter(COUNTER_EMITTED);
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "Apache-2.0";
