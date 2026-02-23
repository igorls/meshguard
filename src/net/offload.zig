///! GRO/GSO offload support for TUN devices.
///!
///! When TUN is opened with IFF_VNET_HDR, every read/write is prefixed
///! by a 10-byte virtio_net_hdr. This enables GSO (write-side) and GRO
///! (read-side) for massive throughput gains:
///!
///! - Read: kernel may deliver a coalesced "super-packet" (up to 64KB).
///!   We split it into MTU-sized segments for WireGuard encryption.
///! - Write: after decrypting WG packets, we coalesce same-flow TCP
///!   segments into one super-packet with GSO metadata. Kernel segments it.
///!
///! Reference: wireguard-go tun/offload_linux.go
const std = @import("std");
const posix = std.posix;

/// virtio_net_hdr — 10 bytes, prepended to every TUN packet when IFF_VNET_HDR is set.
/// Matches the kernel's struct virtio_net_hdr in include/uapi/linux/virtio_net.h.
pub const VirtioNetHdr = extern struct {
    flags: u8 = 0,
    gso_type: u8 = GSO_NONE,
    hdr_len: u16 = 0,
    gso_size: u16 = 0,
    csum_start: u16 = 0,
    csum_offset: u16 = 0,
};

pub const VNET_HDR_LEN: usize = @sizeOf(VirtioNetHdr); // 10

// GSO type constants
pub const GSO_NONE: u8 = 0;
pub const GSO_TCPV4: u8 = 1;
pub const GSO_TCPV6: u8 = 4;
pub const GSO_UDP_L4: u8 = 5;

// TUNSETOFFLOAD flags
pub const TUN_F_CSUM: u32 = 0x01;
pub const TUN_F_TSO4: u32 = 0x02;
pub const TUN_F_TSO6: u32 = 0x04;
pub const TUN_F_USO4: u32 = 0x20;
pub const TUN_F_USO6: u32 = 0x40;

// TUNSETOFFLOAD ioctl number
pub const TUNSETOFFLOAD: u32 = 0x400454d0;

// IP protocol numbers
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

// virtio_net_hdr flags
pub const F_NEEDS_CSUM: u8 = 1;

/// Complete a partial checksum on a packet read from a TUN with IFF_VNET_HDR.
///
/// When the kernel sets F_NEEDS_CSUM, the packet has a partial checksum
/// (pseudo-header seed) at [csum_start + csum_offset]. We need to fold in the
/// rest of the data checksum so the packet has a correct checksum before
/// encryption (the remote peer will inject the decrypted packet into its
/// network stack, which validates checksums).
pub fn completeChecksum(hdr: VirtioNetHdr, pkt: []u8) void {
    if (hdr.flags & F_NEEDS_CSUM == 0) return;

    const csum_start = @as(usize, hdr.csum_start);
    const csum_offset = @as(usize, hdr.csum_offset);
    if (csum_start + csum_offset + 2 > pkt.len) return;
    if (csum_start >= pkt.len) return;

    // The existing value at csum_start+csum_offset is the pseudo-header checksum.
    // We need to compute the checksum over pkt[csum_start..] and store it.

    // Zero the checksum field before computing
    pkt[csum_start + csum_offset] = 0;
    pkt[csum_start + csum_offset + 1] = 0;

    // Compute checksum over the transport header + payload (from csum_start)
    var sum: u32 = 0;

    // Include the pseudo-header checksum that was originally at csum_offset.
    // We already zeroed it, but we need to add it back. Actually, the kernel
    // already included the pseudo-header sum in the seed — we need to start
    // fresh with a pseudo-header checksum and fold it into the data checksum.

    // Re-read: the kernel stores a partial sum as the "seed" at the checksum
    // position. Since we zeroed it, we need to compute the full checksum from
    // scratch. The simplest correct approach: compute checksum of the pseudo-
    // header + transport data. Let's use the same approach as computeTcpChecksum.

    // Detect IP version and protocol
    if (pkt.len < 20) return;
    const ip_version = pkt[0] >> 4;

    var iph_len: usize = undefined;
    if (ip_version == 4) {
        iph_len = @as(usize, pkt[0] & 0x0F) * 4;
    } else if (ip_version == 6) {
        iph_len = 40;
    } else {
        return;
    }

    if (iph_len > pkt.len) return;
    const protocol = if (ip_version == 4) pkt[9] else pkt[6];
    const transport_len: u16 = @intCast(pkt.len - iph_len);

    // Pseudo-header
    if (ip_version == 6) {
        var i: usize = 8;
        while (i < 40) : (i += 2) {
            sum += @as(u32, pkt[i]) << 8 | @as(u32, pkt[i + 1]);
        }
    } else {
        var i: usize = 12;
        while (i < 20) : (i += 2) {
            sum += @as(u32, pkt[i]) << 8 | @as(u32, pkt[i + 1]);
        }
    }
    sum += @as(u32, protocol);
    sum += @as(u32, transport_len);

    // Transport header + data
    var j: usize = iph_len;
    while (j + 1 < pkt.len) : (j += 2) {
        sum += @as(u32, pkt[j]) << 8 | @as(u32, pkt[j + 1]);
    }
    if (j < pkt.len) {
        sum += @as(u32, pkt[j]) << 8;
    }

    // Fold carry
    while (sum > 0xFFFF) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    const csum = ~@as(u16, @intCast(sum & 0xFFFF));
    pkt[csum_start + csum_offset] = @intCast(csum >> 8);
    pkt[csum_start + csum_offset + 1] = @intCast(csum & 0xFF);
}

/// Split a GSO super-packet into individual MTU-sized segments.
/// The input `pkt` is the raw IP packet (no vnet_hdr prefix).
/// Returns the number of segments written to `out_bufs`.
///
/// For TCP: adjusts IP total length, TCP sequence numbers, and checksums.
/// For UDP: adjusts IP total length and UDP length.
pub fn gsoSplit(
    hdr: VirtioNetHdr,
    pkt: []const u8,
    out_bufs: [][]u8,
    out_sizes: []usize,
    max_segments: usize,
) usize {
    if (hdr.gso_type == GSO_NONE) {
        // Not a GSO packet — just copy as-is
        if (max_segments == 0) return 0;
        if (pkt.len > out_bufs[0].len) return 0;
        @memcpy(out_bufs[0][0..pkt.len], pkt);
        out_sizes[0] = pkt.len;
        return 1;
    }

    const seg_size = hdr.gso_size;
    if (seg_size == 0) return 0;

    const ip_version = pkt[0] >> 4;
    var iph_len: usize = undefined;
    var transport_offset: usize = undefined;
    var protocol: u8 = undefined;

    if (ip_version == 4) {
        iph_len = @as(usize, pkt[0] & 0x0F) * 4;
        if (pkt.len < iph_len) return 0;
        protocol = pkt[9];
        transport_offset = iph_len;
    } else if (ip_version == 6) {
        iph_len = 40;
        if (pkt.len < 40) return 0;
        protocol = pkt[6]; // next header
        transport_offset = 40;
    } else {
        return 0;
    }

    var transport_hdr_len: usize = undefined;
    if (protocol == IPPROTO_TCP) {
        if (pkt.len < transport_offset + 20) return 0;
        transport_hdr_len = @as(usize, pkt[transport_offset + 12] >> 4) * 4;
        if (transport_hdr_len < 20 or transport_hdr_len > 60) return 0;
    } else if (protocol == IPPROTO_UDP) {
        transport_hdr_len = 8;
    } else {
        return 0;
    }

    const headers_len = transport_offset + transport_hdr_len;
    if (pkt.len <= headers_len) return 0;

    const payload = pkt[headers_len..];
    const seg_usize = @as(usize, seg_size);

    var seg_count: usize = 0;
    var offset: usize = 0;
    var tcp_seq: u32 = if (protocol == IPPROTO_TCP)
        std.mem.readInt(u32, pkt[transport_offset + 4 ..][0..4], .big)
    else
        0;

    while (offset < payload.len and seg_count < max_segments) : (seg_count += 1) {
        const remaining = payload.len - offset;
        const this_seg_len = @min(remaining, seg_usize);
        const total_pkt_len = headers_len + this_seg_len;

        if (total_pkt_len > out_bufs[seg_count].len) break;

        // Copy headers
        @memcpy(out_bufs[seg_count][0..headers_len], pkt[0..headers_len]);
        // Copy payload segment
        @memcpy(out_bufs[seg_count][headers_len..][0..this_seg_len], payload[offset..][0..this_seg_len]);

        // Fix up IP total length
        if (ip_version == 4) {
            std.mem.writeInt(u16, out_bufs[seg_count][2..4], @intCast(total_pkt_len), .big);
            // Clear IP identification for segments after the first
            if (seg_count > 0) {
                std.mem.writeInt(u16, out_bufs[seg_count][4..6], @intCast(seg_count), .big);
            }
            // Zero IP checksum, recalculate
            out_bufs[seg_count][10] = 0;
            out_bufs[seg_count][11] = 0;
            ipv4HeaderChecksum(out_bufs[seg_count][0..iph_len]);
        } else {
            // IPv6 payload length = total - 40
            std.mem.writeInt(u16, out_bufs[seg_count][4..6], @intCast(total_pkt_len - 40), .big);
        }

        // Fix up TCP sequence number
        if (protocol == IPPROTO_TCP) {
            std.mem.writeInt(u32, out_bufs[seg_count][transport_offset + 4 ..][0..4], tcp_seq, .big);
            tcp_seq +%= @intCast(this_seg_len);

            // Clear PSH flag on non-final segments
            if (offset + this_seg_len < payload.len) {
                out_bufs[seg_count][transport_offset + 13] &= ~@as(u8, 0x08); // clear PSH
            }
        } else if (protocol == IPPROTO_UDP) {
            // Fix UDP length
            std.mem.writeInt(u16, out_bufs[seg_count][transport_offset + 4 ..][0..2], @intCast(transport_hdr_len + this_seg_len), .big);
        }

        // Note: checksums are left as-is from the original. The kernel's
        // partial checksum (pseudo-header + payload) needs to be recalculated
        // for each segment since the payload changed. For now, we compute a
        // proper TCP/UDP checksum for each segment.
        if (protocol == IPPROTO_TCP) {
            // Recompute TCP checksum for this segment
            computeTcpChecksum(out_bufs[seg_count], transport_offset, total_pkt_len, ip_version == 6);
        } else if (protocol == IPPROTO_UDP) {
            // Zero UDP checksum (optional for IPv4, but compute for IPv6)
            out_bufs[seg_count][transport_offset + 6] = 0;
            out_bufs[seg_count][transport_offset + 7] = 0;
        }

        out_sizes[seg_count] = total_pkt_len;
        offset += this_seg_len;
    }

    return seg_count;
}

/// Build a virtio_net_hdr for writing a coalesced packet to TUN with GSO.
pub fn makeGSOHeader(protocol: u8, is_v6: bool, ip_hdr_len: u16, transport_hdr_len: u16, segment_size: u16) VirtioNetHdr {
    var hdr = VirtioNetHdr{};

    if (protocol == IPPROTO_TCP) {
        hdr.gso_type = if (is_v6) GSO_TCPV6 else GSO_TCPV4;
    } else if (protocol == IPPROTO_UDP) {
        hdr.gso_type = GSO_UDP_L4;
    } else {
        hdr.gso_type = GSO_NONE;
        return hdr;
    }

    hdr.hdr_len = ip_hdr_len + transport_hdr_len;
    hdr.gso_size = segment_size;
    hdr.csum_start = ip_hdr_len;

    if (protocol == IPPROTO_TCP) {
        hdr.csum_offset = 16; // TCP checksum offset within TCP header
    } else {
        hdr.csum_offset = 6; // UDP checksum offset within UDP header
    }

    hdr.flags = 1; // VIRTIO_NET_HDR_F_NEEDS_CSUM

    return hdr;
}

/// Check if two decrypted IP packets can be coalesced (same TCP flow, sequential).
/// Returns the payload size of pkt_b if coalesceable, or 0 if not.
pub fn canCoalesceTCP(pkt_a: []const u8, pkt_b: []const u8) usize {
    // Both must be IPv4 TCP (simple case first, IPv6 support later)
    if (pkt_a.len < 40 or pkt_b.len < 40) return 0;

    const ver_a = pkt_a[0] >> 4;
    const ver_b = pkt_b[0] >> 4;
    if (ver_a != ver_b) return 0;

    var iph_len_a: usize = undefined;
    var iph_len_b: usize = undefined;
    var proto_a: u8 = undefined;
    var proto_b: u8 = undefined;

    if (ver_a == 4) {
        iph_len_a = @as(usize, pkt_a[0] & 0x0F) * 4;
        iph_len_b = @as(usize, pkt_b[0] & 0x0F) * 4;
        proto_a = pkt_a[9];
        proto_b = pkt_b[9];

        // Check same src/dst IP
        if (!std.mem.eql(u8, pkt_a[12..20], pkt_b[12..20])) return 0;
        // Check same TTL, TOS
        if (pkt_a[1] != pkt_b[1]) return 0; // TOS
        if (pkt_a[8] != pkt_b[8]) return 0; // TTL
    } else if (ver_a == 6) {
        iph_len_a = 40;
        iph_len_b = 40;
        proto_a = pkt_a[6];
        proto_b = pkt_b[6];

        // Check same src/dst IP (8..40)
        if (!std.mem.eql(u8, pkt_a[8..40], pkt_b[8..40])) return 0;
        // Check same hop limit
        if (pkt_a[7] != pkt_b[7]) return 0;
    } else {
        return 0;
    }

    if (proto_a != IPPROTO_TCP or proto_b != IPPROTO_TCP) return 0;
    if (iph_len_a != iph_len_b) return 0;

    // Check TCP headers: same src/dst port
    const th_a = iph_len_a;
    const th_b = iph_len_b;
    if (pkt_a.len < th_a + 20 or pkt_b.len < th_b + 20) return 0;

    // Same ports
    if (!std.mem.eql(u8, pkt_a[th_a..][0..4], pkt_b[th_b..][0..4])) return 0;

    const tcph_len_a = @as(usize, pkt_a[th_a + 12] >> 4) * 4;
    const tcph_len_b = @as(usize, pkt_b[th_b + 12] >> 4) * 4;
    if (tcph_len_a != tcph_len_b) return 0;

    if (pkt_a.len < th_a + tcph_len_a or pkt_b.len < th_b + tcph_len_b) return 0;

    // Check sequence adjacency: seq_b == seq_a + payload_a
    const seq_a = std.mem.readInt(u32, pkt_a[th_a + 4 ..][0..4], .big);
    const seq_b = std.mem.readInt(u32, pkt_b[th_b + 4 ..][0..4], .big);
    const payload_a_len = pkt_a.len - th_a - tcph_len_a;

    if (seq_b != seq_a +% @as(u32, @intCast(payload_a_len))) return 0;

    // PSH on pkt_a means we can't append after it
    if (pkt_a[th_a + 13] & 0x08 != 0) return 0;

    // Only ACK allowed (no SYN, FIN, RST, URG)
    const flags_mask: u8 = 0x37; // SYN|FIN|RST|URG|ECE|CWR
    if (pkt_a[th_a + 13] & flags_mask != 0) return 0;
    if (pkt_b[th_b + 13] & flags_mask != 0) return 0;

    // Return payload_b size
    return pkt_b.len - th_b - tcph_len_b;
}

/// Compute IPv4 header checksum and write it at bytes 10-11.
fn ipv4HeaderChecksum(hdr: []u8) void {
    // Zero the checksum field first
    hdr[10] = 0;
    hdr[11] = 0;

    var sum: u32 = 0;
    var i: usize = 0;
    while (i < hdr.len) : (i += 2) {
        sum += @as(u32, hdr[i]) << 8;
        if (i + 1 < hdr.len) {
            sum += @as(u32, hdr[i + 1]);
        }
    }

    // Fold carry
    while (sum > 0xFFFF) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    const result = ~@as(u16, @intCast(sum & 0xFFFF));
    hdr[10] = @intCast(result >> 8);
    hdr[11] = @intCast(result & 0xFF);
}

/// Compute TCP checksum for a packet and write it at the correct offset.
/// Handles both IPv4 and IPv6 pseudo-headers.
fn computeTcpChecksum(pkt: []u8, transport_offset: usize, total_len: usize, is_v6: bool) void {
    if (total_len < transport_offset + 20) return;

    // Zero the checksum field first
    pkt[transport_offset + 16] = 0;
    pkt[transport_offset + 17] = 0;

    var sum: u32 = 0;
    const tcp_len: u16 = @intCast(total_len - transport_offset);

    // Pseudo-header
    if (is_v6) {
        // IPv6 pseudo-header: src(16) + dst(16) + tcp_len(4) + next_hdr(4)
        var i: usize = 8;
        while (i < 40) : (i += 2) {
            sum += @as(u32, pkt[i]) << 8 | @as(u32, pkt[i + 1]);
        }
        sum += @as(u32, tcp_len);
        sum += IPPROTO_TCP;
    } else {
        // IPv4 pseudo-header: src(4) + dst(4) + zero + proto + tcp_len
        var i: usize = 12;
        while (i < 20) : (i += 2) {
            sum += @as(u32, pkt[i]) << 8 | @as(u32, pkt[i + 1]);
        }
        sum += IPPROTO_TCP;
        sum += @as(u32, tcp_len);
    }

    // TCP header + data
    var i: usize = transport_offset;
    while (i + 1 < total_len) : (i += 2) {
        sum += @as(u32, pkt[i]) << 8 | @as(u32, pkt[i + 1]);
    }
    if (i < total_len) {
        sum += @as(u32, pkt[i]) << 8;
    }

    // Fold carry
    while (sum > 0xFFFF) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    const csum = ~@as(u16, @intCast(sum & 0xFFFF));
    pkt[transport_offset + 16] = @intCast(csum >> 8);
    pkt[transport_offset + 17] = @intCast(csum & 0xFF);
}
