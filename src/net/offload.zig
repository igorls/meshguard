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
/// Matches wireguard-go tun/offload_linux.go gsoSplit().
///
/// The input `pkt` is the raw IP packet (no vnet_hdr prefix — already stripped).
/// Uses hdr.csum_start as the transport header offset (reliable, from kernel).
/// For each segment: fixes IP header (total_length, ID, checksum), adjusts
/// TCP seq/flags or UDP length, and computes full transport checksum.
pub fn gsoSplit(
    hdr: VirtioNetHdr,
    pkt: []const u8,
    out_bufs: [][]u8,
    out_sizes: []usize,
    max_segments: usize,
) usize {
    if (hdr.gso_type == GSO_NONE) {
        if (max_segments == 0) return 0;
        // For non-GSO, just handle F_NEEDS_CSUM if set
        if (pkt.len > out_bufs[0].len) return 0;
        @memcpy(out_bufs[0][0..pkt.len], pkt);
        if (hdr.flags & F_NEEDS_CSUM != 0) {
            gsoNoneChecksum(out_bufs[0][0..pkt.len], hdr.csum_start, hdr.csum_offset);
        }
        out_sizes[0] = pkt.len;
        return 1;
    }

    const seg_size = hdr.gso_size;
    if (seg_size == 0) return 0;

    const ip_version = pkt[0] >> 4;
    const is_v6 = ip_version == 6;
    const iph_len = @as(usize, hdr.csum_start); // trust virtio_net_hdr

    // Determine protocol
    var protocol: u8 = undefined;
    if (hdr.gso_type == GSO_TCPV4 or hdr.gso_type == GSO_TCPV6) {
        protocol = IPPROTO_TCP;
    } else if (hdr.gso_type == GSO_UDP_L4) {
        protocol = IPPROTO_UDP;
    } else {
        return 0;
    }

    // Compute transport header length
    var hdr_len: usize = undefined;
    if (protocol == IPPROTO_UDP) {
        hdr_len = iph_len + 8;
    } else {
        // TCP: parse data offset
        if (pkt.len < iph_len + 13) return 0;
        const tcp_data_off = @as(usize, pkt[iph_len + 12] >> 4) * 4;
        if (tcp_data_off < 20 or tcp_data_off > 60) return 0;
        hdr_len = iph_len + tcp_data_off;
    }
    if (pkt.len < hdr_len) return 0;

    // Source/dest address offsets for pseudo-header checksum
    const src_addr_off: usize = if (is_v6) 8 else 12;
    const addr_len: usize = if (is_v6) 16 else 4;

    // Read first TCP seq if TCP
    const first_tcp_seq: u32 = if (protocol == IPPROTO_TCP)
        std.mem.readInt(u32, pkt[iph_len + 4 ..][0..4], .big)
    else
        0;

    const next_seg_start = hdr_len;
    const seg_usize = @as(usize, seg_size);
    var seg_count: usize = 0;
    var data_offset: usize = next_seg_start;

    while (data_offset < pkt.len and seg_count < max_segments) : (seg_count += 1) {
        var seg_end = data_offset + seg_usize;
        if (seg_end > pkt.len) seg_end = pkt.len;
        const seg_data_len = seg_end - data_offset;
        const total_len = hdr_len + seg_data_len;

        if (total_len > out_bufs[seg_count].len) break;

        const out = out_bufs[seg_count];

        // Copy IP header
        @memcpy(out[0..iph_len], pkt[0..iph_len]);

        if (!is_v6) {
            // IPv4: update total_length, increment ID, recompute header checksum
            if (seg_count > 0) {
                const orig_id = std.mem.readInt(u16, pkt[4..6], .big);
                std.mem.writeInt(u16, out[4..6], orig_id +% @as(u16, @intCast(seg_count)), .big);
            }
            std.mem.writeInt(u16, out[2..4], @intCast(total_len), .big);
            out[10] = 0;
            out[11] = 0;
            const ip_csum = ~inetChecksum(out[0..iph_len], 0);
            std.mem.writeInt(u16, out[10..12], ip_csum, .big);
        } else {
            // IPv6: update payload length
            std.mem.writeInt(u16, out[4..6], @intCast(total_len - iph_len), .big);
        }

        // Copy transport header
        @memcpy(out[iph_len..hdr_len], pkt[iph_len..hdr_len]);

        if (protocol == IPPROTO_TCP) {
            // Set TCP sequence number
            const tcp_seq = first_tcp_seq +% @as(u32, seg_size) *% @as(u32, @intCast(seg_count));
            std.mem.writeInt(u32, out[iph_len + 4 ..][0..4], tcp_seq, .big);
            // Clear FIN and PSH on non-final segments
            if (seg_end != pkt.len) {
                out[iph_len + 13] &= ~@as(u8, 0x01 | 0x08); // clear FIN|PSH
            }
        } else {
            // UDP: fix UDP length
            const transport_hdr_len_u = hdr_len - iph_len;
            std.mem.writeInt(u16, out[iph_len + 4 ..][0..2], @intCast(seg_data_len + transport_hdr_len_u), .big);
        }

        // Copy payload segment
        @memcpy(out[hdr_len..][0..seg_data_len], pkt[data_offset..seg_end]);

        // Compute transport checksum: pseudo-header + transport header + payload
        // Zero the checksum field first
        const csum_field_off = iph_len + @as(usize, hdr.csum_offset);
        out[csum_field_off] = 0;
        out[csum_field_off + 1] = 0;

        const transport_total_len: u16 = @intCast(total_len - iph_len);
        const pseudo_sum = pseudoHeaderChecksumNoFold(
            protocol,
            pkt[src_addr_off..][0..addr_len],
            pkt[src_addr_off + addr_len ..][0..addr_len],
            transport_total_len,
        );
        const transport_csum = ~inetChecksum(out[iph_len..total_len], pseudo_sum);
        std.mem.writeInt(u16, out[csum_field_off..][0..2], transport_csum, .big);

        out_sizes[seg_count] = total_len;
        data_offset += seg_usize;
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

// ── Checksum helpers (matching wireguard-go tun/checksum.go) ──────────

/// Internet checksum (RFC 1071) with initial accumulator.
/// Returns the ones-complement of the ones-complement sum.
pub fn inetChecksum(data: []const u8, initial: u64) u16 {
    var ac = checksumNoFold(data, initial);
    ac = (ac >> 16) + (ac & 0xffff);
    ac = (ac >> 16) + (ac & 0xffff);
    ac = (ac >> 16) + (ac & 0xffff);
    ac = (ac >> 16) + (ac & 0xffff);
    return @intCast(ac & 0xffff);
}

/// Accumulate data into a checksum without folding.
fn checksumNoFold(data: []const u8, initial: u64) u64 {
    var sum: u64 = initial;
    var i: usize = 0;
    // Process 2 bytes at a time (big-endian)
    while (i + 1 < data.len) : (i += 2) {
        sum += @as(u64, std.mem.readInt(u16, data[i..][0..2], .big));
    }
    if (i < data.len) {
        sum += @as(u64, data[i]) << 8;
    }
    return sum;
}

/// Pseudo-header checksum for TCP/UDP (no fold).
fn pseudoHeaderChecksumNoFold(protocol: u8, src_addr: []const u8, dst_addr: []const u8, total_len: u16) u64 {
    var sum = checksumNoFold(src_addr, 0);
    sum = checksumNoFold(dst_addr, sum);
    var proto_buf: [2]u8 = .{ 0, protocol };
    sum = checksumNoFold(&proto_buf, sum);
    var len_buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &len_buf, total_len, .big);
    return checksumNoFold(&len_buf, sum);
}

/// Complete a partial checksum on a non-GSO packet with F_NEEDS_CSUM.
/// Matches wireguard-go's gsoNoneChecksum().
fn gsoNoneChecksum(pkt: []u8, csum_start: u16, csum_offset: u16) void {
    const csum_at = @as(usize, csum_start) + @as(usize, csum_offset);
    if (csum_at + 2 > pkt.len) return;
    if (@as(usize, csum_start) >= pkt.len) return;
    // The initial value is the pseudo-header checksum seed
    const initial: u64 = @as(u64, std.mem.readInt(u16, pkt[csum_at..][0..2], .big));
    pkt[csum_at] = 0;
    pkt[csum_at + 1] = 0;
    const csum = ~inetChecksum(pkt[@as(usize, csum_start)..], initial);
    std.mem.writeInt(u16, pkt[csum_at..][0..2], csum, .big);
}
