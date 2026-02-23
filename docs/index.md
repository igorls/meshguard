---
layout: home

hero:
  name: meshguard
  text: Decentralized WireGuard Mesh VPN
  tagline: Zero central authority. Trust-agnostic. Single static binary.
  actions:
    - theme: brand
      text: Getting Started
      link: /guide/getting-started
    - theme: alt
      text: Architecture
      link: /concepts/architecture

features:
  - icon: 🔐
    title: Serverless & Trustless
    details: No control plane, no coordinator. Each node holds its own Ed25519 identity and the mesh is self-organizing.
  - icon: 🌐
    title: SWIM Gossip Protocol
    details: O(log N) peer convergence with built-in failure detection. Membership changes propagate in seconds, not minutes.
  - icon: 🛡️
    title: WireGuard Tunnels
    details: End-to-end encrypted tunnels with kernel or userspace WireGuard. Noise_IKpsk2 handshake handles key negotiation.
  - icon: 🕳️
    title: NAT Traversal
    details: STUN-based endpoint discovery, UDP hole punching via rendezvous, and relay fallback for symmetric NATs.
  - icon: 🆔
    title: Deterministic Mesh IPs
    details: Each node's IP is derived from its public key via Blake3 hashing — no DHCP, no conflicts, no coordination.
  - icon: ⚡
    title: Single Static Binary
    details: Built with Zig, cross-compiles to any Linux target. Zero runtime dependencies.
---
