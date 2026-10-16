# iOS / Apple Embedding

MeshGuard's C ABI embeds discovery, encrypted application messages, relay routing,
contacts, and userspace WireGuard data tunnels in an Apple application. It uses
UDP sockets and in-process receive queues. It does not create an operating-system
VPN interface. The same public C header, `include/meshguard.h`, supports
Objective-C, C, C++, and Swift through the `MeshGuardFFI` Clang module.

## Build and packages

Apple builds pin this post-0.17.0 development toolchain because the 0.17.0
release has an iOS `std.Io.Threaded.NullFile.fd` compilation regression. The
pinned toolchain includes the upstream fix without local standard-library patches.

Run these commands on macOS with Zig `0.18.0-dev.253+16d31ceed` and Xcode's command-line tools selected:

```bash
./scripts/build-apple.sh
./scripts/test-apple-link.sh
```

Both scripts accept an optional output directory; the default is `zig-out/apple`.
The link test compiles and runs C and Swift hosts against the macOS libraries,
and links Swift hosts against both iOS slices.
The iOS slices require the iPhoneOS and iPhoneSimulator SDKs from Xcode. The build
targets iOS 15 and macOS 13 as minimum deployment versions and uses Zig
`std.crypto`; no libsodium dependency is needed.

| Output under `zig-out/apple` | Contents |
| --- | --- |
| `MeshGuardFFI.xcframework` | Static `libmeshguard-ffi.a`, public header and module map for iOS arm64 devices and arm64 simulators |
| `macos-arm64` | `lib/libmeshguard-ffi.dylib`, `lib/libmeshguard-ffi.a`, and `include/` |
| `macos-x86_64` | The same layout for Intel macOS |
| `macos-universal` | Both macOS architectures in each library, plus `include/` |

The release asset names are `meshguard-ffi-ios-xcframework.zip`,
`meshguard-ffi-macos-arm64.tar.gz`, `meshguard-ffi-macos-x86_64.tar.gz`, and
`meshguard-ffi-macos-universal.tar.gz`. The iOS XCFramework contains an arm64
simulator slice; an Intel simulator slice is not included.

## Add the library to an Xcode app

Add `MeshGuardFFI.xcframework` to the application target's **Frameworks, Libraries,
and Embedded Content**. Select **Do Not Embed** because the library is static.
Set the app's deployment target to iOS 15 or later. The included
`module.modulemap` declares `MeshGuardFFI` and exposes `meshguard.h`:

```swift
import MeshGuardFFI
```

For an Objective-C host, include `meshguard.h`. If maintaining a custom build
system, select the device or simulator slice that matches the SDK, add its
headers to the compiler's search path, and link its `libmeshguard-ffi.a`. Device
and simulator libraries are different platforms even though both are arm64.

## Swift polling example

Keep the context on one serial host queue. Call every method of this example,
including its initializer and `stop`, on that queue. Persist a generated
32-byte identity seed in Keychain with `meshguard_get_seed`, then supply that
same seed on each launch. The example accepts an existing seed and uses polling,
so it needs no global Swift callback registry.

```swift
import Foundation
import MeshGuardFFI

enum MeshError: Error {
    case invalidInput
    case native(Int32)
}

final class MeshSession {
    private var context: OpaquePointer?

    init(savedSeed: [UInt8]) throws {
        guard savedSeed.count == 32 else { throw MeshError.invalidInput }
        context = savedSeed.withUnsafeBufferPointer {
            meshguard_init($0.baseAddress, 0)
        }
        guard context != nil else { throw MeshError.native(-1) }
    }

    func join(relayIdentity: [UInt8], seedIPv4: [UInt8], port: UInt16) throws {
        guard let ctx = context, relayIdentity.count == 32, seedIPv4.count == 4
        else { throw MeshError.invalidInput }
        let pinResult = relayIdentity.withUnsafeBufferPointer {
            meshguard_set_app_relay(ctx, $0.baseAddress, true)
        }
        guard pinResult == 0 else { throw MeshError.native(pinResult) }
        let joinResult = seedIPv4.withUnsafeBufferPointer {
            meshguard_join(ctx, $0.baseAddress, port)
        }
        guard joinResult == 0 else { throw MeshError.native(joinResult) }
    }

    func send(to identity: [UInt8], wireGuardKey: [UInt8], payload: [UInt8]) throws {
        guard let ctx = context, identity.count == 32, wireGuardKey.count == 32,
              !payload.isEmpty, payload.count <= 1024
        else { throw MeshError.invalidInput }
        let contactResult = identity.withUnsafeBufferPointer { peer in
            wireGuardKey.withUnsafeBufferPointer {
                meshguard_add_contact(ctx, peer.baseAddress, $0.baseAddress)
            }
        }
        guard contactResult == 0 else { throw MeshError.native(contactResult) }
        let sendResult = identity.withUnsafeBufferPointer { peer in
            payload.withUnsafeBufferPointer {
                meshguard_send(ctx, peer.baseAddress, $0.baseAddress, UInt32(payload.count))
            }
        }
        guard sendResult == 0 else { throw MeshError.native(sendResult) }
    }

    func pollMessage() throws -> (sender: [UInt8], data: Data)? {
        guard let ctx = context else { throw MeshError.invalidInput }
        var data = [UInt8](repeating: 0, count: 1024)
        var sender = [UInt8](repeating: 0, count: 32)
        var length: UInt32 = 0
        let result = data.withUnsafeMutableBufferPointer { payload in
            sender.withUnsafeMutableBufferPointer {
                meshguard_recv(ctx, payload.baseAddress, &length, $0.baseAddress)
            }
        }
        if result == 1 { return nil }
        guard result == 0 else { throw MeshError.native(result) }
        return (sender, Data(data.prefix(Int(length))))
    }

    func stop() {
        guard let ctx = context else { return }
        context = nil
        meshguard_destroy(ctx) // Leaves, joins the event-loop thread, then frees.
    }
}
```

Schedule regular inbox draining on the same queue while the app is active, and
explicitly call `stop` when that session ends. Relay identity, endpoint, and
contact keys come from the application's trusted configuration or authenticated
contact exchange. A join result of `0` means the local event loop started; wait
for peer state or actual received traffic to establish connectivity. A successful
send means a socket accepted the packet. Implement an application acknowledgement
if the interface needs to claim recipient delivery.

## Relays, contacts, and delivery status

Pin the relay identity with `meshguard_set_app_relay` before joining. With
`force = true`, application traffic uses that relay and fails closed when no
usable relay route exists. An opaque relay does not advertise other clients;
register each recipient's 32-byte Ed25519 identity and 32-byte WireGuard public
key through `meshguard_add_contact`. `meshguard_set_contacts_only` also restricts
incoming application messages to registered contacts.

Install a relay pass with `meshguard_set_org_cert`. It accepts a 186-byte v1 or
314-byte v2 certificate, verifies that it belongs to this identity and is valid
now, and can be replaced while running. A v2 certificate also binds the
WireGuard public key obtained from `meshguard_get_wg_pubkey`. Admission by the
relay additionally depends on its configured issuer trust. See
[Relay Forwarding](../reference/relay-forwarding.md).

Use `meshguard_send_ex` to obtain the successful frame's 12-byte nonce. Poll
`meshguard_recv_delivery_status` to correlate relay rejection or retry signals:

| Code | Meaning |
| --- | --- |
| `1` | Destination offline |
| `2` | Destination not admitted |
| `3` | Rate limited |
| `4` | Handshake again; the library requests a new relay proof |
| `5` | Sender not admitted |
| `6` | Relay overloaded |

These statuses are accepted only from the pinned relay endpoint for a recently
sent frame. They are not positive delivery receipts. The poll queue holds 64
statuses and drops new statuses when full. `meshguard_set_keepalive_interval`
accepts 1,000–600,000 milliseconds. Set it to `0` to use the join default on
the next join; changing it to `0` while running leaves the previously applied
interval in place until rejoining. The relay proof interval accepts
5,000–3,600,000 milliseconds, or `0` to restore its 15,000-millisecond default.
Tune them to the relay's expiry policy and the app's active lifecycle.

## Threads and ownership

Use a single serial host queue per context. Serialize join, leave, relay
switching, callback setters, sends, queries and destruction; stop polling before
destroying. Use exactly one consumer for each application-message,
delivery-status, and tunnel receive queue. The internal event loop produces
queue entries independently of the host.

Set callbacks before joining, and change or clear them only when the context is
stopped. Message, peer-event, and delivery-status callbacks execute on the
library's event-loop thread. The undeliverable callback executes synchronously
within `meshguard_send` or `meshguard_send_ex` for certain routing failures;
check the send return code as well, since not every error invokes it.

All callback byte pointers are borrowed and expire when the callback returns.
Copy the payload, keys, and nonce before asynchronously dispatching work to the
host queue or main queue. The message callback's length is C `size_t`; the
undeliverable callback's length is `uint32_t`. Callback functions receive no
user-data pointer, so a host using callbacks must manage its own stable routing
registry. Do not call leave, destroy, or switch from an event-loop callback:
leave waits for that same thread. Do not block a callback waiting synchronously
for the host queue, either.

Application-message callbacks do not consume the receive queue. Continue
draining `meshguard_recv`; once its 64 slots are full, new messages are dropped
before their callbacks fire. Treat callback and poll observations as the same
message rather than displaying them twice. Polling alone is usually simpler
when managing several contexts.

## iOS lifecycle and network permissions

The library's `meshguard_suspend` reduces its own activity by stopping periodic
pings and LAN beacons while its event loop can still execute. It does not grant
iOS background execution or prevent the operating system from suspending the
app. A suspended iOS process cannot promise a live relay connection or receive
UDP messages reliably. Use the platform's permitted background mechanisms for
the application's actual use case, and reconnect or rejoin when foreground
execution resumes. `meshguard_resume` requests re-announcement on the event loop;
its return does not prove that the relay has admitted the endpoint again.

LAN discovery accesses the local network and uses multicast. Supply an
appropriate `NSLocalNetworkUsageDescription` and obtain the
[`com.apple.developer.networking.multicast` entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.multicast)
when using `meshguard_join_lan`. See Apple's
[local network privacy guidance](https://developer.apple.com/documentation/technotes/tn3179-understanding-local-network-privacy).
A known relay endpoint
does not require LAN multicast discovery. For a network VPN product, integrate
the appropriate Network Extension separately; this FFI's application data
tunnels do not configure a VPN or TUN interface.

## Buffer sizes and diagnostics

The ABI uses caller-owned byte buffers rather than packed C structs. Always
allocate the required capacity before calling; the ABI does not receive a
buffer-capacity argument for these outputs.

| Operation | Required output capacity |
| --- | --- |
| Public keys and identity seed | 32 bytes |
| Base64 public key | 45 bytes, including NUL |
| Application receive | 1,024-byte payload, 32-byte sender, `uint32_t` length |
| Delivery status | 32-byte destination, 12-byte nonce, 1-byte code |
| Tunnel receive | 1,500-byte payload, 32-byte sender, `uint32_t` length |
| Peer list | `max_peers × 32` bytes |
| Peer information | At least 48 bytes |
| Debug information and route counters | At least 32 bytes each |

`meshguard_get_peer_info` writes IPv4 at bytes `0..3`, a big-endian port at
`4..5`, mesh IPv4 at `6..9`, state at `10`, WireGuard-key presence at `11`,
the key at `12..43`, connection heuristic at `44`, NAT type at `45`, and relay
capability at `46`. Byte `47` is reserved and is not written. State values are
`0` alive, `1` suspected, `2` dead, `3` left; the connection heuristic is
`0` direct, `1` relayed, `2` unknown. It is not proof of the route used for a
particular packet.

`meshguard_debug_info` writes little-endian fields: bound port (`0..1`), total
peers (`2..3`), alive peers (`4..5`), running flag (`6`), SWIM-present flag (`7`),
gossip port (`8..9`), membership size (`10..13`), sent packets (`14..17`), decoded
received packets (`18..21`), raw received packets (`22..25`), and ticks
(`26..29`). Zero-initialize the buffer; trailing bytes are not written.
`meshguard_app_route_stats` writes four little-endian `uint64_t` counters:
direct socket sends, relay socket sends, failed routes, and duplicate drops.
These are transport counters, not delivery evidence.

WireGuard tunnel payloads are limited to **1,396 bytes** because the 1,400-byte
frame includes a 4-byte framing header. `meshguard_tunnel_open` starts the
handshake; a `0` result does not mean the handshake has completed. Its receive
queue holds 256 entries and has one consumer just like the application inbox.
