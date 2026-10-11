#ifndef MESHGUARD_H
#define MESHGUARD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque, owned context. Destroy exactly once after all host work stops. */
typedef struct MeshguardContext meshguard_context;

/*
 * Host contract: use one serial host queue per context and one consumer per
 * receive queue. Serialize all calls with join/leave/switch/destroy. Configure
 * callbacks while stopped. Network callbacks run on the internal event loop;
 * undeliverable callbacks run synchronously inside send/send_ex. Callback
 * pointers are borrowed until the callback returns. Do not call lifecycle
 * functions from a callback or synchronously wait for the host queue there.
 * All non-optional byte pointers must reference the documented buffer size.
 */
typedef void (*meshguard_message_callback)(const uint8_t *data, size_t data_len,
                                          const uint8_t *sender_pubkey);
/* event_type: 1 joined, 2 left/dead; peer_pubkey: 32 bytes. */
typedef void (*meshguard_peer_event_callback)(uint8_t event_type,
                                             const uint8_t *peer_pubkey);
typedef void (*meshguard_undeliverable_callback)(const uint8_t *destination,
                                                const uint8_t *data,
                                                uint32_t data_len,
                                                int32_t error_code);
/* destination: 32 bytes; nonce: 12 bytes; code: relay rejection/retry reason. */
typedef void (*meshguard_delivery_status_callback)(const uint8_t *destination,
                                                  const uint8_t *nonce,
                                                  uint8_t code);

/* Lifecycle: seed is 32 bytes or NULL to generate; port 0 is ephemeral. */
meshguard_context *meshguard_init(const uint8_t *identity_seed, uint16_t listen_port);
meshguard_context *meshguard_init_ipv6(const uint8_t *identity_seed, uint16_t listen_port);
/* bind_ip is a required 4-byte IPv4 address; NULL returns NULL. */
meshguard_context *meshguard_init_bind(const uint8_t *identity_seed,
                                     uint16_t listen_port, const uint8_t *bind_ip);
void meshguard_destroy(meshguard_context *ctx);

/* Identity outputs: 32 bytes, except base64 output which needs 45 bytes. */
void meshguard_get_pubkey(meshguard_context *ctx, uint8_t *out);
void meshguard_get_wg_pubkey(meshguard_context *ctx, uint8_t *out);
void meshguard_get_pubkey_b64(meshguard_context *ctx, uint8_t *out);
/* Secret: persist the seed in secure storage. */
void meshguard_get_seed(meshguard_context *ctx, uint8_t *out);

/* Join returns 0 when the event loop starts, not proof of peer connectivity. */
/* seed_ip: 4 bytes for IPv4, 16 bytes for IPv6; seed_port 0 uses 51821. */
int32_t meshguard_join(meshguard_context *ctx, const uint8_t *seed_ip, uint16_t seed_port);
int32_t meshguard_join_ipv6(meshguard_context *ctx, const uint8_t *seed_ip,
                           uint16_t seed_port);
/* host_str is a NUL-terminated UTF-8 hostname:port; resolves a DNS A record. */
int32_t meshguard_join_host(meshguard_context *ctx, const uint8_t *host_str);
int32_t meshguard_join_lan(meshguard_context *ctx);
void meshguard_leave(meshguard_context *ctx);
/* IPv4 relay switch preserves identity, contacts, certificate and settings. */
int32_t meshguard_switch_relay(meshguard_context *ctx, const uint8_t *relay_pubkey,
                              bool force, const uint8_t *seed_ip, uint16_t seed_port);

/* Configure while stopped. relay_pubkey: 32 bytes or NULL when force is false. */
int32_t meshguard_set_app_relay(meshguard_context *ctx, const uint8_t *relay_pubkey,
                               bool force);
/* Certificate: 186-byte v1 or 314-byte v2, valid for this identity. */
int32_t meshguard_set_org_cert(meshguard_context *ctx, const uint8_t *cert, uint32_t len);
int32_t meshguard_clear_org_cert(meshguard_context *ctx);

/* Contacts: each identity and WireGuard public key is 32 bytes. */
int32_t meshguard_add_contact(meshguard_context *ctx, const uint8_t *ed25519,
                             const uint8_t *wg);
int32_t meshguard_remove_contact(meshguard_context *ctx, const uint8_t *ed25519);
void meshguard_clear_contacts(meshguard_context *ctx);
uint32_t meshguard_contact_count(meshguard_context *ctx);
void meshguard_set_contacts_only(meshguard_context *ctx, bool enabled);

/* Messaging: peer_pubkey is 32 bytes; payload is at most 1024 bytes. */
/* Return 0 means a socket send succeeded; recipient delivery needs a host ACK. */
int32_t meshguard_send(meshguard_context *ctx, const uint8_t *peer_pubkey,
                      const uint8_t *data, uint32_t len);
/* out_nonce must hold 12 bytes; written only on success. */
int32_t meshguard_send_ex(meshguard_context *ctx, const uint8_t *peer_pubkey,
                         const uint8_t *data, uint32_t len, uint8_t *out_nonce);
/* out_data >= 1024 bytes; out_sender >= 32 bytes. 0 received, 1 empty, -1 error. */
int32_t meshguard_recv(meshguard_context *ctx, uint8_t *out_data, uint32_t *out_len,
                      uint8_t *out_sender);
void meshguard_set_on_message(meshguard_context *ctx, meshguard_message_callback cb);
void meshguard_set_on_peer_event(meshguard_context *ctx, meshguard_peer_event_callback cb);
void meshguard_set_on_undeliverable(meshguard_context *ctx,
                                  meshguard_undeliverable_callback cb);
void meshguard_set_on_delivery_status(meshguard_context *ctx,
                                     meshguard_delivery_status_callback cb);
/* out_destination >= 32, out_nonce >= 12, out_code >= 1 byte.
 * 0 received, 1 empty, -1 error. Codes: 1 offline, 2 destination not admitted,
 * 3 rate limited, 4 handshake again, 5 sender not admitted, 6 overloaded.
 */
int32_t meshguard_recv_delivery_status(meshguard_context *ctx, uint8_t *out_destination,
                                      uint8_t *out_nonce, uint8_t *out_code);

/* keepalive: 1000..600000 ms; 0 uses the join default on the next join.
 * Setting keepalive to 0 while running retains the last applied interval.
 * proof: 5000..3600000 ms; 0 restores its 15000 ms default.
 */
int32_t meshguard_set_keepalive_interval(meshguard_context *ctx, uint32_t ms);
int32_t meshguard_set_relay_proof_interval(meshguard_context *ctx, uint32_t ms);
void meshguard_suspend(meshguard_context *ctx);
void meshguard_resume(meshguard_context *ctx);
bool meshguard_is_suspended(meshguard_context *ctx);
bool meshguard_is_running(meshguard_context *ctx);
uint64_t meshguard_last_recv_time(meshguard_context *ctx); /* Epoch milliseconds. */
uint16_t meshguard_get_bound_port(meshguard_context *ctx);
uint32_t meshguard_peer_count(meshguard_context *ctx);
/* out_pubkeys must hold max_peers * 32 bytes; returns the count written. */
uint32_t meshguard_get_peers(meshguard_context *ctx, uint8_t *out_pubkeys,
                            uint32_t max_peers);
/* peer_pubkey: 32 bytes; out_info: at least 48 bytes (see Apple guide). */
int32_t meshguard_get_peer_info(meshguard_context *ctx, const uint8_t *peer_pubkey,
                               uint8_t *out_info);
/* out: >= 32 bytes; fields are little-endian (see Apple guide). */
void meshguard_debug_info(meshguard_context *ctx, uint8_t *out);
/* out: 32 bytes, four little-endian u64 socket-send/drop counters. */
void meshguard_app_route_stats(meshguard_context *ctx, uint8_t *out);

/* WireGuard userspace data tunnels; no operating-system TUN interface. */
int32_t meshguard_tunnel_open(meshguard_context *ctx, const uint8_t *peer_pubkey);
/* Payload limit is 1396 bytes (1400-byte frame minus its 4-byte header). */
int32_t meshguard_tunnel_send(meshguard_context *ctx, const uint8_t *peer_pubkey,
                             const uint8_t *data, uint32_t len);
/* out_data >= 1500 bytes; out_sender >= 32 bytes. 0 received, 1 empty, -1 error. */
int32_t meshguard_tunnel_recv(meshguard_context *ctx, uint8_t *out_data,
                             uint32_t *out_len, uint8_t *out_sender);
void meshguard_tunnel_close(meshguard_context *ctx, const uint8_t *peer_pubkey);

#ifdef __cplusplus
}
#endif

#endif /* MESHGUARD_H */
