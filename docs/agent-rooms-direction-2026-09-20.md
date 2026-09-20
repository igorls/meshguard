# Decentralized agent rooms: investigation and proposed direction

Status: architecture recommendation for discussion. The intended product is decentralized human/agent collaboration across independently operated environments, also serving as a production dogfood application for MeshGuard and WormDB.

Reviewed on 2026-09-20 at MeshGuard commit `7b39986cbfeef9f54622212ecf9d85762393d869`. Scope: the five commits after `415dacf`, the supplied Meet Link walkthrough, current release metadata, Delta's public documentation, and the local WormDB checkout at `47d8f15` plus its existing uncommitted changes. WormDB was inspected read-only; its MeshGuard submodule already points at the reviewed MeshGuard SHA.

## Recommendation

Build agent rooms as a separate application and repository, using MeshGuard for networking and WormDB for local durable shared records and synchronization primitives. Keep encrypted application messaging, peer identity, discovery, NAT traversal, and relay behavior in MeshGuard. Keep generic persistence, verifiable logs, scoped synchronization, and recovery in WormDB. The application owns room invitations, membership, conversations, agent integration, and the collaboration experience.

The user's concrete workflow is a local agent collaborating with Grok Bot in its cloud environment and an agent belonging to another developer on the same project. Each agent uses its own local tools and deliberately chooses what to share. Humans participate through the same room. MemPalace and its logstream are not dependencies of this product. A room needs its own operational history to recover conversations and task state; it does not need to become a knowledge store.

The product promise should be: share a link to bring people and independently operated agents into a project room, while each participant keeps its tools, credentials, private context, checkout, and authority over local actions. Rooms may be temporary or retained by participants; a mandatory permanent room server should not determine their lifetime.

Delta makes conversations, code changes, and review part of a shared workspace. The useful inspiration is that shared work context. Our proposed focus is collaboration across existing agent environments. This is a product direction, not a claim that Delta cannot support a particular integration. See [Delta](https://delta.dev/) and its [getting started documentation](https://delta.dev/docs/getting-started).

## What the commits establish

| Commit | Change |
| --- | --- |
| `13a0d3f` | Adds daemon messaging, invite/join commands, shell worker, and onboarding script. |
| `46f6e69` | Corrects command newline handling and positional receive timeout parsing. |
| `38e14f7` | Fixes stdout/stderr pipe handling, reply sizing, application packet relaying, and blocking receive behavior. |
| `0714028` | Starts the control listener earlier, extends startup waiting, and captures daemon logs. |
| `7b39986` | Skips UPnP in gossip-only mode, expands listener backlog, and improves child liveness checks. |

The patch adds 1,783 lines and removes 91 across five files. Most additions are in `src/main.zig` and `src/services/control.zig`. It provides a prototype of host-to-worker communication. There is no explicit room identity or independent room membership model in this new flow.

Application messaging already existed in the mobile FFI. Its sender and receiver at `src/meshguard_ffi.zig:574` and `:1137` implement the same `0x50` packet shape as the new daemon path. Consolidate that implementation inside MeshGuard before adding more clients: the paths already differ in relay selection, endpoint fallback, queue overflow behavior, and duplicate handling.

## Findings that determine the design

1. **The worker is a shell executor, not an integration with an agent's reasoning loop.** `runAgentLoop` extracts a `command` and calls `executeShellCommand`, which launches `cmd.exe /c` or `/bin/sh -c` (`src/main.zig:5237`, `:5708`). Running this worker in Grok's terminal does not by itself cause Grok Bot to reason about a delegated task. The application needs a receive/respond adapter that the actual agent uses.

2. **An invite is currently connection information.** The generated base64 JSON contains host identity, WG key, seed, and label (`src/main.zig:5432`). It has no room identifier, admission proof, expiry, role, or revocation state. The join path does not consume the token's WG key. It starts a new daemon with `--open` (`:5561`). A valid host key filters execution, but a malformed host key becomes a null filter and the loop still starts after greeting failure (`:5645`, `:5651`, `:5698`). Validate required identities before side effects and fail closed.

3. **Send success is not receipt.** `handleSend` returns success when a direct or relay UDP send succeeds (`src/services/control.zig:813`). The join path calls that a confirmed greeting (`src/main.zig:5636`). There is no corresponding host acknowledgement in this exchange. Room admission and task acceptance need explicit replies and deadlines.

4. **The inbox cannot support independent consumers.** The daemon has one 64-message, 1,024-byte-per-message queue. Overflow drops the oldest entry, and receive removes the next entry (`src/services/control.zig:136`, `:426`, `:448`). Two room clients or a worker and a monitoring client can consume each other's messages. Add application/channel routing and clear overflow behavior at the local messaging interface; keep room history and per-participant cursors in the room app.

5. **Command delivery is not durable or idempotent.** The daemon remembers only 128 nonces in process memory and records them before successful decryption (`src/main.zig:2107`). The worker does not keep a task-ID result ledger. A retry encrypted with a fresh nonce can execute a command again; restart also loses the cache. Authenticate before updating replay state. The application needs stable task IDs, durable acceptance/results, deadlines, cancellation, and explicit handling of uncertain outcomes. Do not promise exactly-once arbitrary shell effects.

6. **The payload size is a control-message budget.** Worker replies truncate stdout to 550 bytes and stderr to 180 before serialization (`src/main.zig:5726`). Patches, logs, and artifacts need a separate bounded transfer mechanism with size and hash verification. Growing one UDP datagram is not a sufficient artifact design.

7. **The release is not a coherent compatibility target.** The onboarding script reuses an installed binary if its version contains `0.9.0` and downloads assets from that release (`dist/agent-join.sh:21`, `:70`), while current source reports `0.10.0` (`src/version.zig:12`). GitHub's `v0.9.0` tag resolves to April commit `af9fc86`; selected assets were replaced on September 20 while macOS and other assets remain from April. The script performs no checksum verification. Publish a fresh immutable release with matching source, version, supported assets, checksums, and messaging capability negotiation.

The new application packet path derives its encryption key directly from static X25519 keys. It does not traverse the WireGuard session handshake (`src/services/control.zig:791`, `src/main.zig:2158`). Treat its authentication and replay properties as a separate protocol review; WireGuard compatibility alone does not establish those properties for application messages.

## What WormDB contributes, and what remains to prove

The inspected code contains local KV/WAL persistence, WORM records, append-log envelopes and MMR proofs, pub/sub, and MeshGuard-backed clustering. The separate `wormdb-server` composition repository also establishes a precedent for keeping application domains out of the database engine.

Several README statements lag the source: current code has org-trust configuration and replication namespace grants. Do not treat the older README's statement that all clustering is open as current behavior. The following limits were checked against the implementation:

- **Stock cluster startup is Linux-only.** `src/main.zig:218` skips clustering on Windows. A Windows workstation plus cloud Linux cannot use stock WormDB clustering unchanged. A portable transport adapter is real core work, not just application wiring.
- **Pub/sub is live signaling.** `src/server/executor.zig:218` publishes to the local event bus; it does not append a durable record or replicate that publication. Disconnected subscribers need catch-up from stored events. See `docs/architecture/pubsub.md`.
- **Replication is broader than selective sharing.** `src/cluster/node.zig:1010` sends writes to peers, and its reconnect path can enumerate the store (`:553`). Org namespace grants constrain incoming writes; they are not proof of outbound confidentiality filtering. Keep private agent state outside the shared store and establish explicitly scoped export/import before using a general cluster for collaboration.
- **A named append log is not distributed consensus.** `src/proof/append_log.zig:103` reads a local tail, allocates the next sequence, and writes a WORM key. Two disconnected nodes writing the same log can independently choose the same next sequence. Use a separate log per author/session, then merge room events by causal references; do not assume one room-wide counter is safe.
- **Append-log replication needs qualification.** `src/procedures/append_log.zig:54` invokes the proof helper, which writes directly to the store; that path does not itself call `cluster.replicateWrite`. The existence of both append logs and clustering does not establish live replication of these particular records.

These are reasons to make the room app a demanding consumer of WormDB, with reusable fixes upstream. They are not reasons to duplicate WormDB's database or implement a second networking stack in the application.

## Proposed ownership

| Project | Responsibility |
| --- | --- |
| MeshGuard | Peer identity, authenticated encrypted channels, discovery, NAT traversal, relays, portable connection lifecycle, channel routing, bounded transfer. |
| WormDB | Local durable records, immutable event storage and proofs, generic scoped replication, catch-up, recovery, local subscriptions, and explicit consistency behavior. Some of these require qualification or extension. |
| New room application | Room protocol and UI, membership and grants, selective publication, conversation/task meaning, agent adapters, human participation, artifact review, and local action policy. |

The application should depend on versioned releases of both projects. Extract the usable messaging seam and move product commands out of MeshGuard incrementally. Avoid a permanent fork of either core. Keep compatibility wrappers during migration if existing users rely on the commands.

Use one room process per participating environment, with its own WormDB store for shared room data. Model person, agent session, and transport peer separately: several agents can belong to one developer and share one machine. Private conversations, credentials, tool traces, and files never enter the replicated store by default. An explicit publish operation selects the payload and its room or recipients.

Each participant can create signed immutable events in an author/session-specific stream. The envelope should bind the room, author/session, event ID, causal parents, membership/key epoch, payload hash, and any artifact hashes. A room view is a projection of accepted events across these streams. Per-author sequence provides local ordering; causal parents preserve replies and dependencies; a deterministic tie-break orders concurrent events for display without claiming a global real-time order. Concurrent task decisions need application rules, not last-write-wins overwrites of a shared task record.

Durable events carry messages, task offers/acceptance/results, review comments, and artifact manifests. Ephemeral signals carry presence, typing, and disposable progress updates. Pub/sub wakes the local UI or agent adapter; durable records and cursors recover missed work. Large artifacts are transferred separately and verified against their manifests.

A creator can issue initial scoped admission grants without remaining online as a message sequencer. Membership changes need signed, versioned authority and an explicit conflict rule. Define revocation behavior under partitions: an offline peer cannot instantly learn a removal. Apply a new membership/key epoch to future traffic after convergence and never promise to revoke content already shared. Room availability after a creator leaves is an acceptance criterion, not an assumed consequence of using P2P networking.

For the first small rooms, authenticate each recipient and send shared events over pairwise encrypted channels to admitted participants. This avoids requiring a new group cryptography protocol just to prove three-party collaboration. Persist per-recipient delivery state for catch-up. Review session-key and forward-secrecy properties of the underlying message channel before describing it as production E2EE. Optional peers may store encrypted envelopes for offline delivery; a recipient must still possess the right keys to read them.

## First useful product slice

Proposed commands, not existing functionality:

```text
rooms create --project <repository> --goal "Investigate issue 42"
rooms join <invite>
rooms send @grok "Reproduce the failure and report evidence"
rooms watch
```

The room should show a participant roster and activity, a conversation, optional task offers and their status, and artifacts with base commit and validation evidence. People and agents can talk without creating a formal task. An agent may accept, decline, ask for clarification, or return a result using its own local tools. Joining must not automatically grant another participant a remote shell. The existing remote shell worker is a separate optional capability, not the room's execution model.

Provide a CLI/JSON interface for shell-capable agents first and an MCP adapter for compatible hosts. MCP exposes tools and resources to a host; it does not itself guarantee that an idle agent wakes to process messages. Each adapter must specify its polling/notification and resume behavior. See the [MCP architecture](https://modelcontextprotocol.io/specification/2026-07-28/architecture).

Use A2A's existing concepts for agent capabilities, tasks, messages, and artifacts when designing the application interface. Add an interoperability adapter once the real workflow is working; do not make full A2A support a prerequisite for the first three participants. See the [A2A 1.0 specification](https://a2a-protocol.org/v1.0.0/specification/).

Keep work in each participant's checkout. Exchange task context and explicit patches or commit references. Include repository identity, base SHA, artifact hash, and test evidence. Applying another developer's patch is a separate local action with a visible diff. Room access does not confer repository access or synchronize credentials.

## Implementation order and acceptance

1. **Prove a real conversation.** Use the actual local agent, actual Grok Bot environment, another developer's actual agent, and a human participant. Each publishes an intentionally selected message and responds using local tools. Establish process lifetime, wakeup behavior, outbound UDP availability, and no-admin operation. Both current direct and relay sends use UDP; a relay does not solve a platform that blocks UDP entirely.
2. **Make the two core dependencies support that slice.** In MeshGuard, unify daemon/FFI messaging, fix fail-open joining and replay-state ordering, and qualify authenticated delivery. In WormDB, establish portable scoped synchronization, durable author streams, and restart/catch-up behavior. Prefer small reusable core changes driven by failing application acceptance cases. Release verifiable compatible artifacts.
3. **Implement the decentralized room app in its own repository.** Build scoped invitations, separate participant/session identity, selective publication, signed durable events, replica convergence, directed messages, and optional task offers/results. The creator must be able to leave while other connected participants keep collaborating. Keep the CLI usable before investing in a desktop shell.
4. **Add the shared review experience.** Build roster/conversation/task/artifact views, human participation, patch inspection, and optional integrations. Use real project work to decide which UI features matter. Conversation and patch review do not require collaborative file editing; defer shared-buffer CRDTs until there is a concrete need.

Acceptance scenario: create one project room; admit the three independent agents and a human; request a reproduction from Grok; have the other developer's agent review the evidence; return a patch or commit reference; inspect it locally. Every participant uses its own tools. Disconnect and reconnect a participant without losing accepted work or silently repeating execution; take the creator offline while the others continue; merge concurrent messages without dropping either; reject an expired invite; remove a participant and deny future operations once the membership update is known. Verify that an unrelated local file and a private message never enter another participant's replica. Existing room history already seen by a removed participant cannot be recalled.

For delivery failures, test lost acknowledgements, duplicate requests with fresh transport nonces, process restart, full queues, messages for two local rooms, denied execution, and an artifact larger than 1 KiB. Distinguish receipt, acceptance, running, and completion in the UI and protocol.

## Production dogfood contract

Use the application to exercise the cores, not hide their defects. A missing transport primitive becomes a MeshGuard change; a missing durable-sync primitive becomes a WormDB change; room-specific policy remains in the application. The room application's integration suite should pin both dependency revisions and act as a release consumer for them.

Record the exact application and dependency builds in each qualification run. Start with Windows-to-cloud Linux and the other developer's actual platform. Exercise direct connectivity, forced relay, restart, packet loss, slow consumers, concurrent offline writes, invite expiry, removal, and multi-room isolation. Measure time to join, message latency, reconnect/catch-up time, duplicate counts, queue growth, memory use, and artifact hash correctness. Set production targets after measuring this representative workload rather than inventing numbers.

Keep durable writes and delivery acknowledgements distinct. Add a real project-work soak after the deterministic failure cases pass. A passing local unit suite or an attractive room UI does not establish production readiness of either core. Voice/video and collaborative editor buffers can be separate later phases; the first useful slice is live conversation, intentionally shared work, and recovery.

## Verification and limits

- Working tree was clean when investigation began.
- Unrelated working-tree edits appeared later in `src/discovery/membership.zig`, `src/discovery/swim.zig`, and `src/services/control.zig`. They were left untouched. Findings and the local 146-test result refer to the earlier reviewed snapshot, not qualification of those concurrent changes.
- Remote `main` matched the reviewed SHA.
- Local `zig build test -Dno-sodium=true --summary all`: 146/146 tests passed on Windows with Zig 0.16.0.
- [CI run 35487493743](https://github.com/igorls/meshguard/actions/runs/35487493743) succeeded for that exact SHA: Windows, macOS, and Linux builds; Linux tests with the standard crypto backend and the default backend.
- The local test target roots at `src/lib.zig` (`build.zig:177`); it does not run the CLI join/agent workflow implemented in `src/main.zig`. Passing these tests is not a cloud-room acceptance result.
- [Release metadata](https://github.com/igorls/meshguard/releases/tag/v0.9.0) was inspected live. Published binary contents and their source provenance were not independently reproduced.
- The walkthrough's writable install-directory description is older than the current script, which chooses the current directory or `/tmp`.
- No live Grok session, second developer, cross-network room, or end-to-end command execution was exercised. Code findings above are static observations, not a completed security audit.
- WormDB was inspected at source level only; no fresh WormDB build, test, or replication qualification was run. Its existing uncommitted work was left untouched. Current source, rather than stale README claims, was used for the capability assessment.
- MemPalace search returned no relevant prior decision about this Meet Link/room feature. This recommendation is grounded in the current code and the user's stated workflow.
- This note is the only repository change made by the investigation.
