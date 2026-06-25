# Bearer comparison — MeshCore tunnel vs. agnostic-LoRa-Net

Question: to give the web client **multi-hop RNS over LoRa**, which bearer
should it integrate — tunnelling raw Reticulum packets over a stock **MeshCore**
companion radio (see `MESHCORE-RNS-TUNNEL-SPEC.md`), or over **agnostic-LoRa-Net**
(`../platformIO/agnostic-lora-net`, the custom mesh firmware)?

This is an independent assessment from the web client's point of view. Both
were read at the wire-contract level: MeshCore's companion protocol (verified in
the spec) and agnostic's tunnel contract (`docs/tcp-bridge.md`, `include/packet.h`).

**Bottom line up front:** for any network you deploy yourself, **agnostic-LoRa-Net
is the better bearer** — cleaner crypto, far less web-client code, no
self-fragmentation, real routing/reliability, and RNS-over-mesh is already proven.
**MeshCore wins on exactly one axis: reaching an existing, off-the-shelf,
already-deployed mesh you don't control.** Whether that axis matters is the whole
decision (§7).

---

## 1. The two integration surfaces, side by side

| | **MeshCore companion (the spec)** | **agnostic-LoRa-Net tunnel** |
|--|--|--|
| Browser transport | BLE NUS (`6e400001/2/3`) | BLE NUS (`6e400001/2/3`) — *same* |
| Wire framing to the radio | MeshCore companion command protocol: `APP_START`/`SET_CHANNEL`/`SEND_CHANNEL_DATA(0x3E)`/`CHANNEL_DATA_RECV(0x1B)` — a bespoke codec we reverse-engineered | **HDLC** (`FLAG 0x7E`, `ESC 0x7D`) — the *same framing the repo already uses* in `hdlc.js` + `rnsd-interface.js` |
| Frame body | `data_type` + our 8-byte tunnel envelope + RNS slice | `[addr_type][addr_len][addr][payload]`; payload = the raw RNS packet, verbatim |
| New web-client code | A whole new interface **plus** a companion-protocol codec **plus** our own fragmentation/reassembly | A thin interface ≈ `rnsd-interface.js` + a typed-address prefix. Reuses `hdlc.js` unchanged |
| Fragmentation | **Ours.** 163-byte host payload → ~155 usable; announces ≈2 frags, packets ≈4; we own reassembly + TTL buffers | **Firmware's.** Node SARs up to 8 KB transparently (CRC + missing-fragment NACK). Web client sends one frame |
| Encryption layers | **Two** — MeshCore channel (AES-128-ECB + 2-byte MAC, shared PSK) *wraps* RNS's AES-256 | **One** — RNS end-to-end only; backbone treats payload as opaque, no network key |
| Addressing | Channel broadcast/flood; RNS filters dest-hash on top | Typed locator: `addr = node-id` (4→16 B), **routed** multi-hop; broadcast = all-`0xFF` |
| Reliability below RNS | None (single-shot datagrams) | Per-hop ARQ (ACK+retry) + SAR NACK repair; CSMA via hardware CAD |
| RNS-over-this proven? | **No** — channel-datagram tunnel is unbuilt/unproven | **Yes** — `scripts/rns_demo.py` round-trips a cryptographically-proven echo over the mesh |
| Existing deployed network | **Large** public community mesh; off-the-shelf radios, stock firmware | **None but yours** — every node must be flashed with agnostic firmware |
| Who controls it | Third party — we adapt to it | You — extend it to fit exactly |

---

## 2. Encryption: single vs. double

Covered in depth in the spec §10; the short version for the decision:

- **MeshCore is double-encrypted and you can't opt out** — a MeshCore channel *is*
  its PSK encryption, so RNS ciphertext rides inside AES-128-ECB with a 16-byte
  channel secret every participant shares. It doesn't *weaken* RNS (the inner layer
  is intact), but it adds airtime overhead and a **shared key that, if leaked, lets
  anyone inject/flood the channel** (a DoS/spam surface, not a confidentiality break).
- **agnostic is single-encrypted by design** — the backbone is explicitly "bring
  your own crypto; the mesh never sees plaintext and there is no network key to leak."
  RNS provides the only (and the real) encryption.

Net: agnostic is the cleaner security model and the one the agnostic README
markets *against* MeshCore. Not a security disqualifier for MeshCore, but a clear
point for agnostic.

---

## 3. Web-client effort: the asymmetry is large

This is where the two diverge most for *this repo*.

**agnostic** lands almost on top of the existing architecture:
- The repo already has `hdlc.js` and `rnsd-interface.js` (HDLC-framed raw RNS
  packets over a byte stream). agnostic's tunnel is *the same idea* — the only delta
  is a `[addr_type][addr_len][addr]` prefix before the RNS bytes and reading a
  src-node-id off inbound frames. The `_onPacket`/`sendPacket`/capabilities contract
  is unchanged.
- **No fragmentation layer** — the node's SAR handles >178-byte payloads, so a
  187-byte announce or a 500-byte packet is one `sendPacket()` call.
- There's even a **zero-new-code path**: run `rnsd` with `AgnosticLoraInterface` +
  the shipped `tcp_bridge.py`, and the web client reaches the mesh through its
  *existing* `rnsd-interface.js`/WebSocket path. (Cost: needs a host running the
  bridge — not pure browser+BLE.)

**MeshCore** requires net-new machinery: a companion command codec
(`APP_START` handshake, `SET_CHANNEL` provisioning, `0x3E`/`0x1B`), a tunnel
envelope with a sender-tag (because `0x1B` carries no sender id), and a full
fragmentation/reassembly engine with bounded TTL buffers. None of it reuses the
existing interface modules beyond the raw BLE transport.

Rough effort: agnostic ≈ a focused interface module (or just config, via the
rnsd path); MeshCore ≈ that **plus** a protocol codec **plus** a reassembler — and
more unknowns to close on real hardware.

---

## 4. Routing, reliability, throughput

- **Routing.** MeshCore tunnel = flood/broadcast; every RNS packet (including
  periodic announces) is flooded across the whole MeshCore mesh and filtered by RNS
  at the edges — simple but airtime-heavy and impolite on a shared community mesh.
  agnostic routes per-direction by link quality (asymmetric links are first-class),
  so traffic is directed, not flooded. agnostic's catch: it routes on **node-id
  locators**, and identity→locator resolution (so an app can address by RNS hash) is
  still being built — today you address a node id or broadcast.
- **Reliability.** agnostic adds per-hop ARQ and SAR NACK under RNS's own proofs;
  MeshCore datagrams are single-shot (RNS carries all reliability). agnostic is
  strictly more robust on lossy RF.
- **Throughput / airtime.** See §4a for computed numbers — the result is *not* a
  clean win for either, and corrects the loose "agnostic uses less airtime" claim.
  Short version: **per single transmission MeshCore is as tight or tighter** (no
  32-byte node IDs, bigger fragments), but **per network delivery agnostic wins**
  because directed routing avoids flood duplication.

## 4a. Airtime — computed numbers (factual)

All byte counts are exact from source (`packet.h`: 41-B header, `MAX_PAYLOAD 230`;
`sar.h`: `SAR_HDR 18`, `SAR_CHUNK 160`; MeshCore: `MAX_CHANNEL_DATA_LENGTH 163`,
8-B tunnel envelope, AES-128 pad to 16 B + 1-B channel hash + 2-B MAC). Airtime is
the standard Semtech LoRa formula, **identical PHY for both** (same SX1262):
BW 250 kHz, CR 4/5, explicit header, CRC on, 8-symbol preamble. MeshCore assumed at
its best case (no 4-B message timestamp; FLOOD route, no transport codes).

**Per single source transmission, single hop, SF9/BW250:**

| RNS packet | bearer | frames | on-air B | airtime | goodput | ms/RNS-byte |
|---|---|--:|--:|--:|--:|--:|
| announce (167 B) | agnostic | **1** | 208 | **523 ms** | 80.3 % | 3.13 |
| announce (167 B) | MeshCore | 2 | 218 | 595 ms | 76.6 % | 3.56 |
| LXMF (250 B) | agnostic | 2 | 368 | 933 ms | 67.9 % | 3.73 |
| LXMF (250 B) | MeshCore | 2 | 298 | **779 ms** | **83.9 %** | 3.12 |
| RNS MTU (500 B) | agnostic | 4 | 736 | 1856 ms | 67.9 % | 3.71 |
| RNS MTU (500 B) | MeshCore | 4 | 596 | **1548 ms** | **83.9 %** | 3.10 |

Two honest findings:
- **≤189-B payloads (announces): slight edge agnostic** — it fits one frame where
  MeshCore needs two, and the saved preamble/header beats agnostic's heavier framing.
- **>189-B payloads: MeshCore is more efficient per transmission** — agnostic pays
  for two 16-byte self-certifying node IDs (41-B header) plus an 18-B SAR header on a
  160-B chunk, so its goodput sits ~68 % vs MeshCore's ~84 %. The richer addressing
  is a real airtime cost. (At SF11 the *ratios* are identical; wall-clock is ~3.3×
  these numbers — e.g. 250-B agnostic = 3117 ms, MeshCore = 2585 ms.)

**But airtime is a network property, not a per-link one.** MeshCore *floods* — every
repeater that hears a packet rebroadcasts the whole thing; agnostic *routes* — one
transmission per hop on the path (+ a ~62 ms link-ACK per frame per hop). Total
network airtime to deliver the 250-B LXMF, SF9/BW250:

| topology | agnostic (routed + ARQ) | MeshCore (flood) |
|---|--:|--:|
| 1 hop, fan-out 1 | 1057 ms | **779 ms** |
| 2 hops, fan-out 3 | **2114 ms** | 2338 ms |
| 3 hops, fan-out 6 | **3170 ms** | 4676 ms |
| 4 hops, fan-out 12 | **4227 ms** | 9351 ms (2.2×) |

MeshCore wins the trivial 1-hop case; agnostic pulls ahead from ~2 hops on and the
gap widens with mesh size, because flood airtime scales with the **number of
repeaters reached** while routed airtime scales with **path length**. On any mesh
bigger than a few nodes, agnostic's directed forwarding is the decisive airtime win —
not its per-frame framing, which is actually heavier.

> PHY note: §4a uses one shared SF for fairness. The bearers' *real* defaults differ —
> see §4b, which turns out to be the more interesting comparison.

## 4b. At each bearer's real default PHY

The §4a numbers hold SF constant. But the two ship different defaults, and comparing
them as-deployed is what matters:

- **agnostic default** (`board_config.h`): **SF9 / BW 250 kHz / CR 4:5 / 16-sym preamble / 22 dBm**.
- **MeshCore NA public default**: **SF7 / BW 62.5 kHz / CR 4:5 / 910.525 MHz** — note the
  bandwidth is **62.5 kHz**, not 250. You can't read "SF7" without the bandwidth.

These two presets share an **identical 2.048 ms symbol time** (`2⁷/62500 = 2⁹/250000`),
so they land at nearly the same operating point from opposite directions:

| RNS packet | MeshCore SF7/BW62.5 | agnostic SF9/BW250 |
|---|--:|--:|
| announce 167 B | 2 frames, 749 ms | **1 frame, 539 ms** |
| LXMF 250 B | 2 frames, 974 ms | 2 frames, 966 ms |
| RNS MTU 500 B | 4 frames, 1958 ms | 4 frames, 1921 ms |

**Range (relative link budget, lower = more sensitive):** MeshCore SF7/BW62.5 ≈ **40.5 dB**
vs agnostic SF9/BW250 ≈ **41.5 dB** → MeshCore is **~1 dB *more* sensitive**. Dropping
bandwidth 4× (+6 dB) and dropping SF by 2 (−5 dB) nearly cancel.

So the intuition "SF7 = short range" is a **false alarm for this preset**: paired with
BW 62.5 kHz, MeshCore's range is comparable-to-slightly-better than agnostic's SF9/BW250,
and per-link airtime is within a few percent. What SF7/BW62.5 *actually* costs:

- **Narrow-band frequency tolerance** — BW 62.5 kHz demands tighter carrier accuracy
  (ppm crystal/temperature drift is a bigger fraction of 62.5 kHz than of 250 kHz). Fine
  on TCXO boards, marginal on crystal-only ones. BW250 has no such sensitivity. This is
  the real SF7/BW62.5 footgun — not range.
- **Low absolute throughput** (~same slow data rate as SF9/BW250) — large payloads/Links
  stay painful on either bearer.
- **You don't control it.** Joining the *public* MeshCore mesh locks you to its
  SF7/BW62.5 preset; agnostic's PHY is yours to set network-wide and retune.

The decisive airtime factor is unchanged by PHY: **MeshCore floods, agnostic routes.**
Per-link they're tied at real defaults; per network delivery agnostic's directed
forwarding still wins from ~2 hops on (§4a). (Minor aside: agnostic's 16-symbol preamble
is double MeshCore's 8 — a cheap ~16 ms/frame it could trim.)

---

## 5. Maturity & risk

- **MeshCore companion protocol**: mature, documented, widely deployed — *as a
  MeshCore chat transport*. Using a channel datagram as an **RNS tunnel** is
  unproven, and carries the spec's open caveats (self-echo unknown, 8-channel-slot
  limit, double-enc overhead, flood duty-cycle).
- **agnostic**: the firmware and its **RNS-over-mesh** are proven on real hardware
  (proven-echo demo, BLE+LoRa coexistence). The gap is the *web-client* side — its
  `web/ble.html` is a chat demo, not an RNS interface — but that gap is small and
  squarely in code you own.

Both carry build risk; agnostic's risk is "wire up a known-good bearer," MeshCore's
is "prove a novel tunnel works at all."

---

## 6. Where MeshCore genuinely wins

Be fair to it — these are real:

1. **An existing, large, deployed mesh.** If there are MeshCore repeaters in your
   area *right now*, MeshCore gives you multi-hop reach with **zero infrastructure of
   your own**. agnostic gives you nothing until you deploy nodes.
2. **Off-the-shelf hardware, no flashing.** A participant buys a MeshCore radio,
   runs stock firmware, and the browser drives it. agnostic requires flashing custom
   firmware onto supported boards (RAK4631, XIAO nRF52, T1000-E, Heltec V4, …) — a
   higher bar for a casual new participant.
3. **Lower per-participant setup** for that reason — the hardware barrier to a new
   user joining is smaller.

---

## 7. The deciding question (and the honest catch)

It comes down to **which network you are trying to join**:

- **"Use the public MeshCore mesh as free relays."** Then MeshCore is the *only*
  option — but read the catch. MeshCore users run **MeshCore, not Reticulum**.
  Tunnelling RNS over their channel does **not** let you talk to them; it only borrows
  their radios to relay *your* RNS overlay, while flooding their mesh with opaque,
  double-encrypted traffic they can't use. The headline "existing network" benefit is
  really "someone else's airtime for your flood," which is both less useful and less
  neighbourly than it first sounds. Both endpoints still need *your* tunnel software
  anyway — MeshCore radios are just the bearer.
- **"Build a Reticulum LoRa overlay I (or my community) control."** Then
  agnostic-LoRa-Net is the better bearer on essentially every technical axis, is far
  less web-client code, is already proven carrying RNS, and is yours to extend (e.g.
  finish identity→locator so the web client can address by RNS hash). The cost is you
  must flash the nodes — which you're doing for an overlay you control regardless.

---

## 8. Recommendation

**Default to agnostic-LoRa-Net** as the web client's multi-hop LoRa bearer:

1. It reuses the existing `hdlc.js` + `rnsd-interface.js` shape — smallest, lowest-risk
   integration, and a possible **zero-new-code** path via `rnsd` + `tcp_bridge.py`.
2. Single-layer encryption, no shared channel PSK, no self-fragmentation (firmware SAR).
3. Routed + ARQ + proven RNS-over-mesh — strictly more robust than flood datagrams.
4. It's your stack: the one real gap (identity-addressed delivery for the browser) is
   yours to close, not a third party's.

**Keep the MeshCore tunnel spec on the shelf for one specific case:** you need to
ride an *existing, deployed* MeshCore mesh with off-the-shelf radios and zero
firmware work, and you accept double encryption, self-fragmentation, flood airtime,
and that you're using the mesh as a relay rather than talking to its users.

Suggested concrete next step if agnostic is chosen: prototype the **direct-BLE
agnostic interface** (`agnostic-interface.js`) — clone `rnsd-interface.js`, keep its
HDLC parser, add the `[0x01][len][node-id]` address prefix on send and strip the
src-id on receive. That is the apples-to-apples equivalent of the MeshCore companion
interface, at a fraction of the code.

---

## References
- `MESHCORE-RNS-TUNNEL-SPEC.md` (this repo) — the verified MeshCore path.
- agnostic-LoRa-Net `docs/tcp-bridge.md` — tunnel wire contract (HDLC + typed address).
- agnostic-LoRa-Net `include/packet.h` — on-air header, `MAX_PAYLOAD`, node-id width.
- agnostic-LoRa-Net `README.md` — the stack, the MeshCore comparison, proven status.
- agnostic-LoRa-Net `reticulum/interfaces/AgnosticLoraInterface.py` — the RNS interface.
