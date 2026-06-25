# Making agnostic-LoRa-Net more airtime-efficient — recommendations

These are suggestions for the **agnostic-LoRa-Net** firmware
(`../platformIO/agnostic-lora-net`), captured here because this repo can't modify
that tree. They come out of the bearer comparison (`BEARER-COMPARISON-MESHCORE-VS-AGNOSTIC.md`)
— specifically the finding that ALN's *per-link* airtime is heavier than MeshCore's
because of its header and SAR framing, even though ALN wins at the network level by
routing instead of flooding. Closing the per-link gap makes ALN strictly better.

All byte counts are exact from source (`include/packet.h`, `lib/mesh/sar.h`,
`include/board_config.h`); airtime is the Semtech LoRa formula at ALN's default
**SF9 / BW250 / CR4:5**.

## Current overhead (the exact picture)

| Constant | Value | Where |
|---|---|---|
| `HEADER_BYTES` | **41 B** = LinkHeader(4) + NetHeader(37) | `packet.h` |
| — of which dst + src node IDs | **32 B** (two 16-byte self-certifying IDs) | `NetHeader` |
| `MAX_PAYLOAD` | **230 B** (not 250 — SX1262 ceiling is 255) | `packet.h` |
| Single-frame RNS capacity | 189 B (230 − 41) | derived |
| `SAR_CHUNK` | **160 B** per fragment | `sar.h` |
| `SAR_HDR_BYTES` | **18 B** = magic(4)+xfer(2)+idx(2)+cnt(2)+len(4)+crc(4), on *every* fragment | `sar.h` |
| `PHY_PREAMBLE_SYMS` | **16** (MeshCore uses 8) | `board_config.h` |

> Note: you recalled the packet size as ~250 B; the live cap is `MAX_PAYLOAD = 230`,
> raised from 200 to fit a 167-B announce + 41-B header in one frame. Headroom to ~250
> exists under the 255-byte SX1262 limit (recommendation C).

On a full single frame the header is **17.8 %** of airtime (41 of 230 B); on
multi-fragment transfers effective goodput falls to ~68 % because the 41-B header +
18-B SAR header repeat on every 160-B chunk.

## Recommendations, ranked by value ÷ effort

| # | Change | Saves | Effort / risk |
|---|--------|-------|---------------|
| **A** | **Preamble 16 → 8 symbols** | ~16 ms/frame (~3 %) | Trivial (one constant). Safe while nodes run **continuous RX**; revisit if RX duty-cycling is ever added (a duty-cycled receiver needs a preamble ≥ its wake period). Network-wide flag day (TX/RX must match). |
| **B** | **Fill the frame: raise `SAR_CHUNK` 160 → `MAX_PAYLOAD−HEADER−SAR_HDR`** (171 at max230, 203 at max250) | **500 B: 4 → 3 fragments** (−1 preamble+header). ~−6 % alone | One constant; SAR is end-to-end (xfer_id + CRC), so bump a SAR version. **Highest value-per-effort.** |
| **C** | **Raise `MAX_PAYLOAD` 230 → ~250** | Single-frame cap 189 → 209; bigger SAR chunks | One constant, under the 255 limit. Caveat: longer frames have a higher frame-error rate on marginal links — ARQ/SAR recover, but it's a real good-link-vs-bad-link tradeoff. |
| **D** | **Trim the SAR header 18 → 6/14 B.** (1) Replace the 4-B `"SAR1"` magic with a `NetHeader` flag bit or a `PKT_SAR` type — the type field already exists. (2) Carry `total_len`(4)+`total_crc`(4) **only in fragment 0** (or the last), not every fragment. | Up to **12 B/fragment** | Moderate; SAR-layer change + version bump. Pairs with B. |
| **E** | **Short locators for DATA packets.** Use an **8-byte** (or 6-byte) routing locator for dst/src on `PKT_DATA`, keeping full 16-byte self-certifying IDs only on `PKT_BEACON`/`PKT_CONTROL`/announces (where signatures actually need them). | **16 B/frame** → header 41 → 25; goodput 80 → 87 % single-frame, 68 → 83 % multi-frag | Larger change, but **aligns with the project's own `identity-vs-locator` boundary** ("mesh routes on locators, apps address on identity hashes") and the in-progress `locator_dir` / distributed-lookup work. Highest structural payoff. |
| F | Flow-handle compression: full locator in SAR fragment 0, a 1–2 B flow handle after (all fragments share dst/src). | a few B/fragment beyond E | Lower priority; diminishing returns once E lands. |
| G | Per-link rate adaptation: use the existing runtime retune + Tier-1 controller to drop to a faster SF/wider BW on strong links. | large, systemic | Complex; the real long-term airtime lever. Future. |

Rationale for **E** (the big one): DATA packets are opaque, RNS-encrypted bytes — the
mesh never authenticates them, so it doesn't need a *self-certifying* address on them,
only a routable *locator*. The 16-byte self-certifying ID earns its keep on announces and
signed control packets; spending it on every data fragment is the single largest avoidable
cost. An 8-byte locator is a 2⁶⁴ space — collision-free for any realistic LoRa mesh.

## Before / after (computed, SF9/BW250)

| RNS packet | v0 current | v1 = A+B+C+D (quick wins) | v2 = v1 + E (8-B data locator) | MeshCore default (ref) |
|---|--:|--:|--:|--:|
| announce 167 B | 539 ms · 80.3 % | 523 ms · 80.3 % | **482 ms · 87.0 %** | 749 ms · 76.6 % |
| LXMF 250 B | 966 ms · 67.9 % | 892 ms · 71.0 % | **820 ms · 78.1 %** | 974 ms · 83.9 % |
| RNS MTU 500 B | 1921 ms · 67.9 % | 1619 ms (4→3 fr) · 77.0 % | **1507 ms · 83.2 %** | 1958 ms · 83.9 % |

- **v1 (constants only, no ID change)** already cuts the 500-B transfer from 4 frames to
  3 and ~16 % of its airtime — cheap and low-risk.
- **v2** brings ALN's per-frame goodput up to MeshCore's ~83 % *and* keeps ALN's
  network-level routing advantage — so tuned ALN beats MeshCore's default on the 500-B
  case (1507 vs 1958 ms) while still avoiding flood duplication on multi-hop.

## Why this also helps duty cycle / regulatory headroom

ALN's `todo.md` flags **FCC dwell-time handling** for the fixed 906.625 MHz channel
(15.247 digital-modulation rules care about channel occupancy/dwell). Every airtime
reduction above is double-counted as benefit: less time on channel per packet means
(1) more dwell/duty headroom, (2) lower collision probability under load — which raises
*effective* throughput beyond the raw per-packet saving, and (3) less energy per message
for solar/battery nodes. The narrow-band MeshCore default (BW62.5) has the opposite
pressure — comparable airtime but tighter carrier-frequency tolerance — which ALN's
BW250 default avoids; keeping ALN's frames short preserves that margin.

## Suggested sequencing

1. **A + B + C** — three constants, immediate ~6–16 % wins, lowest risk. One coordinated
   version bump (preamble + SAR chunk + max payload all touch the wire).
2. **D** — SAR header diet, same SAR version bump window.
3. **E** — the locator split; schedule with the `locator_dir` / identity-vs-locator work
   that's already underway, since it shares the addressing machinery.

(These are firmware-side; nothing here changes what the web client implements. They do
make ALN a meaningfully better bearer for the tunnel in `BEARER-COMPARISON-MESHCORE-VS-AGNOSTIC.md`.)
