# PLSChat Privacy-First Coverage Map — Architecture & Threat Model

**Status**: Phase 1 Complete (Interactive Prototype)  
**Date**: June 2026  
**Core Principle**: "Prove the network exists. Prove nothing else."

---

## 1. Why This Matters (Non-Negotiable)

PLSChat's value proposition is **decentralized, off-grid, anonymous communication** using LoRa mesh + persistent Room Servers + PLSC-powered premium features.

A naive public map of exact node locations would be **catastrophic**:

- Physical targeting / destruction / jamming of repeaters
- Owner de-anonymization (wallet linkage, social engineering)
- Traffic analysis (when & where people communicate)
- Defeats the entire anonymity model that makes PLSChat valuable vs Meshtastic (which shows exact pins)

**This map is a deliberate security feature, not a growth hack that compromises the product.**

---

## 2. What the Public Map Shows (Allowed)

| Data                          | Format                  | Why It's Safe                          | Example |
|-------------------------------|-------------------------|----------------------------------------|---------|
| Approximate coverage          | 1km grid squares + density heatmap | Proves network exists without precision | Green semi-transparent circles |
| Regional node counts          | Ranges only (e.g. 18–42) | No exact fingerprinting                | "Contributing nodes (est.)" |
| Aggregate messages relayed    | 24h totals per region  | No timing or content leaks             | "184,300 messages" |
| Needed repeater target grids  | Grid ID + status       | "Active" when filled — no attribution  | Amber dashed zones |
| Mesh density overlay          | Heatmap style          | No hop lines, no topology              | Opacity + color intensity |

**Never shown**:
- Exact GPS (even to map backend)
- Persistent Node IDs
- Individual uptime / stats
- Wallet addresses or license linkages on the map
- Message timing or content patterns
- Hop paths or RSSI per node

---

## 3. Node-Side Privacy Flow (Device Never Leaks)

```
[ESP32 / T-Deck / Heltec Node]
       │
       ├── 1. Boot → Generate random 128-bit NodeID (ephemeral, rotates every ~30 days)
       │
       ├── 2. GPS read → Immediately snap to nearest 1km grid square
       │                 (math: round(lat * 111) / 111, same for lng with cos(lat) correction)
       │                 Exact coords → discarded from RAM
       │
       ├── 3. Collect local aggregates only:
       │      - Uptime hours (this period)
       │      - Messages relayed count
       │      - (Optional) simple health metrics
       │
       ├── 4. Sign attestation with device private key
       │      (tied to PLSC device-bound license — verifiable but location-free)
       │
       └── 5. Submit ONLY:
             { grid_id: "g1km_51.51_-0.13",
               stats: { nodes_est_range, msgs_24h },
               signature,
               timestamp }
             → Map backend (or via Room Server gateway / Tor)
```

**Key guarantees**:
- Exact GPS **never** leaves the device.
- NodeID is meaningless after rotation.
- Signature proves legitimacy (license) without revealing identity or location.
- Backend receives **no IP** (if submitted via anonymity layer) and **no persistent identifier**.

---

## 4. Backend / Map Service (Minimal Trust)

**Design goals**: Stupidly simple. Hard to abuse. Nothing valuable to steal.

### Phase 2 (Recommended Implementation)
- **Cloudflare Workers** or **Fly.io** / **Railway** minimal API
- Endpoints:
  - `POST /submit` — accepts only validated `{grid_id, stats, signature, ts}`
    - Validates signature against known license public keys (or future ZK)
    - Rate limits aggressively (per grid + global)
    - **Immediately discards** raw submission after aggregation
    - **Never logs** IP, User-Agent, or timestamp beyond coarse bucket
  - `GET /coverage.geojson` — public aggregated data (grid squares + density + ranges)
- Storage: Ephemeral or short-lived (Redis + hourly dump to immutable storage)
- No database of individual submissions after processing
- Optional: Submissions can come via existing Room Servers (they already have internet uplink in many deployments)

**Security properties**:
- Even full server compromise → attacker sees only which 1km squares were active in last N hours
- No way to link submissions to specific devices or people
- No long-term NodeID tracking

### Phase 3+ (Decentralized)
- Publish aggregated GeoJSON to IPFS + Arweave (immutable, censorship resistant)
- Use The Graph or custom subgraph for on-chain verification of aggregates (if desired)
- Future: Nodes can submit directly via smart contract calls (with ZK proofs)

---

## 5. Reward System Privacy (PLSC)

Rewards must **not** create a side-channel that deanonymizes nodes.

**Current / Recommended Model**:
1. Node generates local uptime + relay attestation (signed).
2. Attestation submitted **directly to PLSC reward smart contract** (or privacy oracle) — **bypassing the map entirely**.
3. Contract verifies signature / license validity.
4. Payout to the license-controlled address.
5. Because:
   - License acquisition can be private
   - No location data ever touches the reward path
   - Map data is deliberately coarse and non-linkable
   → There is **no reliable correlation** between "someone earned rewards" and "this specific grid square had activity".

**Future (Stronger)**:
- Zero-knowledge coverage proofs (zkSNARK / zk-STARK) proving "I am a valid licensed node that provided coverage in some grid without revealing which grid".
- This makes even the reward contract blind to location.

**Important**: The map page should **never** be the source of truth for rewards. Rewards are on-chain / contract-driven.

---

## 6. Threat Model (Assumed Adversary)

**Adversary capabilities**:
- Full read access to public map + all historical aggregates
- Can monitor PulseChain for PLSC reward transactions
- Can seize or compromise the map backend server
- Can perform traffic analysis on any internet uplinks
- Wants to locate high-value nodes (journalists, activists, event organizers, etc.)

**What adversary CANNOT do (by design)**:
- Determine exact location of any node (1km uncertainty + no persistent ID)
- Link a specific node to its owner or wallet via the map
- Know which nodes are online right now or their uptime patterns
- Reconstruct mesh topology or communication paths
- Use reward payouts to de-anonymize operators

**Residual risks we accept** (and mitigate elsewhere):
- Very high-density grids in tiny countries could theoretically narrow possibilities (mitigation: encourage more nodes everywhere)
- Social engineering of node operators (outside scope of map — education + opsec)
- Supply-chain attacks on firmware (addressed by open source + reproducible builds)

---

## 7. Implementation Phases (Roadmap)

| Phase | Deliverable                          | Status     | Notes |
|-------|--------------------------------------|------------|-------|
| 1     | Interactive static prototype (this HTML) | ✅ Done   | Self-contained, beautiful, ready to drop into plschat-site repo |
| 2     | Real backend aggregator + live data | Next      | Minimal API, strict privacy, GeoJSON output |
| 3     | On-chain reward integration         | Planned   | Direct from nodes to contract |
| 4     | Decentralized map data (IPFS) + ZK  | Future    | Maximum censorship resistance & privacy |
| 5     | Node firmware integration           | Parallel  | Add optional "report to map" toggle in firmware (off by default, privacy warning) |

---

## 8. Files Created

- `coverage-map.html` — Production-ready interactive prototype page (copy to repo root or `/map`)
- This architecture document

**How to integrate into existing plschat-site**:
1. Copy `coverage-map.html` into the repo as `coverage.html` or `map.html`
2. Add nav link in `index.html` and other pages: `<a href="coverage.html">Coverage Map</a>`
3. (Optional) Add a hero card on homepage: "See the mesh grow — privately →"
4. Update GitHub README + docs with link to new page + this architecture doc

---

## 9. Final Design Philosophy

> We would rather launch with a slightly less impressive map than ship something that puts node operators at risk.

This map turns privacy into a **competitive advantage**:
- Meshtastic shows exact pins → PLSChat shows "the network is real and growing" without the risks.
- This becomes a selling point for security-conscious users (preppers, activists, journalists, event organizers, remote teams).

**If we can't keep users, repeaters, and the mesh safe and anonymous — we don't build the feature.**

---

*Built with security & anonymity as the primary constraints, not afterthoughts.*

**Next step**: Review this doc + prototype. Then decide: Phase 2 backend first, or firmware integration, or both in parallel? 

Ready when you are.