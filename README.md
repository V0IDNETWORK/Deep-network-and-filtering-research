# 🛡️ V0IDNETWORK

**Advanced Research on Networking, Anti-Censorship Technologies & Internet Freedom**

> By **Iliya** — 17-year-old Independent Researcher in Networking, Applied Cryptography, and Internet Measurement

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Status](https://img.shields.io/badge/status-research--in--progress-blue)](#)
[![Topics](https://img.shields.io/badge/topics-networking%20%7C%20VPN%20%7C%20DPI%20%7C%20censorship-orange)](#)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](#)
[![Made with Markdown](https://img.shields.io/badge/made%20with-Markdown-1f425f.svg)](#)

---

> ⚠️ **Disclaimer:** This repository is an educational and research resource on networking, encryption, and Internet-measurement topics. It documents *publicly known* protocol designs and *publicly published* censorship-measurement research (RFCs, vendor documentation, and peer-reviewed papers from venues such as USENIX Security, PETS, and FOCI). It is **not** an operational evasion manual, and it does not target any specific system, organization, or individual. Always follow the laws of your jurisdiction.

## 🌐 Overview

The modern Internet is a layered, negotiated system — and increasingly, a **contested** one. Every TLS handshake, every DNS query, and every UDP datagram is also a fingerprint that a sufficiently motivated observer can read, classify, and act on. **V0IDNETWORK** is a deep-dive research project that maps this contest from the ground up: how packets actually move through the stack, how VPN and proxy protocols try to hide that movement, how Deep Packet Inspection (DPI) tries to see through the hiding, and how nation-state filtering systems — with Iran as the primary case study — combine all of this into a working censorship architecture.

This document does **not** stop at "protocol X uses encryption Y." It traces the full chain: *wire format → fingerprint → detection model → filtering action*, because that is the chain that determines whether a circumvention tool actually survives contact with a real censor.

---

## 📑 Table of Contents

1. [Networking Fundamentals & Data Flow](#1-networking-fundamentals--data-flow)
2. [VPN Technologies – How They Work & How They Get Blocked](#2-vpn-technologies--how-they-work--how-they-get-blocked)
3. [DNS & Encrypted Protocols](#3-dns--encrypted-protocols)
4. [V2Ray / Xray Deep Architecture](#4-v2ray--xray-deep-architecture)
5. [Tunnel Technologies & Encapsulation](#5-tunnel-technologies--encapsulation)
6. [Deep Packet Inspection (DPI)](#6-deep-packet-inspection-dpi)
7. [Internet Censorship Techniques](#7-internet-censorship-techniques)
8. [Technical Analysis of Internet Filtering in Iran](#8-technical-analysis-of-internet-filtering-in-iran)
9. [References](#9-references)
10. [About the Author](#10-about-the-author)

---

## 1. Networking Fundamentals & Data Flow

### 1.1 OSI vs. TCP/IP — Two Maps of the Same Territory

| OSI Layer | TCP/IP Layer | Unit of Data | Examples |
|---|---|---|---|
| 7 — Application | Application | Message | HTTP, DNS, TLS (application data) |
| 6 — Presentation | *(merged into Application)* | — | Encoding, compression |
| 5 — Session | *(merged into Application)* | — | Session tokens, TLS session resumption |
| 4 — Transport | Transport | Segment / Datagram | TCP, UDP, QUIC |
| 3 — Network | Internet | Packet | IPv4, IPv6, ICMP |
| 2 — Data Link | Link | Frame | Ethernet, Wi‑Fi (802.11) |
| 1 — Physical | Link | Bit | Copper, fiber, radio |

The TCP/IP model collapses OSI's Presentation and Session layers into the Application layer — which is exactly why TLS (a "session/presentation" concern) is implemented as a library sitting *on top of* TCP rather than as a true OS network layer.

### 1.2 The Journey of a Packet: Encapsulation & Decapsulation

When a browser sends an HTTPS request, the payload is wrapped — layer by layer — on the way down the stack, and unwrapped in reverse order at the receiver:

```
┌──────────────────────────────────────┐
│ Application Data (HTTP request)       │  Layer 7
├──────────────────────────────────────┤
│ + TCP/UDP header (ports, seq/ack)     │  Layer 4
├──────────────────────────────────────┤
│ + IP header (src/dst IP, TTL)         │  Layer 3
├──────────────────────────────────────┤
│ + Ethernet/Wi-Fi frame (MAC addrs)    │  Layer 2
├──────────────────────────────────────┤
│ + Electrical / optical / RF signal    │  Layer 1
└──────────────────────────────────────┘
```

Each layer **encapsulates** the layer above it by prepending (and sometimes appending) its own header, and treats everything it receives from above as opaque payload. The receiving stack does the reverse — **decapsulation** — stripping headers one layer at a time until the original application message is reassembled. This encapsulation principle is the single most important idea for understanding circumvention: **every tunneling and obfuscation technique in this document is just "add one more encapsulation layer that a censor's classifier doesn't recognize."**

### 1.3 Packets, Frames, Routing & Switching

- **Packet** — the Layer 3 unit (an IP datagram: header + payload).
- **Frame** — the Layer 2 unit (e.g., an Ethernet frame: MAC header + IP packet + FCS).
- **Routing** — Layer 3 forwarding decisions made by routers based on destination IP and routing tables (longest-prefix match).
- **Switching** — Layer 2 forwarding within a local segment, based on destination MAC address and a learned MAC table.

### 1.4 NAT & CGNAT

**NAT** (Network Address Translation) rewrites source/destination IP (and usually port) fields so multiple private hosts can share one public IP. **CGNAT** (Carrier-Grade NAT) is the ISP-scale version: thousands of subscribers share a small pool of public IPv4 addresses, with the operator maintaining large translation tables. This matters for circumvention because **CGNAT means many residential connections do not have a stable, individually-addressable public IP**, which affects both client-side blocking precision and certain NAT-traversal techniques (relevant to WireGuard and other UDP-based VPNs).

### 1.5 BGP — How Networks Find Each Other

**BGP** (Border Gateway Protocol) is the inter-domain routing protocol that glues the Internet's Autonomous Systems (ASes) together. Each AS advertises the IP prefixes it can reach, along with an AS-path, to its BGP neighbors; routers select a best path per prefix based on policy, path length, and other attributes. BGP is relevant to censorship at the nation-state level because route announcements (or withdrawals) can be used to black-hole traffic to specific prefixes, or to force traffic through a chokepoint where DPI is deployed.

### 1.6 DNS, SNI, TLS Handshake, QUIC, HTTP/2 & HTTP/3

- **DNS** resolves human-readable names to IP addresses, traditionally in cleartext over UDP/53.
- **SNI** (Server Name Indication) is a TLS `ClientHello` extension that tells the server which hostname the client wants — sent **in the clear** in TLS 1.2 and earlier, and (without ECH) still visible in TLS 1.3.
- **TLS Handshake** — in TLS 1.3, the bulk of the handshake after `ClientHello`/`ServerHello` is encrypted, but the `ClientHello` itself (TLS version, cipher suites, extensions, SNI) remains observable and is the basis of **JA3/JA4 fingerprinting**.
- **QUIC** is a UDP-based transport that integrates TLS 1.3 directly into the transport handshake, reducing connection setup to effectively one round trip (0‑RTT resumption) and eliminating TCP head-of-line blocking.
- **HTTP/2** is a binary, multiplexed protocol that runs over TLS/TCP. **HTTP/3** is HTTP/2's semantics carried over QUIC instead of TCP+TLS.

Because TLS 1.3 and HTTP/3 encrypt almost everything *except* the early handshake metadata, DPI systems have been pushed toward analyzing **what's left exposed**: SNI (absent ECH), JA3/JA4 fingerprints, certificate metadata, and statistical/behavioral traffic patterns — which is precisely the shift that defines the rest of this document.

### 1.7 TCP vs. UDP

| | TCP | UDP |
|---|---|---|
| Connection model | Connection-oriented (3-way handshake: SYN, SYN/ACK, ACK) | Connectionless |
| Reliability | Built-in retransmission, ordering | None — left to the application |
| Censorship interaction | Vulnerable to **TCP RST injection** (a forged reset tears down the connection) | RST injection has no effect; censor must drop packets outright or block by signature |

### 1.8 Traffic Engineering & Fingerprinting

**Traffic Engineering** (MPLS‑TE, RSVP‑TE) lets large ISPs and CDNs steer flows along preferred paths to balance load and reduce latency — a purely operational concern, but one that increasingly co-exists with DPI deployments that classify "sensitive" flows for differentiated handling. **Fingerprinting** is the broader practice of identifying an application, OS, or protocol from observable network metadata: TLS cipher-suite ordering, TCP options/window-scaling behavior, packet-size distributions, and inter-packet timing can all reveal what software produced a flow — even when the payload itself is opaque ciphertext. This single idea — *metadata survives encryption* — is the foundation of nearly every detection technique discussed in Sections 6–8.

---

## 2. VPN Technologies – How They Work & How They Get Blocked

| Protocol | Transport / Port | Encryption | Key Exchange | DPI Detectability | Censorship Resistance |
|---|---|---|---|---|---|
| **PPTP** | TCP/1723 control + GRE (proto 47) | MPPE (RC4, ≤128-bit) | MS‑CHAPv2 | Trivial — GRE is unmistakable | Very low |
| **L2TP/IPsec** | UDP/1701 (L2TP) + UDP/500 (IKE) + ESP/AH | 3DES/AES via IPsec | IKE | High — distinctive IKE exchange | Low–Medium |
| **SSTP** | TLS 1.x over TCP/443 | TLS (cert-based) | RSA/DH via TLS | Low — looks like HTTPS | Medium–High |
| **OpenVPN** | UDP/1194 or TCP/443, TLS 1.2/1.3 | AES‑GCM/AES‑CBC | ECDHE/DHE via TLS | Medium-High via packet-size/handshake fingerprinting | Medium |
| **WireGuard** | UDP/51820 | ChaCha20‑Poly1305 | Noise Protocol Framework | Very high — fixed-format handshake bytes | Low |
| **SoftEther** | Multi-protocol (often HTTPS-mimicking) | TLS-based | TLS | Medium-High via unique TLS certificate fingerprint (JA4X) | Medium |
| **Outline** | Shadowsocks-based | AEAD ciphers | Pre-shared key | Medium via active probing (inherits Shadowsocks behavior) | Medium |

### PPTP
The oldest mainstream VPN protocol, tunneling PPP inside GRE. A TCP/1723 control channel negotiates the session, while user data crosses in **GRE protocol 47**, optionally protected by **MPPE** (commonly RC4‑128). Architecturally simple, but cryptographically broken — MPPE lacks integrity protection and PPTP carries multiple known vulnerabilities. Because GRE packets have a distinctive, fixed structure, **DPI identifies PPTP almost instantly**, and it is blocked outright in most heavily-filtered networks, including Iran and China.

### L2TP/IPsec
L2TP itself (UDP/1701) provides only point-to-point tunneling with **no encryption**; it is paired with IPsec for confidentiality. **IKE** (UDP/500) negotiates Security Associations, after which traffic flows through **ESP** (IP protocol 50) and/or **AH** (protocol 51), typically with AES or 3DES. The IKE exchange uses recognizable message types and ports, so DPI can fingerprint the protocol with moderate ease, even though the payload itself is properly encrypted.

### SSTP
Microsoft's VPN protocol tunnels PPP/IPsec traffic inside a standard **TLS 1.x session over TCP/443**. Because it rides on a genuine TLS handshake, distinguishing SSTP from ordinary HTTPS is hard unless the certificate or handshake metadata is anomalous — giving it comparatively strong censorship resistance, at the cost of being Windows-centric with a small open-source ecosystem.

### OpenVPN
One of the most widely deployed open-source VPNs, built on TLS 1.2/1.3 for both authentication and key exchange (ECDHE/DHE), with AES‑GCM (or CBC) for data encryption, over UDP/1194 or TCP/443. Its strengths — flexibility, strong security, broad platform support — are offset by a real fingerprinting weakness: independent research (e.g., the protocol-obfuscation study presented at **ACM CCS 2015**) has shown that OpenVPN's distinctive initial packet sizes and response patterns allow high-accuracy classification by passive traffic analysis, even when run over port 443.

### WireGuard
A modern, kernel-integrated, minimalist VPN using the **Noise Protocol Framework** for its handshake and **ChaCha20‑Poly1305** for data. Its first handshake message has a **fixed, easily-matched byte layout**: a 4‑byte message-type field followed by sender index, ephemeral public key, and — critically — fixed-position MAC fields. This rigid structure is exactly what makes WireGuard so easy to fingerprint at the byte level; censors that simply pattern-match the first bytes of UDP/51820 traffic can block it with very low false-positive rates. (This is precisely the gap that obfuscated forks such as **AmneziaWG** were created to close, by randomizing header fields that vanilla WireGuard leaves static.)

### SoftEther
A multi-protocol VPN suite ("VPN Gate") capable of tunneling over HTTPS or emulating OpenVPN/L2TP/SSTP. While its HTTPS-mimicry is generally convincing, research has found that SoftEther's TLS certificate-generation process produces a **distinctive JA4X (certificate) fingerprint**, giving advanced DPI a reliable hook for identification despite the protocol's HTTPS disguise.

### Outline
Jigsaw's user-friendly VPN framework is, under the hood, a **Shadowsocks** server with a simplified management layer (the Outline Manager). It inherits both the strengths and weaknesses of Shadowsocks: strong AEAD encryption defeats passive content inspection, but **active probing** — connecting to a suspected server and observing its response behavior — can reveal it, just as it can with vanilla Shadowsocks.

**Summary by transport class:**
- **TLS/TCP-based** (SSTP, OpenVPN-TCP, SoftEther) — defeated mainly through TLS/handshake fingerprinting unless wrapped in additional obfuscation (e.g., obfs4-style).
- **UDP-based** (WireGuard, OpenVPN-UDP) — defeated through fixed-byte handshake signatures.
- **Legacy** (PPTP, L2TP/IPsec) — defeated almost instantly due to distinctive GRE/ESP/IKE structure.

---

## 3. DNS & Encrypted Protocols

| Protocol | Port | What's Hidden | What's Still Visible | Censor Countermeasure |
|---|---|---|---|---|
| Traditional DNS | UDP/53 | Nothing | Full query in plaintext | Poisoning, hijacking, blocking |
| **DoT** (DNS-over-TLS) | TCP/853 | Query content | Port number + SNI of resolver | Block port 853 / SNI of known resolvers |
| **DoH** (DNS-over-HTTPS) | TCP/443 | Query content, blends with HTTPS | SNI of resolver (if not using ECH) | Block known DoH resolver SNIs/IPs |
| **DoQ** (DNS-over-QUIC) | UDP/853 (typ.) | Query content | QUIC handshake metadata | Block port / QUIC version fingerprint |
| **ECH** (Encrypted Client Hello) | n/a (TLS extension) | Inner SNI | Outer ("public name") SNI, ECH config fetch | Block the ECH bootstrap query itself |
| **SNI / legacy ESNI** | n/a (TLS extension) | — (plaintext by default) | Hostname in cleartext | Direct string match + RST |

DNS is the Internet's address book, and historically the easiest layer to censor: a censor sitting anywhere on the path can intercept a plaintext UDP/53 query and inject a forged response (**DNS poisoning/mangling**) or simply redirect resolution traffic to a state-controlled resolver (**DNS hijacking**). Encrypted DNS — DoT, DoH, DoQ — hides the *query content*, but each still leaks a metadata signal a censor can act on: DoT's fixed port (853), DoH's TLS SNI (unless paired with ECH), or QUIC's version/handshake bytes for DoQ.

**ECH** goes one step further by encrypting the *inner* ClientHello (including the real SNI) inside an *outer* ClientHello that exposes only a generic "public name." The catch: to use ECH, a client must first fetch an `ECHConfig` record via DNS — and if *that* bootstrap query itself travels over plaintext or easily-identified encrypted DNS, a censor can simply block the bootstrap and prevent ECH from ever activating. This is why several censoring states (China since 2020, and reportedly others) block ESNI/ECH traffic outright rather than try to inspect it — denying the capability is simpler than defeating it.

---

## 4. V2Ray / Xray Deep Architecture

### 4.1 Core Architecture

V2Ray (and its actively-developed fork, **Xray-core**) is built around a modular pipeline:

```
            ┌─────────────┐        ┌──────────┐        ┌──────────────┐
Client ───▶ │  Inbound(s) │ ─────▶ │ Routing  │ ─────▶ │  Outbound(s)  │ ───▶ Internet
            │ VMess/VLESS │        │  Rules   │        │ Direct/Proxy/ │
            │ Shadowsocks │        │ (domain, │        │ Blackhole/DNS │
            │ SOCKS/HTTP  │        │ IP, geo) │        │               │
            └─────────────┘        └──────────┘        └──────────────┘
```

A single instance can run **multiple Inbound protocols simultaneously** (e.g., VMess + Shadowsocks + SOCKS on different ports), and the **Routing** engine decides, per-connection, which Outbound a flow should take — based on destination domain, IP, GeoIP database, or custom rules. Each Inbound/Outbound independently configures its own **Transport** (TCP, WebSocket, gRPC, HTTPUpgrade, QUIC, mKCP) and **Security Layer** (none, TLS, XTLS, or Reality).

### 4.2 Proxy Protocols

| Protocol | Handshake | Auth Mechanism | Notable Structural Detail |
|---|---|---|---|
| **VMess** | None separate (data starts immediately) | AEAD header (AES‑128‑GCM) encoding a UUID + timestamp + CRC32 | Stateful timestamp field historically enabled **replay/timing-based fingerprinting** |
| **VLESS** | None separate | Raw UUID only, no timestamp/MD5 | Lighter, stateless, simpler than VMess — smaller fingerprint surface |
| **Trojan** | Standard TLS `ClientHello`/`ServerHello` | SHA‑224 password hash sent as the first "line" after TLS completes | Indistinguishable from ordinary HTTPS at the connection level |
| **Shadowsocks** | None (first packet is ciphertext) | Pre-shared key, AEAD | Legacy versions leaked an address-type byte before AEAD hardening |
| **SOCKS5** | Plaintext version/method negotiation | Optional plaintext or none | No encryption — trivially fingerprinted |
| **HTTP CONNECT** | Plaintext `CONNECT host:port HTTP/1.1` | None (unless wrapped in TLS) | The literal string `CONNECT` is a direct DPI signature |

**VMess vs. VLESS** is the clearest illustration of the project's own fingerprint-reduction evolution: VMess's AEAD header packs a UUID, timestamp, and CRC32 into an encrypted blob, but the timestamp dependency (and the deprecated legacy MD5 auth mode) created subtle timing and replay characteristics that traffic analysis could exploit. VLESS strips this down to a bare UUID validated inside the TLS channel, eliminating the timing dependency entirely and shrinking the protocol's distinguishing footprint to almost nothing beyond "a TLS connection exists."

**Trojan's defining property** is that it adds *no* extra protocol layer on top of TLS at all — after a completely standard TLS handshake, it sends one short, hash-authenticated line and then behaves exactly like a proxied HTTPS connection. This is why, protocol-for-protocol, Trojan is widely regarded as the hardest of this family for DPI to distinguish from ordinary web traffic — at the cost of needing a genuinely valid-looking TLS certificate and SNI to avoid certificate-based scrutiny.

### 4.3 Transports

| Transport | Layered On | Header Overhead | DPI Visibility |
|---|---|---|---|
| **TCP (raw)** | — | TCP header only | Full TCP metadata, plaintext unless TLS added |
| **WebSocket (WS)** | HTTP/1.1 Upgrade | 2–14 bytes/frame | HTTP Upgrade handshake is visible; subsequent frames blend with web traffic |
| **gRPC** | HTTP/2 | Protobuf framing | Looks like generic HTTP/2 traffic |
| **HTTPUpgrade** | HTTP/1.1 Upgrade (alt. to WS) | Similar to WS | Upgrade header visible during handshake |
| **QUIC** | UDP | QUIC header + TLS 1.3 | Fixed version bytes (`0x00000001`) at the start of the handshake are a known fingerprint |
| **mKCP** | UDP | Seq/Ack/Window fields | Custom UDP header structure is itself a recognizable signature |

### 4.4 Security Layer: TLS, XTLS, Reality & Vision

- **TLS** — the standard security layer; when combined with a Trojan-style or VLESS-over-TLS inbound, the wire pattern is a normal-looking TLS session.
- **XTLS** — Xray's optimized TLS variant that eliminates redundant double-encryption (data would otherwise be encrypted once by the proxy protocol and again by TLS); functionally it behaves like TLS at the handshake level but reduces CPU overhead and latency.
- **Vision** (an XTLS flow control mode) — shapes the outgoing data pattern (e.g., padding behavior) specifically to reduce statistically-distinguishable artifacts in the encrypted stream.
- **Reality** — perhaps the most significant recent development: instead of presenting *its own* TLS certificate, a Reality server **borrows the TLS handshake of a real, legitimate website** (the "camouflage" target) for unauthenticated clients, while authenticated clients are transparently routed to the proxy. Because the observable `ClientHello`/`ServerHello`/certificate exchange is byte-for-byte that of a genuine third-party site, traditional certificate- and SNI-based fingerprinting has nothing anomalous to key on. As of this writing, Reality remains substantially harder for deployed DPI systems to flag than VMess/VLESS/Trojan-over-self-signed-TLS, *provided* the camouflage handshake and timing remain consistent with the real site's behavior.

---

## 5. Tunnel Technologies & Encapsulation

| Tunnel Type | Carrier Protocol | What Gets Hidden | DPI's View |
|---|---|---|---|
| **SSH Tunnel** | TCP/22 | All forwarded application data | Encrypted SSH stream on port 22; content opaque |
| **TLS Tunnel** (e.g., Stunnel) | TCP/443 (TLS) | Any TCP service wrapped behind TLS | Standard `ClientHello`→`ApplicationData` pattern |
| **Reverse Tunnel** | Usually SSH | Lets a server behind NAT/firewall expose a port via an outbound-initiated connection | Same as SSH — visible only as an outbound SSH session |
| **WebSocket Tunnel** | HTTP/1.1 → WS frames | Arbitrary binary payload inside WS frames | HTTP Upgrade handshake, then opaque binary frames |
| **HTTP Tunnel** | HTTP `CONNECT`, or data in POST/GET bodies | Raw TCP stream (via CONNECT) or app data (via body) | The literal `CONNECT host:port` string, or recognizable HTTP request structure |
| **QUIC Tunnel** | UDP (QUIC) | Encrypted application stream | QUIC's own handshake bytes; encrypted payload otherwise |
| **UDP Tunnel** (e.g., GUE / RFC 8085) | Raw UDP | Arbitrary encapsulated protocol | A custom UDP header (flags, version, next-header field) is itself often a recognizable signature |

In every case the underlying principle is the same one introduced in Section 1.2: the *real* payload is wrapped inside a "carrier" protocol's own encapsulation, and the carrier protocol is chosen because it is common enough (TLS, HTTP, SSH) that a censor cannot block it wholesale without enormous collateral damage to legitimate traffic. DPI cannot read inside a properly-encrypted tunnel, but it can often **infer that a tunnel exists** from secondary signals: an SSH session on a network where SSH is rare, a TLS handshake on a non-standard port repeated with unusual regularity, or a WebSocket Upgrade to a server with no other web presence.

---

## 6. Deep Packet Inspection (DPI)

### 6.1 What DPI Is

DPI inspects packets beyond the basic header fields used for routing — up through the application layer where possible — searching for protocol signatures, embedded metadata, and known patterns. Engines such as **Suricata** and **Snort** implement this via rule sets that match strings, byte offsets, and protocol state machines. In large-scale deployments, DPI typically sits at network edges (Internet exchange points) and operates on **mirrored traffic** so that the heavy inspection workload doesn't add latency to the primary path.

### 6.2 Detection Methodologies

| Method | What It Looks At | Effective Against |
|---|---|---|
| **Flow Analysis** | Packet counts, timing, sizes over a session | Streaming/VoIP service identification |
| **Signature/Keyword Matching** | Known byte sequences, strings, protocol markers | Plaintext or weakly-obfuscated protocols |
| **Statistical Detection** | Distributions of packet size, entropy, inter-arrival time (often ML-assisted) | "Fully encrypted" protocols with no plaintext markers (Shadowsocks-style) |
| **Behavioral Detection** | Handshake sequence shape, response timing | TLS/SSH implementations, proxy software |
| **Active Probing** | Connecting to a suspected server and eliciting a response | Lightly-authenticated proxy protocols (Shadowsocks, naive proxies) |
| **Passive Monitoring** | Continuous background fingerprint comparison | TLS/SSH client identification at scale |

### 6.3 TLS & SSH Fingerprinting

- **JA3** hashes the ordered list of TLS version, cipher suites, extensions, elliptic curves, and curve point formats from a `ClientHello` into an MD5 digest — effectively a fingerprint of *which TLS library/configuration* produced the handshake.
- **JA4** is the evolved successor, adding parameters like ALPN and using a format more resistant to simple extension-order randomization.
- **JA4X** extends fingerprinting to **certificate structure** itself — this is the mechanism researchers used to identify SoftEther's distinctively-generated TLS certificates even when its traffic otherwise mimicked HTTPS.
- **HASSH** applies the same idea to SSH: hashing the client's offered key-exchange, cipher, MAC, and compression algorithms (SHA‑256) to fingerprint the SSH client implementation.

### 6.4 Protocol-by-Protocol Detectability

| Technology | Primary Detection Vector | Difficulty for DPI |
|---|---|---|
| OpenVPN | Packet-size/handshake statistical fingerprinting | Medium (research shows high-accuracy classification is achievable) |
| WireGuard | Fixed-byte handshake header (reserved bytes + MAC fields) | Low — easily signature-matched |
| SoftEther | JA4X certificate fingerprint | Medium |
| Shadowsocks / VMess / "fully encrypted" protocols | Statistical/entropy analysis distinguishing them from genuine TLS or random noise; active probing | Medium — modern research (USENIX Security 2023) demonstrates real-world detection of this protocol class |
| Trojan / VLESS+TLS / XTLS | None beyond standard TLS metadata — behaves like genuine HTTPS | High (i.e., hard to detect) |
| Reality | Camouflage handshake is byte-identical to a real site's TLS | Very high (i.e., very hard to detect), contingent on consistent camouflage behavior |

---

## 7. Internet Censorship Techniques

| Technique | Layer | Mechanism |
|---|---|---|
| **DNS Poisoning/Mangling** | DNS | Inject a forged response (often `NXDOMAIN` or a sinkhole IP) before the real answer arrives |
| **DNS Hijacking** | DNS / routing | Intercept queries en route (e.g., at the ISP) and answer with a controlled resolver |
| **IP Blocking** | Network | Drop all traffic to a specific destination IP |
| **ASN Blocking** | Network | Drop traffic to an entire Autonomous System's announced prefixes |
| **BGP Manipulation** | Network | Withdraw, alter, or insert route announcements to redirect or black-hole traffic |
| **SNI Filtering** | TLS | Read the plaintext SNI in `ClientHello`; if it matches a blocklist, terminate the connection |
| **TLS Filtering** | TLS | Inspect certificate fields (CN/SAN) or JA3/JA4 fingerprints |
| **TCP RST Injection** | Transport | Forge a TCP reset packet to both endpoints so each believes the other closed the connection |
| **Traffic Shaping / QoS Abuse** | Transport+ | Throttle bandwidth for flows matching a suspicious profile rather than blocking outright |
| **Active Probing** | Application | Connect to a suspected server as a fake client to confirm what it's running |
| **Packet Dropping/Shaping** | Network | Drop fragmented packets, reorder/delay traffic to disrupt protocol assumptions |

### The Censorship Pipeline

```
   Identify            Classify             Act
┌───────────┐      ┌──────────────┐    ┌─────────────────┐
│ Match IP/ │ ───▶ │ Determine    │ ──▶│ Block (RST/drop) │
│ port/SNI/ │      │ protocol /   │    │ Throttle (QoS)   │
│ signature │      │ service type │    │ Log / report     │
└───────────┘      └──────────────┘    └─────────────────┘
```

Censorship systems generally operate this three-stage pipeline: a flow is first **identified** (by address, port, or an early-packet signature), then **classified** against policy (is this HTTPS, DNS, VoIP, a VPN?), and finally acted on — most commonly via **TCP RST injection** for TCP flows (cheap, stateless, effective) or outright packet dropping for UDP flows (since RST has no meaning for UDP).

---

## 8. Technical Analysis of Internet Filtering in Iran

> *The following is a technical synthesis based on independent network-measurement research (notably the FOCI 2013 study "Internet Censorship in Iran: A First Look" by Aryan, Aryan & Halderman, and subsequent reporting by groups such as OONI, ASL19/Filterwatch, and Miaan Group) combined with general DPI/censorship engineering principles. It describes architecture and observed behavior at a conceptual level, not an operational targeting guide.*

### 8.1 Filtering Architecture

Iran's filtering model has historically operated as a **hybrid protocol-allowlist + DPI system**, rather than a pure blocklist. At the protocol-filtering layer, the network appears to permit a narrow set of recognized protocols — principally **DNS, HTTP, and HTTPS** — while traffic that does not conform to a recognized HTTP/TLS handshake pattern on a given port is dropped outright. In practice, this means a TCP/443 stream is expected to begin with a standards-conformant TLS `ClientHello`; a stream that doesn't (e.g., raw OpenVPN, unwrapped SSH, or vanilla WireGuard) is liable to be cut regardless of which port it uses.

### 8.2 Role of DPI

Above the protocol-allowlist layer, Iran has deployed **TLS-aware DPI** capable of inspecting handshake metadata in real time. This was documented concretely during the 2018 protests, when measurement researchers observed that connections were being terminated based on matching either the **SNI field** or the **certificate Common Name** against blocklisted services (Instagram being a widely-cited example) — wherever that name appeared in the handshake, the connection was torn down, typically via TCP RST.

### 8.3 Role of DNS Filtering

DNS has long been a primary lever: queries for blocked domains are commonly answered with `NXDOMAIN` or a sinkhole address rather than the real result. Encrypted DNS (DoT/DoH) can route around this at the *query* layer, but the protocol-allowlist layer described in 8.1 creates a secondary obstacle — non-standard or unrecognized ports/handshakes (including DoT's fixed port 853) can themselves be targeted independently of the DNS content.

### 8.4 Role of SNI Filtering

Consistent with the DPI behavior above, plaintext SNI matching against a blocklist remains a primary, low-cost filtering lever. Encrypted SNI mechanisms (ECH) are not yet in wide practical use in this context — partly because, as discussed in Section 3, ECH's own bootstrap (fetching `ECHConfig` via DNS) is itself interceptable, giving a censor an earlier point to intervene before ECH ever activates.

### 8.5 Role of Active Probing

While less formally documented than China's GFW probing infrastructure, anecdotal and field reports describe proxy/VPS IP addresses being tested and subsequently blocked shortly after activation — consistent with some form of active or semi-automated probing of suspected proxy endpoints, though this has not been comprehensively characterized in public research the way GFW probing has.

### 8.6 Role of Traffic Analysis

Beyond per-connection inspection, coarser network-level signals — such as a spike or drop in measurement-probe connectivity (e.g., RIPE Atlas probes going dark) during politically sensitive periods — are consistent with broader, possibly automated, anomaly-based intervention layered on top of the DPI/protocol-allowlist system, though the precise mechanisms are not fully public.

### 8.7 Role of IP Reputation

Iranian ISPs reportedly maintain blocklists informed by **IP/ASN reputation** — addresses associated with well-known VPN, proxy, Tor, or VPS providers (frequently hosted in countries commonly used for circumvention) can be pre-emptively blocked, sometimes before any circumvention service is even configured on them.

### 8.8 Detection Vectors by Circumvention Technology

| Technology | Primary Risk in This Environment | Why |
|---|---|---|
| Raw V2Ray/Xray without TLS, bare OpenVPN, vanilla WireGuard | **Blocked immediately by the protocol-allowlist layer** | Doesn't resemble a conformant TLS/HTTP handshake |
| OpenVPN over TCP/443, SSTP | **Possible**, but at risk from handshake/packet-size fingerprinting | Mimics TLS but has statistically distinguishable internal patterns |
| Trojan, VLESS/XTLS over genuine TLS | **Comparatively resilient** | Indistinguishable from ordinary HTTPS at the protocol level; risk shifts to certificate/SNI-level scrutiny |
| Reality | **Currently among the more resilient options** | Borrows a real site's TLS handshake, leaving DPI nothing anomalous in the visible exchange |
| Shadowsocks / Outline | **At risk from active probing and statistical detection** | Lacks a conventional handshake; entropy-based and probing-based detection methods (as documented in USENIX Security 2023 GFW research) generalize beyond China |
| WireGuard (unobfuscated) | **High risk** | Fixed-byte handshake header is a near-perfect signature match |

### 8.9 Summary

Iran's combination of (1) a default-deny protocol allowlist, (2) TLS-aware DPI capable of SNI/certificate inspection, and (3) IP-reputation blocking creates a layered system where **survival depends less on encryption strength and more on indistinguishability from ordinary, permitted traffic** — which is precisely the design philosophy behind Trojan, VLESS-over-TLS, and Reality, and precisely the weakness in protocols (WireGuard, raw OpenVPN, Shadowsocks) whose wire format diverges, even subtly, from genuine HTTP/TLS.

---

## 9. References

- RFC 791 (IP), RFC 793 (TCP), RFC 768 (UDP), RFC 8446 (TLS 1.3), RFC 9000/9001 (QUIC/QUIC-TLS), RFC 7540 (HTTP/2), RFC 9114 (HTTP/3), RFC 8484 (DoH), RFC 7858 (DoT), RFC 9250 (DoQ), RFC 8085 (UDP Usage Guidelines / GUE context)
- IETF Draft: TLS Encrypted Client Hello (ECH)
- Project Xray / V2Ray official documentation (Inbound/Outbound/Routing/StreamSettings, VMess, VLESS, XTLS, Reality)
- WireGuard whitepaper, Jason A. Donenfeld
- AmneziaWG project documentation (WireGuard handshake fingerprinting & obfuscation)
- Aryan, S., Aryan, H., Halderman, J.A. — *"Internet Censorship in Iran: A First Look,"* FOCI 2013
- Wang, L. et al. — *"Seeing through Network-Protocol Obfuscation,"* ACM CCS 2015
- *"How the Great Firewall of China Detects and Blocks Fully Encrypted Traffic,"* USENIX Security 2023 (GFW Report)
- *"Triplet Censors: Demystifying Great Firewall's Real Time Bypassing Capability,"* USENIX Security 2023
- JA3/JA4 fingerprinting methodology, Salesforce Engineering / FoxIO
- HASSH SSH fingerprinting methodology, Salesforce Engineering
- OONI (Open Observatory of Network Interference) measurement reports
- ASL19 / Filterwatch (Article19) — Iran network-filtering reporting
- Cloudflare Engineering Blog — TLS, QUIC, and ECH explainers

---

## 10. About the Author

**Iliya** is a 17-year-old independent security researcher focused on computer networking, applied cryptography, and Internet-censorship measurement. **V0IDNETWORK** is an ongoing, open research effort to document — rigorously and accurately — how the modern Internet's circumvention and surveillance technologies actually work at the protocol level, in support of a more open and resilient Internet.

Contributions, corrections, and citations to additional peer-reviewed research are welcome via pull request.

---

<p align="center"><sub>This repository is for research and education. It does not provide operational instructions for evading any specific deployed system.</sub></p>
