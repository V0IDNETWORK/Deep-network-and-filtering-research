# Deep-network-and-filtering-research

# Networking, VPN & Internet Censorship-Resistance Technologies

**A technical reference on network architecture, VPN protocols, encrypted DNS, the V2Ray/Xray ecosystem, tunneling, Deep Packet Inspection (DPI), and internet censorship mechanisms — including a technical case study of filtering in Iran.**

> 💡 *This document is a translated and reorganized version of a Persian-language technical write-up. Project name, author, and links are left as placeholders below — fill in your own.*

---

## 📖 Table of Contents

- [Networking Fundamentals](#networking-fundamentals)
- [VPN Technologies](#vpn-technologies)
- [DNS & Encryption](#dns--encryption)
- [V2Ray & Xray Architecture](#v2ray--xray-architecture)
- [Tunnel Technologies](#tunnel-technologies)
- [Deep Packet Inspection (DPI)](#deep-packet-inspection-dpi)
- [Internet Censorship & Filtering Techniques](#internet-censorship--filtering-techniques)
- [Case Study: Filtering in Iran](#case-study-filtering-in-iran)
- [References](#references)

---

## Networking Fundamentals

In the OSI reference model, data travels from the **application layer** (e.g., DNS, HTTP) down through the **transport layer** (UDP/TCP), the **network layer** (IP), the **data link layer** (Ethernet/Wi-Fi), and finally the **physical layer**. For example, an HTTP packet is first built at the application layer, encapsulated with a TCP or UDP header at the transport layer, addressed with IP at the network layer, framed (Ethernet or Wi-Fi) at the data link layer, and ultimately transmitted as an electrical or optical signal.

```
+--------------------------------------+
| Application Layer (HTTP, DNS, ...)   |
+--------------------------------------+
| Transport Layer (TCP/UDP)            |
+--------------------------------------+
| Network Layer (IP)                   |
+--------------------------------------+
| Data Link Layer (Frames)             |
+--------------------------------------+
| Physical Layer (Bits)                |
+--------------------------------------+
```

The TCP/IP model works similarly, with **Application**, **Transport**, **Internet** (≈ IP), and **Link** layers. The main difference from OSI is that the **Presentation** and **Session** layers are merged into the layers above in TCP/IP.

- **Packet** — the unit of data at the network layer (an IP packet).
- **Frame** — the unit of data at the data link layer (e.g., an Ethernet frame).
- **Routing** — routers forward packets between networks based on destination IP addresses.
- **Switching** — happens at the data link layer; switches move frames within a local network based on MAC addresses.

### NAT / CGNAT

**NAT** (Network Address Translation) operates at the network layer to let multiple private hosts share a single public IP address. **CGNAT** (Carrier-Grade NAT) is a large-scale version of NAT used by ISPs to share a limited pool of IPv4 addresses among thousands of subscribers. This involves rewriting the address and port in packet headers so return traffic is routed back to the correct host.

### BGP

**BGP** (Border Gateway Protocol) is the primary protocol for exchanging routing information between large networks (Autonomous Systems, or ASes). Each BGP router advertises the IP prefixes it can reach and the AS path to its neighbors. The BGP routing table selects the optimal path based on policy, path length, and other metrics.

### DNS

**DNS** translates human-readable names (e.g., `example.com`) into corresponding IP addresses. Modern networks increasingly use **encrypted DNS** variants:

| Variant | Transport | Port | Notes |
|---|---|---|---|
| Traditional DNS | UDP/TCP, plaintext | 53 | Queries visible to any observer |
| **DoT** (DNS-over-TLS) | TLS | 853 | Wraps queries in a TLS session |
| **DoH** (DNS-over-HTTPS) | HTTPS (HTTP/2 or HTTP/3) | 443 | Hidden inside normal HTTPS traffic |
| **DoQ** (DNS-over-QUIC) | QUIC | — | Runs over the QUIC protocol |

In addition, TLS 1.3 introduced **ECH** (Encrypted Client Hello), which encrypts almost the entire TLS ClientHello (except a small fixed portion). **SNI** (Server Name Indication), part of the ClientHello in TLS 1.3 and earlier, transmits the destination hostname in the clear. Earlier efforts — **ESNI** and later **ECH** — tried to close this leak. Without ECH, SNI travels as plaintext, letting corporate or state firewalls filter by domain.

### TLS

In TLS 1.2 and earlier, the ClientHello (including SNI) was sent in plaintext. In TLS 1.3, most of the handshake is encrypted, though a few early parameters (such as protocol version) remain inferable from visible data. A DPI appliance can analyze parameters like TLS version, the cipher suite list, and ClientHello formatting — known as **TLS fingerprinting** or **JA3** — to guess what software/system is in use. TLS runs over either TCP or QUIC (TLS 1.3 over QUIC). In TLS 1.3, a session resumption ticket is also exchanged, useful for quickly re-establishing a connection.

### HTTP/2 and HTTP/3

**HTTP/2** is a binary protocol over TLS/TCP that supports multiplexing and header compression. **HTTP/3** is effectively HTTP/2 over QUIC, benefiting from QUIC features like 0-RTT and faster connection setup. In HTTP/3, the entire handshake is encrypted, but SNI can still leak unless ECH is used. Because headers are encrypted, DPI systems can no longer see content or URLs directly — only early fields like SNI or traffic patterns (packet size, packet count) remain visible.

### TCP and UDP

**TCP** establishes connections with a three-way handshake (SYN, SYN/ACK, ACK) and guarantees delivery via retransmission. **UDP** is connectionless and has no built-in error control — each packet is sent independently, and ordering/delivery guarantees are left to the application layer. TCP flows can be monitored and blocked by DPI via **TCP RST** injection, but UDP is immune to RST (unless the UDP packets themselves are blocked).

### Traffic Engineering

Large networks use Traffic Engineering (TE) techniques — such as **MPLS-TE** and **RSVP-TE** — to route traffic along preferred paths and balance network load. ISPs and CDNs optimize traffic paths to reduce latency and congestion. Modern DPI systems are sometimes deployed alongside TE systems to control sensitive traffic without saturating the link.

### Fingerprinting

Traffic can be identified through patterns at multiple layers. For instance, the combination of TLS version and cipher suite in a handshake can reveal the application or operating system in use. Statistical and behavioral detection algorithms based on traffic volume, timing patterns, and packet direction offer another way to track services. At the IP/TCP layer, packet type (UDP vs. TCP), unusual ports, or fixed header fields can also serve as fingerprints — for example, Wireshark can distinguish operating systems by analyzing the sequence of non-decrypted TCP handshakes. These techniques form the foundation of DPI's ability to "fingerprint" protocols or applications and, if needed, block or throttle them.

---

## VPN Technologies

### PPTP
An old VPN protocol using PPP and **GRE tunneling** (IP protocol 47). After a TCP control connection on port 1723, user traffic flows through the GRE tunnel, protected by MPPE encryption (typically RC4-128). Simple architecture but weak security (MPPE is not trusted and has multiple known vulnerabilities). DPI easily identifies PPTP because GRE packets are distinctive and hard to disguise. PPTP has poor resistance to filtering and is routinely blocked in many regions, including China and Iran.

### L2TP/IPsec
L2TP alone only provides a point-to-point connection over UDP (port 1701) and is typically combined with IPsec for encryption. The architecture usually uses **IKE** (UDP port 500) for key exchange, followed by Security Associations (SAs) for **ESP** (IP protocol 50) and **AH** (IP protocol 51). Strong encryption (AES, 3DES) is used. DPI can detect L2TP/IPsec by observing IKE packets (known port exchanges and message types). Resistance to filtering is moderate — traffic is encrypted, but the specific protocols and ports are identifiable. Active attacks or misconfiguration can lead to detection.

### SSTP
Microsoft's VPN protocol, which uses TLS 1.x over TCP/443 for tunneling. After the TCP/TLS handshake, PPP/PPPoE or tunneled IPSec traffic flows inside TLS. SSTP benefits from running over the standard HTTPS port. Encryption and key exchange follow standard TLS (X.509/DH/RSA certificates). Its major advantage is the ability to traverse port-restrictive firewalls (since it resembles HTTPS). Downsides: Windows-only, limited adoption in the open-source community. DPI struggles to distinguish SSTP from genuine HTTPS (similar to Trojan), unless the certificate or headers look unusual. As a result, it has good resistance to filtering (in practice, censors often leave SSTP traffic alone as ordinary HTTPS).

### OpenVPN
One of the most popular open-source VPNs. Typically built on TLS (1.2 or 1.3), using UDP or TCP (default ports 1194/UDP or 443/TCP). Keys are exchanged via ECDHE/DHE TLS, and data is encrypted with AES-GCM (or CBC/BF). Setup involves an initial TLS handshake plus certificate-based key exchange. **Pros:** strong security (configuration-dependent), flexible configuration, large community, cross-platform support. **Cons:** TLS overhead and certificate management. DPI commonly identifies OpenVPN: researchers have shown that initial packet patterns and response sizes can be used to fingerprint the protocol (a USENIX study found over 85% detection accuracy by analyzing such patterns). Because TLS headers and maximum packet length follow a specific pattern, DPI can also recognize OpenVPN's opcode patterns. Due to its use of TLS and ability to run on port 443, OpenVPN's resistance to filtering is moderate: it fares better behind additional obfuscation (e.g., proxying behind HTTPS), but can be blocked under normal conditions.

### WireGuard
A modern, lightweight, kernel-based VPN (default port 51820/UDP). Its architecture uses public/private key pairs based on the **Noise Protocol** handshake. The first handshake message includes a fixed 4-byte value and two 16-byte MAC fields (MAC1, MAC2), which are initially zero. **Pros:** simple, fast, modern cryptography (ChaCha20+Poly1305), public-key authentication, low latency. **Cons:** UDP-only, NAT traversal requires extra work, no built-in DNS service. DPI can easily identify WireGuard: every WireGuard handshake is a UDP packet with 3 reserved zero bytes and two zeroed MAC fields at the start — this unique pattern makes detection straightforward for DPI equipment. Resistance to filtering is **weak**: without additional obfuscation, filters can easily block WireGuard by recognizing its distinctive byte patterns.

### SoftEther
A multi-protocol VPN suite (known as "VPN Gate") that can substitute for various other protocols. It can tunnel traffic as HTTPS or provide traditional VPN protocols. **Pros:** highly versatile (supports L2TP/IPsec, OpenVPN, SSTP, etc.), user-friendly GUI, open source, capable. **Cons:** largely identifiable via TLS fingerprinting. While it's hard to distinguish SoftEther traffic from HTTPS at a glance, recent research shows SoftEther's certificate-generation method produces a unique **JA4X** fingerprint that can expose it. Advanced DPI systems can use this specific fingerprint to detect and block SoftEther traffic.

### Outline
A VPN framework by Jigsaw that uses the **Shadowsocks** protocol under the hood. Its architecture is simple: a Shadowsocks server plus the Outline Manager for configuration. Encryption and keying work the same as Shadowsocks. **Pros:** easy setup for everyday users, open source. **Cons:** inherits all of Shadowsocks's weaknesses. DPI can detect Outline the same way it detects Shadowsocks. China's Great Firewall (GFW) has reportedly tested both Shadowsocks and Outline together (since they share a similar protocol). Outline's resistance to filtering mirrors Shadowsocks's: if active probing against Shadowsocks works, Outline is equally at risk.

*(OpenConnect, Cisco's proprietary protocol, is mentioned only briefly: active probing against it has not been observed in Iran, so it's outside the main scope here.)*

### Summary

| Category | Examples | Detection Method | Filtering Resistance |
|---|---|---|---|
| TLS/TCP-based VPNs | OpenVPN, SSTP, SoftEther | DPI via TLS handshake/pattern analysis | Moderate — survives unless obfuscated (e.g., obfsproxy) |
| UDP-based VPNs | WireGuard, OpenVPN (UDP) | Fixed byte patterns in handshake messages (e.g., WireGuard's 59-byte ClientHello-equivalent) | Weak by default |
| Legacy VPNs | PPTP, L2TP | Distinctive GRE/ESP protocols | Very weak — typically blocked outright |

In short: PPTP and L2TP, relying on old standards, are almost always blocked. TCP-based OpenVPN and SSTP run over port 443 and often pass through if their TLS traffic looks normal, but deep filters may still detect and close specific packet patterns. WireGuard and newer UDP protocols are inherently weak unless extra protections (like simplified UDP wrapping or traffic obfuscation) are applied.

---

## DNS & Encryption

### Traditional DNS
DNS requests are typically sent over UDP/53, with the query name in plaintext. Censors can drop these packets, return forged responses (cache poisoning), or alter resolver routes. Techniques like **DNS poisoning** (rewriting the response) or **DNS hijacking** (redirecting to a fake server) are used to return incorrect answers for blocked domains.

### DoT (DNS-over-TLS)
DNS queries are sent inside a TLS session, typically on TCP/853. Encryption wraps the traditional UDP query. DPI can detect this by observing port 853 or the SNI at the start of the TLS handshake (often a fixed domain like `dns.cloudflare.com`). If SNI isn't encrypted, a filter can block the DNS service name. On regular HTTPS, this is harder to block without collateral damage.

### DoH (DNS-over-HTTPS)
DNS queries are sent as HTTPS requests (HTTP/2 or HTTP/3) over port 443. Content is encrypted, and even SNI may not look like a typical DNS hostname. In practice, DoH usually points to a specific service (e.g., Google's `dns.google` or Cloudflare). Because all traffic rides on port 443, DPI struggles unless it recognizes the SNI/hidden URL. If providers use a default DNS SNI (e.g., `mozilla.cloudflare-dns.com`), censors can block it; using an unusual domain or ECH makes detection harder. One challenge: browsers usually need an initial, unencrypted DNS query to locate the resolver before starting DoH — and that initial query can itself be blocked.

### DoQ (DNS-over-QUIC)
Similar to DoH but over QUIC. Since QUIC encrypts its own handshake (instead of relying on TLS over TCP), DoQ traffic initially resembles HTTP/3 over UDP. Still, port 853 (QUIC variant of DoT) or QUIC-specific handshake patterns can be used for detection.

### ECH (Encrypted Client Hello)
A technique to encrypt the TLS ClientHello (including SNI). To start an ECH connection, the client needs an ECH config from DNS (e.g., a domain like `alpn-ech.cloudflare.com`) indicating the server supports ECH. If DNS is blocked, ECH fails. Research (PETS) shows that establishing ECH requires the client to use encrypted DNS (DoQ/DoT/DoH) to fetch the ECH config — DoQ/DoT are identifiable via port 853, but DoH on port 443 looks like ordinary traffic. Also, in HTTP/2 over TCP/TLS, the SNI in ClientHello is usually sent in plaintext. Before ECH, **ESNI** attempted to encrypt only the SNI field, but China began blocking ESNI outright in 2020 (regardless of the actual domain).

### How Censors Block DNS
Censorship systems restrict DNS through several methods: manipulating or poisoning DNS traffic at the network layer, or blocking routes at the IP layer so DNS packets never reach their destination. ASNs or IP blocks belonging to public DNS providers (like Google or Cloudflare) may be blocked entirely. In addition, enabling DPI on TLS traffic lets censors inspect SNI and even some hidden TLS metadata to block suspicious connections. Finally, widespread use of older techniques like TCP-reset or HTTP-to-DNS blocking can prevent access to resolvers altogether.

---

## V2Ray & Xray Architecture

### Overall Architecture
The V2Ray platform (and its more advanced fork, Xray) uses a modular architecture: multiple **inbound** protocols can run simultaneously (e.g., a single server accepting VMess, Shadowsocks, and SOCKS at once), each over one or more transport layers (TCP, UDP, QUIC, WS, gRPC, etc.). A **routing** component then decides how inbound traffic is directed to **outbounds** (e.g., based on domain, destination IP, geographic location, or user-defined rules).

In general, V2Ray has three core building blocks:
- **Inbounds** — proxies that receive traffic.
- **Outbounds** — where traffic is sent onward to the network.
- **Routing** — connects inbounds to the appropriate outbounds.

Each component is independently configurable. A single V2Ray process can run multiple inbound/outbound protocols simultaneously and route traffic based on configuration (e.g., split by region or domain). V2Ray nodes can also disguise their traffic to resemble ordinary HTTPS websites.

Below the core protocol layer (sometimes called the **Security Layer** or **TLS Layer**), either standard TLS or **XTLS** can be used (XTLS merges multiple encryption layers to reduce overhead). The **Transport Layer** can be raw TCP, WebSocket (sending packets in HTTP frames), gRPC (built on HTTP/2), HTTP/2 Upgrade, KCP (a UDP variant with error control), or QUIC. **Stream Settings** — such as allowing compressed datagrams, secondary encryption, or multiplexing — are also configurable.

### Key Configuration Components

- **Inbound** — the entry point for traffic, e.g., a TCP port for VMess with TLS.
- **Outbound** — where traffic is sent onward, e.g., directly (`Direct`), to a `DNS`/`Blackhole` outbound, or to another server (via Trojan/VLESS/VMess, etc.).
- **Routing** — rules for directing traffic from various inbounds to the appropriate outbounds, based on IP, domain, GeoIP, or other filters.
- **Stream Settings** — how data is packaged at each transport layer (e.g., enabling TLS, KeepAlive, or XTLS).
- **Transport Layer** — the actual transport protocol (TCP, UDP/KCP, QUIC, WS, gRPC, HTTPUpgrade).
- **Security Layer** — usually TLS or XTLS for connection-layer encryption. XTLS is Xray's replacement for standard TLS, offering optimizations like **Splice** (avoiding double encryption).

### Emerging Technologies

- **Reality** — uses next-generation cryptography combined with a QUIC-like profile resembling TLS/SPDY handshakes to conceal the proxy. The domain is not exposed via SNI but sent as an encrypted public address. This is a very new technique and, as of now, mostly undetected by DPI systems — provided the handshake and real SNI stay hidden.
- **XTLS (Vision/Flow)** — a flow mode of XTLS designed to mask traffic patterns, applying minimal padding so it's harder to fingerprint.
- **Padding/obfuscation after handshake** — additional techniques designed to hide the proxy's fingerprint and make traffic classification harder.

### Key Protocols

**VMess**
The original, older V2Ray protocol, running over TCP. Its routing relies on **AuthID**, an encrypted user-identification code containing the user's UUID, a timestamp, and a CRC32. Other fields in the Client Request include an encrypted header length, a random Nonce, and the data itself. VMess has two authentication modes: a newer **AEAD** mode (using AES-128-GCM for header integrity) and an older, now-deprecated **MD5+AES-128** mode. VMess's strength lies in its encrypted, stateless structure: servers verify the user's identity upon receiving a request and forward it once authenticated. Its weakness is that, being complex and distinctive, its traffic fingerprint can be recognized by DPI (e.g., specific lengths in the initial packets). Additionally, the older MD5-based time dependency can be vulnerable to timing attacks — a problem VLESS doesn't have.

**VLESS**
A newer, lighter version of VMess. Its documentation describes VLESS as "stateless, lightweight, and independent of system time," authenticating with a fixed UUID. Unlike VMess, there's no CRC, timestamp, or MD5 involved — only the raw user UUID (inside the TLS session) is used for authentication. This simplicity reduces both implementation complexity and fingerprintability. VMess and VLESS are technically similar; the main differences are the removal of timestamps and the authentication method. Since VLESS typically runs over TLS (e.g., XTLS or plain TLS), its handshake looks like ordinary TLS. In short: VLESS has a simpler packet structure and a shorter handshake than VMess.

**Shadowsocks**
A lightweight, encryption-based proxy protocol. Its architecture is simply a server and client with no defined handshake; the client sends the first packet to the server already encrypted, after establishing TCP or UDP. In older versions, the first packet included 1 byte for address type (IPv4/domain/IPv6), the destination address, and a 2-byte port. This minimal handshake allowed firewalls to use active probing: an attacker could open 256 connections with different first bytes, and observe that a server waits for valid values (e.g., 1 or 3) in the first byte while terminating others — revealing a Shadowsocks server. Modern versions, using AEAD encryption, neutralize this specific attack (unless the key is guessed). Shadowsocks is generally known for traffic that resembles strong random data, but advanced DPI combined with active probing (e.g., injecting arbitrary content and observing a large encrypted response) can still detect it. Its resistance to filtering is moderate: if it responds to unsolicited packets with large encrypted replies, that pattern signals a Shadowsocks server.

**SOCKS**
A standard, unencrypted proxy protocol that lets clients forward ports. It's very easy to identify due to its fixed format (e.g., version byte 5 followed by a `CONNECT` request). With no encryption, it offers no inherent censorship resistance and is blocked by DPI based on content rules (if the destination DNS or IP is flagged).

**HTTP Proxy (CONNECT)**
A protocol letting a client send a `CONNECT` request to an HTTP server to open a simple TCP tunnel. The request looks like `CONNECT domain:port HTTP/1.1`, which is clearly identifiable. Since it's plaintext, DPI can easily find and block or restrict this string (unless TLS is layered on top). If run over TLS (HTTPS), it appears as ordinary HTTPS, and only TLS packets are visible.

### V2Ray/Xray Transports

- **TCP** — the most common transport. If TLS is layered on top, it resembles HTTPS traffic. TCP packets have a length header, sequence number, SYN/ACK flags, etc. DPI can easily inspect the header and either plaintext content or TLS metadata (like SNI).
- **WS (WebSocket)** — a layer on top of HTTP; after an `Upgrade` request, a bidirectional, "framed" connection is established. Each WS frame has a 2–14 byte header followed by binary data. Since it starts over HTTP/1.1 on port 80/443, it can disguise itself as web traffic. Downsides: sequential headers are recognizable, and HTTP setup is required.
- **gRPC** — built on HTTP/2, sending data in protobuf frames. When used (in newer V2Ray builds), it closely resembles HTTP/2, and DPI may classify it similarly to WS or HTTP/2.
- **HTTPUpgrade (HTTP/2 Upgrade)** — behaves like WS but uses HTTP/1.1's `Upgrade` feature to switch to H2 and binary-encode traffic. DPI can spot the `Upgrade` field or infer the use from HTTP/2 content.
- **QUIC** — a transport layer riding on UDP. All handshakes are encrypted (using TLS 1.3) and use a Connection ID for routing, which may change during a session. DPI typically detects QUIC by inspecting the version field at the start of the UDP payload; since QUIC's handshake always starts with specific bytes (`0x00 0x00 0x00 0x01` for version 1), it's relatively easy to recognize.
- **KCP** — a fast UDP-based implementation with lightweight error control, including fields like Seq, Ack, and Window in its header. DPI can detect KCP packets based on this distinctive header structure (UDP/IP with specific data patterns).

### Per-Protocol Characteristics

| Aspect | Example |
|---|---|
| **Packet structure** | VMess: AEAD, 16-byte initial body, 18-byte AuthID, length field, 8-byte nonce. Shadowsocks: simple SOCKS-style header. Trojan: a single SHA224 hash line sent after a standard TLS handshake. |
| **Handshake** | VMess: no separate handshake. VLESS: only sends a UUID. Shadowsocks: no complex handshake (just ChaCha/AES encryption over TCP). Trojan: an ordinary TLS handshake (ClientHello/X25519/certificate), followed by addressing. |
| **Network fingerprint** | Protocols resembling HTTPS (Trojan over TLS, TLS-wrapped V2Ray) have little to no distinct fingerprint. Protocols with fixed headers or lengths (VMess, WireGuard without TLS) have a clear fingerprint. |
| **Traffic pattern** | Shadowsocks usually shows a high-entropy, random-looking data stream that DPI can flag due to lack of recognizable structure. Trojan and all TLS-based protocols resemble ordinary web traffic (a ClientHello packet followed by ACKs). |
| **Weaknesses** | Trojan/VLESS/VMess require careful key/UUID management — any leak is a risk. Older Shadowsocks was vulnerable to active probing (fixed by AEAD). WireGuard's lack of TLS makes it easy to identify. |
| **Strengths** | All these protocols are designed to evade filtering: Trojan via full HTTPS disguise, VMess/VLESS via strong encryption, Shadowsocks via simplicity and performance. However, if one protocol is detected, the rest of the filtering pipeline may simply block it outright (e.g., Iranian filtering generally only allows plain TLS through). |

---

## Tunnel Technologies

In tunneling, traffic from one protocol or path is encapsulated within a different layer. Examples include:

**SSH Tunnel** — uses SSH (TCP/22) to create a secure tunnel. A user might establish local port forwarding or a dynamic SOCKS proxy. All data is wrapped inside encrypted SSH packets (using algorithms like AES). After user authentication, requests can be relayed through SSH to another destination (acting as a proxy). An SSH packet structure includes fields such as size, packet type (data/keep-alive), and encrypted payload. DPI typically cannot read SSH content — it can only see a TCP connection on port 22. **Resistance:** appears as secure TCP traffic, so it usually evades blocking unless port 22 itself is blocked.

**TLS Tunnel (e.g., Stunnel)** — works like an SSH tunnel but uses SSL/TLS instead of SSH. A Stunnel service on the server side might accept data over TLS on port 443 and forward it to another TCP destination. This produces standard TLS packets (encrypted ClientHello, ServerHello, Application Data). This tunnel looks like ordinary HTTPS; DPI cannot see the data, only the TLS header (SNI, certificate).

**Reverse Tunnel** — typically means the server and client swap roles; for example, an SSH server with reverse port forwarding lets the client relay inbound connections arriving at the server to a port on the client. In other words, a user behind NAT or a firewall can expose internal services this way. The packet structure here mirrors regular SSH (since it uses SSH).

**WebSocket Tunnel** — sends ordinary data inside WebSocket frames. For example, a tool like `tunnel-ws` lets a user forward a local port to a WebSocket server on the internet. It begins with an HTTP `Upgrade` request to establish the WebSocket, after which data is sent as binary WebSocket frames. Each WS frame has a few header bytes (MASK, length, etc.). DPI may notice the initial HTTP handshake and distinctive WebSocket headers, but if port 443/TCP is open, this technique can disguise traffic as ordinary web traffic.

**HTTP Tunnel** — has two common meanings. One is the `CONNECT` method in an HTTP proxy: the client sends a `CONNECT` request to open a direct TCP tunnel to another address (the most basic form of an HTTP proxy). After `CONNECT`, the user's TCP data passes through the HTTP layer. DPI inspects the plaintext `CONNECT host:port HTTP/1.1` line to detect this. The other approach embeds data inside an HTTP `POST` or `GET` payload — e.g., an HTTP tunnel that sends data in a POST body (used by some older tools). This also has ordinary HTTP headers and a URL path that's easily identifiable.

**QUIC Tunnel** — transmits data via QUIC as a tunneling layer, such as QUIC-over-WireGuard or Google's QuicTransport. UDP packets resembling QUIC (including 3 reserved bytes and a Connection ID) are used. Because QUIC supports TLS 1.3, the ClientHello is also encrypted. DPI must look for QUIC/UDP signatures to detect it; however, since QUIC is still relatively uncommon in many countries, it may be flagged and blocked outright.

**UDP Tunnel** — examples include GUE (Generic UDP Encapsulation, RFC 8085) or simpler GRE/UDP tunnels. UDP packets are sent with special headers (e.g., a tunneled-protocol header and a Next-Header type field). DPI typically drops or flags unusual UDP packets; for instance, GUE has Flags, Version, and Next-Header fields that, if recognized by a firewall, can be used to block the flow.

In all these methods, inbound traffic is encrypted and carried by the secure tunnel protocol, then encapsulated at a lower layer (TCP or UDP). In other words, the real content is wrapped inside secure packets (QUIC/TLS/SSH) and sent over a public channel (the internet). Because of this layered security, DPI cannot read the actual content — but it may still infer that a tunnel exists by observing headers and patterns (e.g., TLS on unusual ports, or a TCP/22 connection on a network where SSH usage isn't typical).

---

## Deep Packet Inspection (DPI)

### What DPI Is and How It Works
DPI opens every packet or network flow up to the application layer to examine its content (addresses, ports, protocols, and even payload). DPI uses inspection engines (such as Suricata/Snort rules) to look for specific patterns — text strings, protocol metadata, SSH/TLS fingerprints. Based on what it finds, it decides whether to pass or block the packet. As Wikipedia describes it, DPI "inspects in detail all or part of a packet (e.g., a web page or a VoIP conversation) and may take actions such as alerting, blocking, rerouting, or logging information" once a pattern is detected. On the internet backbone, DPI is typically deployed at network edges (Internet Exchange points), using traffic mirroring (splitters) so that heavy computational inspection doesn't slow down the main link.

### General Detection Approaches

- **Flow Analysis** — analyzing overall packet flow (count, timing, length). For example, video streaming services have distinct packet patterns that DPI can use to identify the service type.
- **Signature Matching (Keyword/Content)** — finding known patterns in data (signatures or keywords). Useful for plaintext protocols, but largely ineffective against encrypted data.
- **Statistical Detection** — statistical methods (e.g., machine-learning classification) that try to determine the protocol/service based on statistical features (such as packet-size distribution).
- **Behavioral Detection** — detection based on client/server behavior (e.g., the sequence of handshake steps in TLS or SSH). The combination of version and cipher suites in a ClientHello can be interpreted as a fingerprint (JA3/JA4 for TLS, HASSH for SSH).

### TLS Fingerprinting (JA3/JA4)
**JA3** generates an MD5 hash based on the list of cipher suites, extensions, elliptic curves, and point formats in a ClientHello. **JA4** is a more advanced version that also includes newer parameters like ALPN and is resistant to extension reordering. DPI engines like nDPI also incorporate the TLS certificate's SHA-1 key (or JA3S) into their fingerprint database. Even **JA4X**, used in detecting SoftEther/Xray, leverages certificate information (since SoftEther's unique certificate-generation method creates a recognizable fingerprint). In short: advanced DPI hashes the TLS handshake and compares it against a signature database.

### SSH Fingerprinting (HASSH)
Similar to JA3, but for SSH. At the start of an SSH connection, the client sends a list of supported algorithms (cipher, KEX, compression, MAC). HASSH computes a SHA-256 hash of this list, which can identify the SSH client software. DPI or IDS systems can use HASSH to distinguish between different SSH clients.

### Active Probing
Some censors don't rely solely on passive monitoring — they actively connect to suspicious addresses to test the protocol's response. For example, China has been known to identify a candidate Shadowsocks server, then send test packets (a copied "first packet" or random data) and observe the response (a large amount of returned ciphertext signals Shadowsocks). DPI systems or firewalls may perform this to confirm that a banned service is actually running at that IP. This technique is effective against proxies like Shadowsocks or V2Ray that have simple handshakes.

### Passive Monitoring
In the typical case, DPI simply observes traffic and makes decisions based on signatures or statistics. An advanced DPI system might use TLS certificate fields, JA3/JA4, the SNI field, or even HTTP headers to identify a connection.

### How DPI Detects Specific Protocols

- **VPNs in general** — Modern DPI can detect most VPNs. Researchers have found that OpenVPN's specific patterns (packet order and sizes) allow over 85% detection accuracy. SSTP and SoftEther mimic HTTPS traffic, but SoftEther carries a fingerprint due to its certificate structure (a unique JA4X). WireGuard typically has distinctive starting bytes (three zero bytes + a 32-byte MAC) that are easily recognized.
- **Shadowsocks/Trojan/VLESS/VMess/V2Ray** — As noted, several of these run over TLS or HTTP. Protocols like Trojan, which exactly mimic HTTPS, are hard for DPI to distinguish (they look like a secure website). However, research shows that even Trojan/VLESS/Shadowsocks/VMess are often detectable: their TLS flows frequently carry a statistical fingerprint. A 2024 USENIX paper found that more than 70% of Trojan, VLESS, Shadowsocks, and VMess flows could be detected by inspecting the TLS handshake.
- **Shadowsocks** — DPI usually cannot detect it directly (since the data is fully encrypted), but combining content detection with active probing can locate it. China's GFW uses active probing specifically against Shadowsocks.
- **Trojan** — Since Trojan is effectively HTTPS (a standard TLS ClientHello followed by a short encrypted line), ordinary DPI sees nothing but normal web traffic. If TLS 1.2 or 1.3 is used, the SNI, certificate, and other parameters look like an ordinary site. The only realistic detection approach is finding very subtle differences in the certificate (e.g., issuing authority or validity period), but this attack is quite difficult in practice. Technically, Trojan adds no extra layer beyond TLS itself (unlike VMess, which adds an independent cipher), making it nearly invisible to DPI — an excellent advantage against filtering.
- **WireGuard** — as noted, identifiable by its fixed binary pattern.
- **SoftEther** — despite claims of resistance, DPI can identify it via its JA4X fingerprint.
- **General TLS Fingerprinting** — DPI can use JA3/JA4 to identify a tool's overall TLS profile, and sometimes even the specific service (e.g., Cloudflare's "JA3+" feature can identify client type). DPI can also classify TLS traffic based on handshake timing or message length.

---

## Internet Censorship & Filtering Techniques

The main mechanisms of internet censorship and filtering include:

**DNS Poisoning (including DNS Mangling)** — Censors gain access to DNS responses and substitute forged values. For example, in China, every DNS request passing through a firewall is inspected; if the domain is banned, the firewall immediately returns a fake response (often pointing to a meaningless IP). This is called "DNS mangling." Alternatively, censors use **cache poisoning**: intercepting the DNS response path and substituting the legitimate server's answer with a worse one (NXDOMAIN or a wrong IP). In effect, banned domain names are never resolved to their real IP, so even a successful TCP connection on another port would yield the same failure.

**DNS Hijacking** — Similar to poisoning, but occurring at ISP equipment or transit nodes. When a user tries querying any global DNS server, the censor intercepts the request (e.g., via routing) and returns a forged response. In Iran, ISPs have at times been required to change DNS settings under government directive.

**IP Blocking** — Blocking the IP addresses of servers. If a filter (e.g., an ISP or router) blocks a destination IP, no packets reach it. This can target a single IP, an IP range, or an entire operator's ASN (**ASN blocking**). China and Iran sometimes block CDN IPs belonging to banned services entirely — effective, but it can also impact legitimate sites sharing the same infrastructure.

**BGP Manipulation** — Altering BGP routes to prevent traffic from reaching outside networks, or to introduce a fake route. A censor could define a false route to a destination that's blocked in a particular region, or inject an unauthorized BGP announcement pointing to internal resources. This is rarely used for general censorship but can cause international disruption or partial circumvention of privacy.

**SNI Filtering** — Inspecting the domain name in the TLS SNI header and blocking the connection if it matches a blacklist. For example, Chinese and Iranian authorities read SNI headers containing `facebook.com` or other banned site names and terminate the TLS connection with a TCP RST. SNI's transparency makes it one of the primary tools for DPI-based HTTPS filtering. After ECH's introduction, detection became harder, but some countries simply block ECH/ESNI traffic outright (out of concern over domain concealment). **Domain fronting** (presenting a different SNI than the actual HTTP Host header) was previously used to evade SNI filtering, but large service providers have mostly blocked this or stopped supporting it.

**TLS Filtering** — Inspecting the server's certificate and handshake can also be used for filtering. Some DPI systems filter based on certificate fields (CN or SAN) or issuing authority. For example, some ISPs (e.g., in India) have historically used certificate-embedded information for blocking. TLS 1.3 has narrowed this avenue somewhat. JA3/JA4 TLS fingerprinting also falls into this category, helping identify specific software.

**TCP Reset (RST) Injection** — Injecting forged TCP RST packets to disrupt a TCP connection. The filter intercepts the TCP stream and sends a fake RST to both client and server so each believes the other has closed the connection. This is widely used in Iran, China, and elsewhere — for instance, China's GFW extensively uses RST injection against Tor or VoIP traffic. The advantage of RST injection is its high efficiency and out-of-band operation (it doesn't require much state-keeping). Its drawback is the need to guess the correct sequence number (to fool the recipient), but this is usually feasible alongside basic DPI.

**Traffic Shaping / Throttling** — Reducing speed or allocating less bandwidth to certain traffic. A simple approach: when DPI flags a connection as sensitive, it's heavily throttled (**QoS abuse**). For example, TLS/SSL connections with suspicious patterns might be deprioritized so the user rarely manages to communicate. This is an indirect technique (not a full block, but the service becomes practically unusable). In some cases, filters have been observed reducing the volume or speed of VPN/Tor traffic to make usage impractical.

**Active Probing** — A system that finds suspicious flows, then tests their address by attempting a connection. If DPI notices a pattern suggesting a possible proxy server, the filtering system connects as a virtual client and sends test packets. As with Shadowsocks: Iran/China probe a candidate Shadowsocks server with random or copied "first packet" data; if the server returns a large encrypted response, it's flagged as Shadowsocks. This active step can be considered a supplementary form of DPI.

**Packet Dropping / Shaping** — Censors may also randomly drop packets or fragment traffic. Examples: blocking fragmented packets, or reducing QoS for certain users. OONI and other researchers have shown that deliberately shrinking packets or manipulating TCP ordering can sometimes block specific connections (techniques like `brdgrd` and `GoodbyeDPI` originated outside censoring regimes as countermeasures).

### Identification → Classification → Restriction → Blocking
DPI first identifies packets (e.g., determining whether a connection is HTTPS, DNS, or VPN traffic). It then classifies traffic according to policy (e.g., Skype, BitTorrent, or VPN traffic). If censorship is warranted, the connection can be **blocked** (dropped or RST-injected) or **throttled**. Finally, information may be logged or reported (e.g., recording visited sites). In Iran, for example, non-HTTP connections (such as plain V2Ray, WireGuard, or SSH without TLS) are reportedly dropped entirely by protocol filtering, specific DNS queries are answered with injected NXDOMAIN responses, and TLS traffic associated with particular social networks is terminated via RST.

---

## Case Study: Filtering in Iran

*(Presented strictly from a technical, network-engineering perspective.)*

Technically, Iran has implemented a combined **filtering-in-depth** system, comprising low-level **protocol filtering** plus deeper DPI at a higher layer.

### Filtering Architecture
Reports indicate that Iran permits only recognized **DNS**, **HTTP**, and **HTTPS** traffic, blocking all other protocols outright. In other words, if a packet resembles an unauthorized protocol (such as OpenVPN, SSH, or WireGuard) on the network, the filter drops it. This filtering focuses on both ports and packet signatures: for instance, on TCP/443, if the handshake doesn't begin with a valid TLS ClientHello, or on port 80 if it doesn't begin with a valid HTTP GET, the connection is terminated. Findings suggest that only "ordinary" TLS and HTTP using specific verbs (`GET`, `POST`, `HEAD`, `CONNECT`, `OPTIONS`, `DELETE`, `PUT` are allowed; two other verbs, `TRACE` and `PATCH`, are blocked) pass through. Regarding IPs, filtering is not applied to certain IPs and public addresses (e.g., internal IPs or some CDNs), but it is active across most external networks.

### Role of DPI
Beyond protocol-level filtering, Iran uses DPI for content filtering — particularly **TLS inspection**. During the 2018 protests, it became clear that this DPI inspects TLS traffic to identify handshakes for services like Instagram. Tests showed that both the SNI field and the TLS certificate's Common Name are inspected, and any connection associated with Instagram — wherever it appears — is terminated. Iran's DPI generally focuses on visible TLS and HTTP fields, blocking the TLS connection within HTTPS and typically following up with a TCP RST. It's also been reported that some TLS-based traffic (like SoftEther or similar proxies) gets blocked by DPI when it doesn't precisely match expected patterns (e.g., an unexpected SNI).

### Role of DNS Filtering
For broad blocking, Iran has consistently manipulated DNS. Over the years, both domestic and foreign domains have frequently been answered with NXDOMAIN responses or internal IP addresses. By using encrypted DNS (DoT/DoH), users can sometimes avoid DNS-level censorship, but Iran's protocol filter likely also attempts to block unrelated traffic on ports 853 and 443. Popular public DNS services like Google or Cloudflare may also be blocked at the local resolver level. From a DPI perspective, even a DoH query to a specific host is identifiable (e.g., via the SNI of the HTTPS request to the DNS server).

### Role of SNI Filtering
As noted, SNI in Iran is inspected via DPI (notably targeting media outlets and social networks). Additionally, encrypted SNI (ECH) is not yet widely deployed. Since an ECH client first needs to obtain the ECHConfig from DNS or within the initial handshake's SNI, a firewall can prevent this initial ECH exchange through inspection. Iran appears to still rely mainly on the traditional SNI model — terminating the connection as soon as a banned name appears in the SNI.

### Role of Active Probing
Solid documentation on active probing in Iran is limited, but anecdotal reports suggest proxy IPs (e.g., VPS servers carrying proxy traffic) are sometimes suddenly cut off and then re-tested for unusual activity. It's been suggested that before deploying a proxy, an HTTPS server check on the same address occurs to verify it isn't already blacklisted. If active probing bots operate in Iran, they likely scan high-traffic V2Ray/VPN servers. This hasn't been officially confirmed but appears plausible based on observed behavior.

### Role of Traffic Analysis
DPI is Iran's primary tool, but the network may also benefit from concurrent traffic analysis in some areas. For example, during recent protests, many RIPE Atlas probes were observed going offline — evidence of the start of a deep disruption. Packet behavior (such as the number of open connections or traffic patterns) may be monitored to flag unusual activity.

### Role of IP Reputation
Iran maintains blacklists of specific IPs (often belonging to proxy services, CDNs, or foreign countries). If a server's IP belongs to a country commonly associated with circumvention tools (e.g., Sweden, the US), it's more likely to end up on a blocklist. Iranian ISPs also sometimes directly blacklist IPs already known to be affected by the firewall (e.g., IPs known for Tor or L2TP use). Anecdotal reports also suggest some VPS IPs are blocked even before any VPN is installed — apparently due to this kind of IP reputation system.

### Detection Vectors for Circumvention Technologies
Each circumvention method has its own detection vector: traditional VPNs and non-TLS V2Ray are immediately blocked by the first-stage protocol filter, since "Iran's filter only accepts DNS, HTTP, and HTTPS." Protocols that closely mimic HTTPS (Trojan, XTLS, TCP/OpenVPN) typically pass through but may still be flagged by content-based DPI or TLS infrastructure analysis. Outline/Shadowsocks is detectable at first glance via active probing/signature analysis; UDP-based VPNs (WireGuard) are identifiable by their distinctive binary handshake pattern.

In summary, Iran combines tools across multiple layers:
1. First, identify the flow (based on address/port/packet signature).
2. Then classify the content (using DPI and signatures).
3. Finally, block or restrict the connection via forged DNS, RST, or packet dropping, as needed.

---

## References

This material draws on publicly available technical literature and research, including:

- IETF RFCs and protocol specifications (TLS, QUIC, HTTP/2, HTTP/3, DNS)
- Official V2Ray/Xray project documentation
- Academic research (USENIX Security, IEEE, ACM, PETS)
- Cloudflare Engineering Blog
- OONI (Open Observatory of Network Interference) reports
- Independent field reports and measurement studies on internet filtering in Iran and China

---

## 🤝 Contributing

Issues and pull requests are welcome — corrections, additional sources, and translation improvements are all appreciated.
