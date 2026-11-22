# IPSEC VPN Simulator

A web-based **Site-to-Site IPsec VPN Simulator & Troubleshooter** supporting multi-vendor network topologies, real-time Phase 1 / Phase 2 state modeling, interactive traffic diagnostics, and production-grade CLI configuration generation.

---

## 🚀 Key Features

- **Multi-Vendor Gateway Simulation**:
  - Cisco IOS-XE (ISR / ASR / Catalyst 8000)
  - Cisco ASA (9.x / Firepower)
  - Fortinet FortiGate (FortiOS 7.x)
  - Palo Alto Networks PAN-OS (PA-Series / VM-Series)
  - Juniper SRX (Junos OS)
  - MikroTik RouterOS (RouterOS 7)
  - strongSwan (Linux charon / swanctl)
  - Microsoft Azure VPN Gateway (route-based VpnGw SKU)
- **Circular Topology & Protected Subnet Visuals**:
  - Peer gateway circular nodes with vendor and WAN branding.
  - Protected LAN subnet circular nodes (`LAN A` & `LAN B`).
  - Active visual alerting: connection lines turn **bright red** with diagnostic tags (`Subnet SNATed`, `Subnet DNATed`, `Route Missing`, `Selector Mismatch`) when policies or paths fail.
- **Traffic NAT (SNAT & DNAT)**:
  - Independent toggles for both Source NAT and Destination NAT.
  - Dedicated custom IP / Subnet inputs for both modes.
  - Full bidirectional simulation including reverse de-NAT on return legs.
- **Local ID & Remote ID**:
  - Auto-pulls local interface and peer IP address by default.
  - Supports custom IP, FQDN, and email identifiers with validation against strict peer policies.
- **Comprehensive Cryptographic Suites**:
  - Phase 1 & 2 Ciphers: AES-CBC (128/192/256), AES-GCM (128/192/256), ChaCha20-Poly1305, Camellia, Blowfish, 3DES, DES, NULL.
  - Hashes/Integrity: SHA-256, SHA-384, SHA-512, SHA-1, MD5, AES-XCBC-96.
  - Diffie-Hellman / PFS Groups: 1, 2, 5, 14, 15, 16, 18, 19, 20, 21, 24, 31 (Curve25519).
- **Interactive Host Diagnostic Terminal (Traffic Test)**:
  - Interactive bash-like host terminal with command history (<kbd>↑</kbd>/<kbd>↓</kbd>).
  - Executable commands: `ping`, `telnet <host> <port>`, `traceroute`, `curl`, `nc -zv`, `ip route`, `ip addr`, `arp -n`, `help`, `clear`, `reset`.
- **Troubleshooting & CLI Generation**:
  - **Negotiation Ladder**: Step-by-step IKE packet exchange with vendor-authentic syslog and debug output.
  - **Diagnosis Engine**: Prioritized root-cause analysis with one-click automated fixes.
  - **Live Configuration Generator**: Production-ready, downloadable configuration scripts for all 8 supported platforms.

---

## 🌐 Hosting as a Subpage on Your Website

This tool is built with `vite-plugin-singlefile`, producing a **100% self-contained single file** (`dist/index.html`). All JavaScript, CSS, SVGs, and web fonts are inlined. There are no external asset folders or dependencies, making it effortless to host on any subpage or subpath.

### 1. Direct Subpath Deployment (Nginx / Apache / S3 / Cloudflare / Vercel / Netlify)
Place `dist/index.html` into any subfolder on your web server:
- `https://yourwebsite.com/tools/vpn-simulator/`
- `https://yourwebsite.com/ipsec-simulator/`
- `https://yourwebsite.com/pages/vpn/`

### 2. URL Deep-Linking & Pre-selected Scenarios
You can link directly to specific configurations, tabs, or scenarios via URL query parameters:

| Query Parameter | Example | Description |
| :--- | :--- | :--- |
| `?scenario=<id>` | `?scenario=azure-branch` | Opens a pre-configured lab scenario |
| `?tab=<tab>` | `?tab=traffic` | Jumps straight to `traffic`, `diagnosis`, `negotiation`, `compare`, or `config` |
| `?init=<A\|B>` | `?init=B` | Sets Site A or Site B as the tunnel initiator |
| `?embed=1` | `?embed=1` | Enables compact embed mode for seamless iframe integration |
| `?autorun=1` | `?autorun=1` | Automatically brings the tunnel up upon opening |
| `?config=<data>` | `?config=eyJBL...` | Encodes complete custom site A/B settings in the URL |

**Example URL:**
```
https://yourwebsite.com/tools/vpn-simulator/?scenario=azure-branch&tab=traffic
```

### 3. Iframe Embedding on Any CMS (WordPress / React / HTML)
To embed this tool into an existing blog post or portal page:

```html
<iframe
  src="https://yourwebsite.com/tools/vpn-simulator/?embed=1"
  width="100%"
  height="920"
  style="border: none; border-radius: 12px; box-shadow: 0 4px 24px rgba(0,0,0,0.35);"
  title="IPSEC VPN Simulator"
  loading="lazy"
  allow="clipboard-write"
></iframe>
```

---

## 🛠️ Development & Build

```bash
# Install dependencies
npm install

# Run Vite development server
npm run dev

# Build single-file production bundle
npm run build
```

---

## 📦 Project Structure

```
├── index.html
├── package.json
├── vite.config.ts
├── tsconfig.json
└── src/
    ├── App.tsx                     # Main layout & scenario state
    ├── main.tsx
    ├── index.css                   # Tailwind CSS styling & animations
    ├── components/
    │   ├── Topology.tsx            # Circular topology & protected subnets
    │   ├── SitePanel.tsx           # Multi-vendor parameter config panels
    │   ├── TrafficTab.tsx          # Interactive host diagnostic CLI
    │   ├── NegotiationTab.tsx      # IKE ladder & vendor syslog viewer
    │   ├── DiagnosisTab.tsx        # Root-cause analysis & 1-click fixes
    │   ├── ParametersTab.tsx       # Live pre-flight parameter comparison
    │   ├── ConfigTab.tsx           # Multi-vendor CLI script generator
    │   └── ui.tsx                  # Accessible UI inputs, buttons & switches
    └── lib/
        ├── types.ts                # Core domain interfaces & algorithm lists
        ├── vendors.ts              # Vendor capabilities, CLI commands & rules
        ├── simulate.ts             # Phase 1, Phase 2 & data-path engine
        ├── logs.ts                 # Vendor-authentic IKE / IPsec syslog engine
        ├── scenarios.ts            # Lab scenario presets
        ├── compare.ts              # Pre-flight comparison matrix
        ├── net.ts                  # IPv4 CIDR calculation & subnet helpers
        └── config/                 # Vendor CLI configuration generators
            ├── cisco.ts            # Cisco IOS-XE & ASA
            ├── firewalls.ts        # FortiGate, PAN-OS, Juniper SRX
            ├── open.ts             # MikroTik RouterOS & strongSwan
            └── azure.ts            # Microsoft Azure CLI scripts
```
