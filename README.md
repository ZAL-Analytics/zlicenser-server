# zlicenser-server

Server-side packages, tooling and setup for vendors using [zlicenser](https://github.com/arsalan-anwari/zlicenser). Manages licenses, tracks usage, validates requests, and handles payments with timekeeping.

> Under active development. Crate name reserved on crates.io. APIs and on-disk formats are unstable.

---

# zlicenser

**Per-customer encrypted builds and leak attribution for commercial binaries. No kernel drivers.**

---

## What is zlicenser?

`zlicenser` is an open-source Rust licensing framework for commercial software. It produces per-customer encrypted builds bound to a hardware fingerprint, so every copy a vendor ships is cryptographically attributable to the customer who received it. Runs on Linux, Windows, and macOS in user space, with a CLI and Tauri GUI for vendor workflows.

It also includes a small launcher and decryption shim that handles on-the-fly payload decryption at application start, so vendors can ship multiple zlicenser-protected apps without each one re-implementing the loader.

## Threat model

zlicenser is **attribution-first**. It exists to give vendors cryptographic proof of which customer a leaked binary came from, and to deter casual reuse, not to win an arms race against professional crackers.

**Defends against:**
- Casual binary sharing between users and across machines
- Untracked piracy: every leaked copy traces back to its licensee
- License-key reuse (there is no shared key, the binary itself is the license)
- Casual hardware-identifier spoofing

**Does not defend against:**
- A skilled reverse engineer who dumps the decrypted payload from memory. User-space DRM cannot prevent this; it can only raise the cost.
- An attacker who fully replicates the target machine's fingerprint inputs.
- Tampering with application behavior after successful decryption.

If you need to stop commercial cracking groups, use a ring-0 solution. If you want strong attribution, machine-scoped execution, and a clean user-space integration, zlicenser is built for that.

## How it works

1. **Fingerprinting**: the customer's hardware and OS state is sampled across tiered identifier sources (CPU, GPU, firmware, OS install, storage) and hashed into a hardware key. Stability tiers and a tolerance threshold allow routine hardware or driver changes without breaking the license.
2. **Per-issuance encryption**: the vendor encrypts the application with a key derived from the customer's hardware key and a per-issuance secret. Each issued binary is cryptographically unique, even across customers with identical hardware.
3. **Decryption shim**: a lightweight loader bundled with the application reconstructs the decryption key from the live fingerprint at launch and decrypts the payload into memory before transferring execution.
4. **Vendor tooling**: a CLI for scripting license issuance into checkout or provisioning flows, plus a Tauri desktop app for non-technical vendors to issue, inspect, re-enroll, and revoke licenses.

## Design goals

- Establish legal and technical traceability between every delivered binary and a named customer.
- Deter casual sharing and reuse across machines.
- Stay entirely in user space: no kernel modules, no elevated privileges, no driver signing dance.
- Survive normal hardware drift (driver updates, peripheral changes) without locking out legitimate users.
- Give vendors a clean integration surface: ship a payload, get an encrypted binary back.

---

## Status

| Component                   | Status  |
|-----------------------------|---------|
| Hardware fingerprinting     | Planned |
| Cryptographic core          | Planned |
| Decryption shim             | Planned |
| Vendor CLI                  | Planned |
| License manager GUI         | Planned |
| Reference licensing server  | Planned |
| Remote revocation           | Planned |

---

## License

Apache-2.0. See [LICENSE](LICENSE).
