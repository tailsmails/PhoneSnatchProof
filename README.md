<div align="center">
  <img src="https://github.com/tailsmails/PhoneSnatchProof/blob/main/mimicfs_psp_mascot.png?raw=true" width="220" alt="mimicfs-psp mascot">
  <h1>mimicfs-psp</h1>
  <p>An anti-forensic execution framework designed for high-risk Android endpoints.</p>
</div>

# PhoneSnatchProof / PSP

**PhoneSnatchProof (MimicFS)** is an anti-forensic execution framework designed for high-risk Android endpoints. It decouples sensitive application data from persistent storage, forcing execution to occur within a cryptographically secured **RAM (tmpfs)** layer.

By isolating storage mount points at the kernel namespace level, MimicFS ensures that database files, cache structures, and application assets do not write directly to physical NAND flash. When the target application is terminated or the device loses power, the volatile data is cleared from RAM. 

The recommended implementation is **`mimicfs_next.v`**, which introduces a fully native cryptographic pipeline, eliminating runtime dependencies on external command-line utilities.

![License](https://img.shields.io/badge/License-GPLv3-blue.svg)

---

## Quick Start (Android / Termux)

Run the following command to bootstrap the environment, compile the next-generation binary (`mimicfs_next.v`), and install it. This version utilizes native compiled cryptography, reducing dependencies by eliminating the need for external `openssl` and `zstd` packages.

```sh
pkg update -y && pkg install -y git clang make tar termux-api && if ! command -v v >/dev/null 2>&1; then git clone --depth=1 https://github.com/vlang/v && cd v && make && ./v symlink && cd ..; fi && git clone --depth=1 https://github.com/tailsmails/PhoneSnatchProof && cd PhoneSnatchProof && v -enable-globals -prod -gc boehm -prealloc -skip-unused -d no_backtrace -d no_debug -cc clang -cflags "-O3 -flto -fPIE -fstack-protector-all -fstack-clash-protection -D_FORTIFY_SOURCE=3 -fno-ident -fno-common -fwrapv -ftrivial-auto-var-init=zero -fvisibility=hidden -Wformat -Wformat-security -Werror=format-security" -ldflags "-pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -Wl,-z,separate-code -Wl,--gc-sections -Wl,--icf=all -Wl,--build-id=none" mimicfs_next.v -o mimicfs && strip --strip-all --remove-section=.comment --remove-section=.note --remove-section=.gnu.version --remove-section=.note.ABI-tag --remove-section=.note.gnu.build-id --remove-section=.note.android.ident --remove-section=.eh_frame --remove-section=.eh_frame_hdr mimicfs && ln -sf $(pwd)/mimicfs $PREFIX/bin/mimicfs && sudo mimicfs help
```

---

## Core Architecture

### 1. In-Memory Volatile Runtime (`mimicfs_next.v` Upgrades)
Target applications run isolated from physical block storage. The directory `/data/data/<package_name>` is overlaid with a temporary memory filesystem (`tmpfs`).
*   **Double-Layer Cryptography:** Rather than relying on a single cipher or external binaries, `mimicfs_next.v` performs encryption and decryption tasks in-memory using a native dual-layer **AES-CTR and ChaCha20-Poly1305** pipeline via native V modules (`x.crypto.chacha20`, `x.crypto.chacha20poly1305`, `crypto.aes`, `crypto.cipher`, `crypto.argon2`, and `crypto.sha3`). This combined cipher structure ensures cryptographic resistance against single-algorithm compromises.
*   **Dual-Engine Compression:** Uses the native `compress.zstd` module to process volatile payload chunks directly in-memory, ~~while maintaining `compress.gzip` to handle outer tarball structures.~~
*   **Data Lifecycle:** On startup, the encrypted container is decrypted and extracted into the allocated `tmpfs` space. Upon explicit termination, changes are compressed, encrypted, and synced back to persistent storage. Active RAM blocks are then neutralized via multi-pass random data writes before unmounting.

### 2. Post-Quantum VDF, Obfuscated Headers & Key Wrapping
*   **Memory-Hard Post-Quantum VDF:** Upgraded from a simple sequential SHA-3 loop to a memory-hard delay chain. The system initializes a state using `SHA-3-512` based on the master password and file salt, sequentially resolving VDF iterations to enforce a reliable memory-hard CPU delay.
*   **Deterministic Seed Derivation (Password-Only UX):** To simplify the user experience and reduce human error, `seed0`, `seed1`, and `seed2` are no longer inputted manually. Instead, they are deterministically and securely derived from the master password (using PBKDF2-SHA3-512 with cryptographically isolated salts). This binds the entire cryptographic pipeline exclusively to the master key.
*   **Direct Seed0 Keystream Header Obfuscation:** The configuration parameters (such as `t` iterations, Argon2 memory, thread limits, chunk length, and compression status) are encrypted using a direct XOR-based decoding scheme. A keystream is generated deterministically using `key_seed0` (derived from the derived `seed0`) and contextual index offsets, eliminating the need for slow brute-forcing of headers while maintaining indistinguishability from random noise.
*   **Argon2-VDF XOR Key Wrapping:** The master key-wrapping layer has been strengthened. The master key-wrapping material (`final_key_bytes`) is computed by XORing a memory-hard **Argon2 KDF** key (derived from password + salt) with a mask generated from the final VDF delay trapdoor (`w_mask`). The 48-byte session key and IV are then encrypted via XOR with this combined key. Decryption is computationally bound to completing both the memory-hard VDF chain and entering the correct password (required for Argon2).
*   **Obfuscated VDF Metadata Layer:** To prevent passive detection of time-lock containers, the serialized VDF parameters block is completely obfuscated by XORing it with a rolling index key derived from `SHA-3-512(Password + Salt)`. This ensures that even the VDF length and iteration boundaries are indistinguishable from random data to observers who do not possess the password.
*   **PwGuard Memory Protection:** Plaintext passwords are not retained in system memory. The `PwGuard` structure generates shuffled binary buffers containing random byte values. Password characters are encoded and reconstructed on-the-fly via offset-based pointer lists, minimizing plaintext exposure in physical RAM dumps.

*check github.com/tailsmails/salty for more detais*

### 3. DeSpy: Active Hardware & Process Integrity Overwatch
A background defense module that polls kernel parameters and hardware interfaces:
*   **USB Hard-Kill:** Writes empty configurations to `/config/usb_gadget/g1/UDC` and toggles USB configuration properties to physically disable data lanes at the kernel level, blocking hardware extraction kiosks (such as Cellebrite or GrayKey) while preserving charging capabilities.
*   **Process Map Auditing:** Scans the memory maps (`/proc/<pid>/maps`) of running root processes to detect writable and executable memory maps (W^X violations). It enforces execution policies by immediately terminating untrusted binaries spawned from unauthorized paths like `/data/local/tmp` or `/tmp`.
*   **Baseband Protection:** Continuously inspects parent-child relationships in the process tree originating from the Radio Interface Layer (RIL). If a baseband process spawns shell environments (`sh`, `bash`) or network transfer utilities (`curl`, `wget`), the process chain is killed to prevent modem-based exploitation.
*   **Hardware State Analysis:** Monitors `/sys/class/regulator` and `/proc/interrupts` to alert the user of unauthorized activation of camera, microphone, or GPS components.

### 4. Entropy Injection Daemon
To counteract entropy starvation on mobile devices, a background daemon harvests hardware noise from physical onboard sensors (Magnetometer, Accelerometer, Gyroscope). This raw data is combined with monotonic time markers, hashed via SHA-256, and injected back into the Linux entropy pool (`/dev/urandom`) via `ioctl` system calls to improve key generation quality.

### 5. Log and Snapshot Nullification
Log directories and tracing mechanisms are preemptively neutralized by mounting read-only or zero-sized memory-backed overlays on paths associated with tracking and forensic indicators:
*   Usage Stats: `/data/system_ce/0/usagestats`
*   Dropbox Diagnostics: `/data/system/dropbox`
*   System Errors: `/data/tombstones` and `/data/anr`
*   Logd Buffers: `/data/misc/logd`
*   Disk Swap Disabling: Scans active swaps via `/proc/swaps`. If disk-based swap partitions are detected on `/data` or `/mnt/expand`, they are disabled and wiped with random passes to prevent RAM data leaks to persistent flash.

---

## Technical Specifications

| Parameter | Configuration / Algorithm |
| :--- | :--- |
| **Symmetric Cipher** | Dual-layer AES-CTR + ChaCha20-Poly1305 (Native V Implementation) |
| **Header Encryption** | ChaCha20 Stream Cipher (Keys and IVs derived via PBKDF2) |
| **Seed Derivation & Stretching** | PBKDF2-SHA3-512 (5,000 Iterations, derived securely from Master Password) |
| **Delay Function** | Memory-hard Sequential SHA-3-512 Post-Quantum VDF (16,384 Block Mixing Table) |
| **Key wrapping KDF** | Argon2d (32MB Memory, 2 Iterations, 4 Threads) XOR-masked with VDF Output |
| **VDF Metadata Protection** | Parameter structures XORed with Password-Salt SHA-3-512 keystream |
| **Compression** | Zstd (Chunk-level) ~~& Gzip (Tarball-level)~~ |
| **Password Guard** | Offset-based Pointer Mapping over Shuffled Buffers |

---

## Installation & Compilation

Since MimicFS is written in V, it is compiled directly to native machine code. The build utilizes defensive compiler flags to enable mitigations such as position-independent execution, stack-smashing protection, and strict symbol stripping.

```bash
# Compile mimicfs_next.v with security hardening enabled
v -enable-globals -prod -gc boehm -prealloc -skip-unused -d no_backtrace -d no_debug -cc clang \
  -cflags "-O3 -flto -fPIE -fstack-protector-all -fstack-clash-protection -D_FORTIFY_SOURCE=3 -fno-ident -fno-common -fwrapv -ftrivial-auto-var-init=zero -fvisibility=hidden -Wformat -Wformat-security -Werror=format-security" \
  -ldflags "-pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -Wl,-z,separate-code -Wl,--gc-sections -Wl,--icf=all -Wl,--build-id=none" \
  mimicfs_next.v -o mimicfs

# Strip debugging symbols and unnecessary ELF sections
strip --strip-all --remove-section=.comment --remove-section=.note --remove-section=.gnu.version \
  --remove-section=.note.ABI-tag --remove-section=.note.gnu.build-id --remove-section=.note.android.ident \
  --remove-section=.eh_frame --remove-section=.eh_frame_hdr mimicfs
```

---

## CLI Interface Reference

When executed without command-line arguments, MimicFS defaults to an interactive terminal user interface (TUI). It can also be controlled via the CLI:

```bash
sudo mimicfs <command> [args]
```

| Command | Description |
| :--- | :--- |
| `add <pkg>` | Moves target app data to volatile storage and generates an encrypted baseline. |
| `start <pkg>` | Decrypts and mounts application data to the designated RAM overlay. |
| `stop <pkg>` | Compresses active RAM data, encrypts it to persistent storage, and wipes the memory partition. |
| `forcestop <pkg>` | Abruptly terminates the application and discards all pending memory changes. |
| `sync <pkg>` | Saves the current state to the encrypted persistent file without terminating the application. |
| `remove <pkg>` | Securely shreds the encrypted container files from `/data/local/tmp`. |
| `cpw <pkg>` | Re-encrypts container headers to update the authorization password. |
| `list` | Displays managed containers and their current runtime status. |
| `lockall` | Iterates over active mount paths to sync, encrypt, and unmount all running containers. |
| `resize <pkg>` | Modifies the size allocation of an active application's tmpfs mount dynamically. |
| `despy` | Runs the active hardware monitor, process integrity auditor, and USB hard-kill interface. |
| `deepclean` | Overwrites free user space on `/sdcard` with random bytes, followed by an `fstrim` instruction. |
| `extc <pkg> <path>` | Creates a volatile tmpfs mount for generic external file paths. |
| `unextc <path>` | Unmounts a custom volatile path. |
| `unhide <pkg>` | Re-enables a package that has been hidden from the user interface. |
| `purge` | Triggers the Emergency Purge sequence. |

### Emergency Purge Protocol
The `purge` command is a panic option that:
1. Identifies and terminates all processes associated with running containers.
2. Wipes volatile memory arrays.
3. Shreds encrypted data files (`/data/local/tmp/*.enc`) using multi-pass file-system overwrites (`shred`).
4. Erases command history files, environment paths, and local configuration logs.
5. Issues system-wide cache flushes (`drop_caches`) and SSD storage trims (`fstrim`).
6. Triggers an immediate hardware reboot.

---

## Technical Limitations

1. **Volatile State Retention:** Data residing within the memory layers is transient. If the device undergoes an unexpected reboot, loses power, or suffers kernel instability while a container is open, all modifications made since the last synchronization event are lost.
2. **Physical Attack Vectors:** While persistent flash memory analysis is mitigated, the target application's active state remains resident in system memory. Highly sophisticated attacks, such as physical cold-boot extractions on a powered device, remain a theoretical threat vector.
3. **Kernel Dependence:** The security guarantees of namespace isolation and process monitoring depend on the integrity of the underlying Android kernel. A kernel-level compromise by malware or rootkits will bypass these user-space controls.

---

*Disclaimer: This software is provided strictly for educational and defensive security research. The authors accept no responsibility for potential data loss, hardware instability, or deployment in violation of local regulatory frameworks.*
