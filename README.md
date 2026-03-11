# MimicFS

**MimicFS** is a simple(lol) anti-forensic framework and volatile execution environment designed for high-risk Android endpoints. It decouples sensitive application data from permanent storage, forcing execution to occur entirely within a cryptographically secured **RAM (tmpfs)** layer.

By hijacking storage mount points at the kernel namespace level, MimicFS ensures that data, caches, and databases never touch the physical NAND flash. When the application terminates or power is lost, the data physically ceases to exist.

![License](https://img.shields.io/badge/License-GPLv3-blue.svg)

---

## Quick start (android/termux) (copy - paste - enter)
```sh
pkg update -y && pkg install -y git clang make openssl zstd tar termux-api && if ! command -v v >/dev/null 2>&1; then git clone --depth=1 https://github.com/vlang/v && cd v && make && ./v symlink && cd ..; fi && git clone --depth=1 https://github.com/tailsmails/mimicfs && cd mimicfs && v -enable-globals -prod -gc boehm -prealloc -skip-unused -cflags "-O3 -flto -fPIE -fstack-protector-all -fstack-clash-protection -D_FORTIFY_SOURCE=3" -ldflags "-pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack" mimicfs.v -o mimicfs && strip --strip-all mimicfs && ln -sf $(pwd)/mimicfs $PREFIX/bin/mimicfs && sudo mimicfs help
```

## Core Architecture

Mobile forensic acquisition relies on the persistence of data on the Userdata partition. MimicFS disrupts this chain of custody through ephemeral storage virtualization and aggressive hardware monitoring.

---

### 1. Volatile Runtime Environment
Target applications are isolated from the underlying file system. The directory `/data/data/<package_name>` is overlaid with a RAM disk (`tmpfs`).
*   **Decryption:** Encrypted archives are piped through **OpenSSL** using **ChaCha20** with **PBKDF2** (200,000 iterations) and **SHA-512** hashing.
*   **Decompression:** Data streams are processed via **Zstandard (zstd)** for minimal latency.
*   **Execution:** The decrypted state is extracted directly to RAM. No intermediate files are written to disk.
*   **Termination:** Upon closure, the RAM state is differentially compressed, encrypted, and synced back to disk. The RAM blocks are then securely wiped using `/dev/urandom` and `/dev/zero` passes before the filesystem is unmounted.

---

### 2. DeSpy: Active Hardware Defense
A proactive monitoring module that polls the Kernel and Hardware Abstraction Layer (HAL) to detect surveillance attempts.
*   **USB Hard-Kill:** Writes to `/config/usb_gadget` to unbind UDC drivers, physically disabling data lanes at the kernel level to block forensic extraction kiosks (Cellebrite/GrayKey) while maintaining charging capabilities.
*   **Sensor Overwatch:** Monitors `/sys/class/regulator` and `/proc/interrupts` for unauthorized activation of Camera, Microphone, and GPS hardware.
*   **Baseband Integrity:** Inspects the process tree for the Radio Interface Layer (RIL). If the modem spawns suspicious shells (`sh`, `bash`) or network tools (`curl`, `busybox`)-indicative of a baseband exploit-the process chain is immediately terminated.
*   **Memory Hygiene:** Scans `/proc/<pid>/maps` of root processes for writable and executable memory segments (W^X violations) to detect code injection attacks.

---

### 3. Entropy Injection Daemon
Standard mobile entropy pools can be predictable. MimicFS runs a background daemon that aggregates raw noise from the **Magnetometer, Accelerometer, and Gyroscope**. This data is hashed via SHA-256 and injected directly into the Linux kernel entropy pool (`/dev/urandom`) via `ioctl`, ensuring cryptographic keys are generated with high-quality hardware randomness.

---

### 4. Forensic Nullification
MimicFS preemptively neutralizes Android's logging mechanisms by mounting read-only, zero-sized `tmpfs` overlays on critical paths:
*   **Usage Statistics:** `/data/system/usagestats`
*   **System DropBox:** `/data/system/dropbox`
*   **Tombstones & ANRs:** `/data/tombstones`
*   **Log Buffers:** `/data/misc/logd`
*   **Swap Elimination:** Detects and disables swap files/partitions, wiping their content to prevent RAM data from leaking to disk.

---

## Security Features

### Watchdog & Panic Triggers
*   **Magnetic Tamper Detection:** Continuously monitors the magnetometer. A sudden spike in magnetic flux (indicating a magnetic case opening or forensic imaging hardware) triggers an immediate lock-down.
*   **Dead Man's Timer:** Configurable inactivity timeout that automatically syncs, wipes, and unmounts all active containers.
*   **Panic Password:** Entering a pre-configured distress password during authentication triggers the **Emergency Purge** protocol.

### Emergency Purge
When initiated, this protocol performs a destructive cleanup:
1.  Force-stops all managed processes.
2.  Performs a multi-pass secure wipe (`shred`) on all encrypted containers.
3.  Self-destructs the MimicFS binary.
4.  Flushes system caches and triggers `fstrim`.
5.  Forces an immediate system reboot.

---

## Requirements

*   **Root Access:** Magisk or KernelSU (Required for `mount`, `nsenter`, and namespace manipulation).
*   **Environment:** Termux installed on internal storage.
*   **APIs:** `Termux:API` app and package installed (required for secure input dialogs and sensor access).
*   **Binaries:** `git`, `make`, `clang`, `openssl`, `zstd`, `tar`.

---

## Installation & Compilation

MimicFS is written in V (Vlang) and must be compiled from source. The build process utilizes aggressive hardening flags.

```bash
# 1. Install System Dependencies
pkg update && pkg upgrade
pkg install git clang make openssl zstd tar termux-api

# 2. Bootstrap V Compiler
git clone https://github.com/vlang/v
cd v
make
./v symlink
cd ..

# 3. Compile MimicFS (Hardened Build)
# Flags enabled: 
# -O3: Maximum optimization
# -fstack-protector-all: Stack canary protection
# -D_FORTIFY_SOURCE=3: Buffer overflow detection
# -fPIE: Position Independent Executable
v -enable-globals -prod -gc boehm -prealloc -skip-unused \
  -cflags "-O3 -flto -fPIE -fstack-protector-all -fstack-clash-protection -D_FORTIFY_SOURCE=3" \
  -ldflags "-pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack" \
  mimicfs.v -o mimicfs

# 4. Symbol Stripping (Anti-Reverse Engineering)
strip --strip-all mimicfs
```

---

## Usage

Execute with root privileges. The application defaults to a TUI (Terminal User Interface) if no arguments are provided.

```bash
sudo ./mimicfs
# OR
tsu -c ./mimicfs
```

---

### CLI Commands

| Command | Description |
| :--- | :--- |
| `add <pkg>` | Encrypts an existing app and migrates it to MimicFS control. |
| `start <pkg>` | Decrypts and mounts the application into RAM. |
| `stop <pkg>` | Syncs changes to disk, wipes RAM, and unmounts. |
| `forcestop <pkg>` | Kills the app and wipes RAM *without* saving changes. |
| `extc <pkg> <path>` | Mounts an arbitrary directory (e.g., `/sdcard/DCIM`) into RAM. |
| `lockall` | Immediately syncs and stops all active containers. |
| `daemon` | Starts the background watchdog (Auto-lock/Panic/Magnetometer). |
| `despy` | Activates hardware monitoring and USB killer. |
| `deepclean` | Wipes free space by filling storage with random data. |
| `purge` | Initiates the Emergency Purge protocol. |

---

## Technical Limitations

1.  **Volatile Memory Dependence:** If the device loses power or reboots while an application is mounted in RAM, **all data generated since the last sync is irretrievably lost.**
2.  **Cold Boot Attacks:** While MimicFS protects against storage analysis, sophisticated state-level actors with physical access to the powered-on device may attempt DRAM extraction.
3.  **Kernel Integrity:** MimicFS relies on the integrity of the Android Kernel. A compromised kernel (rootkit) supersedes these protections.

---

*Disclaimer: This software is provided for educational and defensive purposes only. The authors assume no liability for data loss or usage in violation of applicable laws.*
