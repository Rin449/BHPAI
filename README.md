# 🛡️ BHPAI Community Edition (Open Source Tier)

Welcome to the **BHPAI (Behavioral Hybrid Predictive AI) Community Edition**. This repository represents the curated **25% open-source core** of the BHPAI cyber defense platform, focused on **High-Performance Static PE Analysis, Capstone Disassembly, and Multi-Format File Routing**.

---

## 🚀 Features Included in this Release

1. **Static PE Analyzer & Disassembler (`Core/scanner/`, `Core/Decompile/`)**:
   - Deep structural analysis of 32-bit & 64-bit PE binaries.
   - Section-by-section Shannon Entropy calculation for packing & encryption detection.
   - Capstone Engine disassembler for x86/x64 instruction streams.
   - Opcode N-Grams (N=2,3,4) and API N-Grams extraction with TF-IDF weighting.
   - Control Flow Graph (CFG) generation & Cyclomatic Complexity calculation ($M = E - N + 2P$).
   - Automated YARA rule synthesis (`YaraGen`) with Rust compiler runtime noise filtering.
   - AVX2-accelerated binary string search (`StringEx.cpp`).

2. **In-Memory Packer Decompressors (`Core/pack/`)**:
   - Native unpackers for UPX and WWPack to uncover Original Entry Points (OEP).

3. **Multi-Format File Router & Defanger (`Analyzers/Common/`)**:
   - 3-stage file routing (Magic bytes, in-memory container inspection, script classification).
   - Universal IOC extractor & defanger (neutralizing malicious URLs, IPs, and domains).
   - Evidence-based MITRE ATT&CK mapping.
   - Universal Schema 2.0 standardized JSON output.

4. **Fuzzy Hashing (`fuzzy/`)**:
   - Context-Triggered Piecewise Hashing (SSDEEP) for binary similarity clustering.

5. **CLI & Desktop Scanner Utilities**:
   - `scan.py`: Recursive PE batch scanner.
   - `app_scan.py`: Dedicated PyQt6 desktop PE analysis utility.

---

## 🛠️ Build Instructions

### Prerequisites
- C++17 compiler (MinGW-w64 with GCC 10+ / MSYS2 or MSVC 2019+)
- CMake 3.16+
- Libraries: `capstone`, `OpenSSL 3.x`, `zlib`

### Building pe_analyzer:
```bash
mkdir build && cd build
cmake .. -G "MinGW Makefiles"
cmake --build . --config Release
```

### Running the Analyzer:
```bash
./pe_analyzer.exe <path_to_sample.exe>
```

---

## 🔒 Enterprise Edition Features (Closed Source)
The Enterprise Edition of BHPAI additionally features:
- Dynamic Ring-3 Stealth Windows Sandbox (PEB unlinking, in-memory PE scrubber, 2-layer COW filesystem/registry virtualization).
- Intel Processor Trace (Intel PT) hardware-assisted execution tracing.
- BHR Ransomware Candidate Key Extractor (20+ crypto standards from RAM & `pagefile.sys`).
- Offline WinRE Emergency Rescue Suite (`bhpai_rescue.exe` with 5-phase ACID transaction pipeline).
- Client-Side Zero-Knowledge Encrypted Vault (SRP-6a PAKE & AES-256-GCM).
- Full Multi-Format PDF Analyzer V2.0 & Hard-Negative Calibrated AI Pipeline.

---

## 📄 License
This Community Edition is licensed under the MIT License. See [LICENSE](LICENSE) for details.
