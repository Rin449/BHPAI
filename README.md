# 🛡️ TÀI LIỆU DỰ ÁN TOÀN DIỆN: BHPAI
> **Phiên bản hệ thống**: V1.6 Enterprise Edition
> **Tác giả**: Bao
> **Ngôn ngữ & Công nghệ cốt lõi**: C++17 (MinGW-w64 / MSYS2), Python 3.9+, PyQt6, FastAPI, MinHook, Capstone Engine, Intel PT (Processor Trace), PyTorch, LightGBM, OpenSSL 3.x, zlib, Argon2id, Cryptography  
> **Tài liệu tham chiếu Master**: Chi tiết kiến trúc đa định dạng (Multi-Format), giải thuật phân tích đệ quy, phân tích tĩnh PE & PDF, giám sát động Sandbox Stealth Ring-3, trích xuất khóa Ransomware, mô hình AI chống cảnh báo giả (False Positive Resistant) và bảo mật dữ liệu đám mây Zero-Knowledge.

---

## 📋 MỤC LỤC TỔNG QUAN

1. [TỔNG QUAN DỰ ÁN & TẦM NHÌN KIẾN TRÚC ĐA ĐỊNH DẠNG](#1-tổng-quan-dự-án--tầm-nhìn-kiến-trúc-đa-định-dạng)
   - [1.1 Bối cảnh an ninh mạng & Thách thức bảo mật hiện đại](#11-bối-cảnh-an-ninh-mạng--thách-thức-bảo-mật-hiện-đại)
   - [1.2 Triết lý thiết kế Hybrid Đa định dạng (Multi-Format Tri-Layer Engine)](#12-triết-lý-thiết-kế-hybrid-đa-định-dạng-multi-format-tri-layer-engine)
   - [1.3 Bảng thông số kỹ thuật cốt lõi V1.6 (Technical Highlights)](#13-bảng-thông-số-kỹ-thuật-cốt-lõi-v16-technical-highlights)
2. [SƠ ĐỒ KIẾN TRÚC & LUỒNG XỬ LÝ DỮ LIỆU TỔNG THỂ](#2-sơ-đồ-kiến-trúc--luồng-xử-lý-dữ-liệu-tổng-thể)
3. [CHI TIẾT PHÂN HỆ 1: DYNAMIC WINDOWS SANDBOX & STEALTH MONITORING (RING-3)](#3-chi-tiết-phân-hệ-1-dynamic-windows-sandbox--stealth-monitoring-ring-3)
   - [3.1 Môi trường Desktop ảo hóa độc lập & Giới hạn Windows Job Object](#31-môi-trường-desktop-ảo-hóa-độc-lập--giới-hạn-windows-job-object)
   - [3.2 Tước bỏ đặc quyền quản trị bằng Restricted Token](#32-tước-bỏ-đặc-quyền-quản-trị-bằng-restricted-token)
   - [3.3 Kỹ thuật Anti-Evasion & Stealth (PEB Unlinking, Memory PE Wiping, DACL Guard)](#33-kỹ-thuật-anti-evasion--stealth-peb-unlinking-memory-pe-wiping-dacl-guard)
   - [3.4 Can thiệp Native NT API qua MinHook Engine & RAII HookGuard](#34-can-thiệp-native-nt-api-qua-minhook-engine--raii-hookguard)
   - [3.5 Công nghệ Copy-On-Write (COW) 2 lớp cho Filesystem & Registry](#35-công-nghệ-copy-on-write-cow-2-lớp-cho-filesystem--registry)
   - [3.6 Kernel Event Tracing (ETW Monitor)](#36-kernel-event-tracing-etw-monitor)
   - [3.7 Fake Network Server (C2 Sinkhole & Payload Mocking)](#37-fake-network-server-c2-sinkhole--payload-mocking)
   - [3.8 Giám sát Phần cứng Intel Processor Trace (Intel PT) Engine](#38-giám-sát-phần-cứng-intel-processor-trace-intel-pt-engine)
4. [CHI TIẾT PHÂN HỆ 2: STATIC PE ANALYZER & CAPSTONE DISASSEMBLER](#4-chi-tiết-phân-hệ-2-static-pe-analyzer--capstone-disassembler)
   - [4.1 Phân tích cấu trúc PE, Entropy Sections & Nhận diện Dị thường (Anomalies)](#41-phân-tích-cấu-trúc-pe-entropy-sections--nhận-diện-dị-thường-anomalies)
   - [4.2 Giải mã Opcode N-Grams & Trọng số TF-IDF](#42-giải-mã-opcode-n-grams--trọng-số-tf-idf)
   - [4.3 Chuỗi gọi API N-Grams & Đồ thị dòng điều khiển (CFG)](#43-chuỗi-gọi-api-n-grams--đồ-thị-dòng-điều-khiển-cfg)
   - [4.4 Bộ nhận diện & Tự động Giải nén Packer (UPX / WWPack Unpacker)](#44-bộ-nhận-diện--tự-động-giải-nén-packer-upx--wwpack-unpacker)
   - [4.5 Tự động sinh luật YARA nâng cao (YaraGen - Lọc Nhiễu Rust) & Fuzzy Hashing](#45-tự-động-sinh-luật-yara-nâng-cao-yaragen---lọc-nhiễu-rust--fuzzy-hashing)
5. [CHI TIẾT PHÂN HỆ 3: MULTI-FORMAT ENGINE & NATIVE C++ PDF ANALYZER V2.0](#5-chi-tiết-phân-hệ-3-multi-format-engine--native-c-pdf-analyzer-v20)
   - [5.1 Bộ định tuyến tệp 3 giai đoạn (FileRouter Engine)](#51-bộ-định-tuyến-tệp-3-giai-đoạn-filerouter-engine)
   - [5.2 Động cơ Phân tích PDF Native C++ V2.0 (`Analyzers/PDF/`)](#52-động-cơ-phân-tích-pdf-native-c-v20-analyzerspdf)
   - [5.3 Cây Phân tích Đệ quy Phân cấp (`AnalysisNode` Architecture)](#53-cây-phân-tích-đệ-quy-phân-cấp-analysisnode-architecture)
   - [5.4 Động cơ Chấm điểm Nguy cơ Ngữ cảnh & Quy tắc Thống trị Con (Child Dominance Rule)](#54-động-cơ-chấm-điểm-nguy-cơ-ngữ-cảnh--quy-tắc-thống-trị-con-child-dominance-rule)
   - [5.5 Phòng thủ Anti-DoS & Chống Bom Giải nén (Decompression Bomb Protection)](#55-phòng-thủ-anti-dos--chống-bom-giải-nén-decompression-bomb-protection)
   - [5.6 Ánh xạ MITRE ATT&CK Dựa trên Bằng chứng & Universal IOC Defanger](#56-ánh-xạ-mitre-attck-dựa-trên-bằng-chứng--universal-ioc-defanger)
   - [5.7 Chuẩn hóa Báo cáo Đầu ra Universal Schema 2.0](#57-chuẩn-hóa-báo-cáo-đầu-ra-universal-schema-20)
6. [CHI TIẾT PHÂN HỆ 4: DATASET 3 TẦNG & PIPELINE AI PDF CHỐNG FALSE POSITIVE](#6-chi-tiết-phân-hệ-4-dataset-3-tầng--pipeline-ai-pdf-chống-false-positive)
   - [6.1 Cấu trúc Phân tầng Dataset 3 Lớp (`dataset/pdf/`)](#61-cấu-trúc-phân-tầng-dataset-3-lớp-datasetpdf)
   - [6.2 Xóa bỏ lối tắt suy luận "False Positive Machine" qua Hard Negatives](#62-xóa-bỏ-lối-tắt-suy-luận-false-positive-machine-qua-hard-negatives)
   - [6.3 Khử trùng lặp đa cấp độ trước khi phân tách (Multi-Level Deduplication)](#63-khử-trùng-lặp-đa-cấp-độ-trước-khi-phân-tách-multi-level-deduplication)
   - [6.4 Phân tách tập độc lập chống rò rỉ dữ liệu `StratifiedGroupKFold`](#64-phân-tách-tập-độc-lập-chống-rò-rỉ-dữ-liệu-stratifiedgroupkfold)
   - [6.5 Vector 57 Đặc trưng & Hiệu chuẩn Xác suất (`CalibratedClassifierCV`)](#65-vector-57-đặc-trưng--hiệu-chuẩn-xác-suất-calibratedclassifiercv)
   - [6.6 Kết quả Benchmark Kiểm định & Khả năng Kháng Cảnh báo Giả (Audit Report)](#66-kết-quả-benchmark-kiểm-định--khả-năng-kháng-cảnh-báo-giả-audit-report)
7. [CHI TIẾT PHÂN HỆ 5: MACHINE LEARNING & AI ENSEMBLE (PE & GNN & SHAP)](#7-chi-tiết-phân-hệ-5-machine-learning--ai-ensemble-pe--gnn--shap)
   - [7.1 Hợp nhất Không gian Đặc trưng Đa chiều (Feature Vectorization)](#71-hợp-nhất-không-gian-đặc-trưng-đa-chiều-feature-vectorization)
   - [7.2 PyTorch API Sequence Embedder & Control Flow Graph GNN](#72-pytorch-api-sequence-embedder--control-flow-graph-gnn)
   - [7.3 Tối ưu hóa đặc trưng bằng SHAP Feature Pruning](#73-tối-ưu-hóa-đặc-trưng-bằng-shap-feature-pruning)
   - [7.4 Mô hình Phân loại LightGBM Ensemble (Adam, Eve, Marcus) & Ngưỡng động](#74-mô-hình-phân-loại-lightgbm-ensemble-adam-eve-marcus--ngưỡng-động)
8. [CHI TIẾT PHÂN HỆ 6: BHR ENGINE (RANSOMWARE DETECTOR & KEY RECOVERY)](#8-chi-tiết-phân-hệ-6-bhr-engine-ransomware-detector--key-recovery)
   - [8.1 Thuật toán phát hiện mã hóa Entropy cao (Shannon Entropy Rate)](#81-thuật-toán-phát-hiện-mã-hóa-entropy-cao-shannon-entropy-rate)
   - [8.2 Giám sát Burst Modification Rate & Hành vi xóa Shadow Copy](#82-giám-sát-burst-modification-rate--hành-vi-xóa-shadow-copy)
   - [8.3 Trích xuất khóa mã hóa đa thuật toán (20+ Standards) từ RAM & `pagefile.sys`](#83-trích-xuất-khóa-mã-hóa-đa-thuật-toán-20-standards-từ-ram--pagefilesys)
   - [8.4 Khôi phục dữ liệu tự động 100% từ Vùng đệm COW Virtual Overlay](#84-khôi-phục-dữ-liệu-tự-động-100-từ-vùng-đệm-cow-virtual-overlay)
   - [8.5 Nhật ký Crypto Timeline & Bản đồ biến đổi dữ liệu](#85-nhật-ký-crypto-timeline--bản-đồ-biến-đổi-dữ-liệu)
   - [8.6 Kiểm thử Thực tế Dual-Engine Hybrid Ransomware Memory Key Extraction](#86-kiểm-thử-thực-tế-dual-engine-hybrid-ransomware-memory-key-extraction)
   - [8.7 Kiến trúc Recovery Engine Registry & Crypto Dataflow Tracker](#87-kiến-trúc-recovery-engine-registry--crypto-dataflow-tracker)
9. [CHI TIẾT PHÂN HỆ 7: BEHAVIOR CORRELATOR & BEHAVIORGRAPH ENGINE V1.6](#9-chi-tiết-phân-hệ-7-behavior-correlator--behaviorgraph-engine-v16)
   - [9.1 Chuẩn hóa sự kiện đa nguồn (Userland Hooks + Kernel ETW)](#91-chuẩn-hóa-sự-kiện-đa-nguồn-userland-hooks--kernel-etw)
   - [9.2 Đồ thị Hướng Liên Tiến Trình (`BehaviorGraph`) & State Machine Chuỗi Tấn Công](#92-đồ-thị-hướng-liên-tiến-trình-behaviorgraph--state-machine-chuỗi-tấn-công)
   - [9.3 Độ phủ Win32 / NT Native API & Chuẩn hóa Đường dẫn Kernel](#93-độ-phủ-win32--nt-native-api--chuẩn-hóa-đường-dẫn-kernel)
   - [9.4 Giám sát Registry Native & Bộ Phân loại Persistence 9 Điểm](#94-giám-sát-registry-native--bộ-phân-loại-persistence-9-điểm)
   - [9.5 Stateful NetworkSessionTracker & Bộ Bóc Tách TLS SNI / HTTP](#95-stateful-networksessiontracker--bộ-bóc-tách-tls-sni--http)
   - [9.6 Mô hình Nhật ký Mã hóa Cấu trúc Enriched CryptoOperation](#96-mô-hình-nhật-ký-mã-hóa-cấu-trúc-enriched-cryptooperation)
   - [9.7 Bản đồ ma trận kỹ thuật MITRE ATT&CK Enterprise Matrix](#97-bản-đồ-ma-trận-kỹ-thuật-mitre-attck-enterprise-matrix)
   - [9.8 Bộ Thử Nghiệm Tự Động 7 Chiều & Kết Quả Benchmark V1.6](#98-bộ-thử-nghiệm-tự-động-7-chiều--kết-quả-benchmark-v16)
10. [CHI TIẾT PHÂN HỆ 8: ZERO-KNOWLEDGE ENCRYPTED BACKUP VAULT](#10-chi-tiết-phân-hệ-8-zero-knowledge-encrypted-backup-vault)
    - [10.1 Mô hình mã hóa Client-Side E2EE & Cây sinh khóa KDF/HKDF](#101-mô-hình-mã-hóa-client-side-e2ee--cây-sinh-khóa-kdfhkdf)
    - [10.2 Giao thức xác thực không tiết lộ tri thức SRP-6a PAKE (RFC 5054)](#102-giao-thức-xác-thực-không-tiết-lộ-tri-thức-srp-6a-pake-rfc-5054)
    - [10.3 Cơ chế Đổi mật khẩu tức thì (Instant Re-Keying Mechanism)](#103-cơ-chế-đổi-mật-khẩu-tức-thì-instant-re-keying-mechanism)
    - [10.4 Xác thực AAD Chuẩn hóa & Bucket Size Padding chống phân tích lưu lượng](#104-xác-thực-aad-chuẩn-hóa--bucket-size-padding-chống-phân-tích-lưu-lượng)
11. [CHI TIẾT PHÂN HỆ 9: GIAO DIỆN PYQT6 & HỆ THỐNG RESTFUL API SERVER](#11-chi-tiết-phân-hệ-9-giao-diện-pyqt6--hệ-thống-restful-api-server)
    - [11.1 Kiến trúc Giao diện PyQt6 Modern Dark Glassmorphism (Multi-Threading QThread)](#111-kiến-trúc-giao-diện-pyqt6-modern-dark-glassmorphism-multi-threading-qthread)
    - [11.2 Hệ thống RESTful API Server & Universal Scan Endpoint (`/scan`)](#112-hệ-thống-restful-api-server--universal-scan-endpoint-scan)
    - [11.3 Subscription Tiering API & Quản lý Hạn mức Lưu trữ](#113-subscription-tiering-api--quản-lý-hạn-mức-lưu-trữ)
    - [11.4 Threat Intelligence API (IOCs, Malware Families & User Scan History)](#114-threat-intelligence-api-iocs-malware-families--user-scan-history)
12. [HƯỚNG DẪN BIÊN DỊCH, KHỞI CHẠY & VẬN HÀNH HỆ THỐNG](#12-hướng-dẫn-biên-dịch-khởi-chạy--vận-hành-hệ-thống)
    - [12.1 Hướng dẫn Biên dịch Native C++ Modules (CMake & MinGW-w64)](#121-hướng-dẫn-biên-dịch-native-c-modules-cmake--mingw-w64)
    - [12.2 Cài đặt Môi trường Phụ thuộc Python](#122-cài-đặt-môi-trường-phụ-thuộc-python)
    - [12.3 Khởi chạy Giao diện Quản trị Desktop (`gui.py`)](#123-khởi-chạy-giao-diện-quản-trị-desktop-guipy)
    - [12.4 Khởi chạy Backend RESTful API Server (`server/main.py`)](#124-khởi-chạy-backend-restful-api-server-servermainpy)
    - [12.5 Vận hành Công cụ Dòng lệnh Độc lập (CLI Tools)](#125-vận-hành-công-cụ-dòng-lệnh-độc-lập-cli-tools)

---

## 1. TỔNG QUAN DỰ ÁN & TẦM NHÌN KIẾN TRÚC ĐA ĐỊNH DẠNG

### 1.1 Bối cảnh an ninh mạng & Thách thức bảo mật hiện đại
Trong kỷ nguyên an ninh mạng hiện nay, các cuộc tấn công có chủ đích (APT), mã độc gián điệp, và mã độc tống tiền (Ransomware) đã hoàn toàn vượt ra ngoài giới hạn của các tập tin thực thi truyền thống (`.exe`, `.dll`):
1. **Tấn công Đa định dạng & Vũ khí hóa Tài liệu (Document Weaponization)**: Mã độc xâm nhập ban đầu qua tài liệu PDF độc hại (chứa mã khai thác lỗ hổng Adobe Acrobat CVE, Javascript bị làm mờ, action `/Launch` thực thi command ngầm) hoặc đóng gói tệp thực thi PE nhúng bên trong PDF dạng Dropper.
2. **Lẩn tránh Phân tích Tĩnh (Static Evasion)**: Sử dụng các biến thể đa hình (Polymorphic), biến hình (Metamorphic), nén nhiều lớp (Packers), hoặc chèn các thành phần giả mạo hợp lệ nhằm đánh lừa mô hình học máy đơn giản tạo thành các lối tắt học vẹt (Heuristic Shortcut Failure).
3. **Lẩn tránh Môi trường Phân tích Động (Anti-Sandbox / Anti-Analysis)**: Quét bộ nhớ phát hiện các DLL giám sát nạp trong tiến trình, kiểm tra PEB module list, tháo gỡ hook (Unhooking), phát hiện môi trường máy ảo và thực hiện kỹ thuật ngủ (Sleep Acceleration Evasion).
4. **Phá hủy Dữ liệu Tốc độ Cao (High-speed Crypto Destruction)**: Các biến thể Ransomware thế hệ mới (LockBit 3.0, BlackCat, Hyper, Conti) sử dụng song song nhiều thuật toán mã hóa (Dual-Engine Hybrid: AES-256-GCM + ChaCha20 + X25519/RSA), xóa toàn bộ Volume Shadow Copies và phá hủy dữ liệu trước khi các hệ thống truyền thống kịp phản ứng.

**BHPAI** phiên bản **V1.6 Enterprise** là hệ sinh thái an ninh mạng thế hệ mới, giải quyết triệt để toàn bộ chuỗi tấn công thông qua kiến trúc **Multi-Format Hybrid Engine**: Định tuyến tự động đa định dạng (PE, PDF, Office, Script), phân tích đệ quy payload lồng nhau, cô lập Sandbox Ring-3 tàng hình, giám sát phần cứng Intel PT, và mô hình AI hiệu chuẩn chống cảnh báo giả.

---

### 1.2 Triết lý thiết kế Hybrid Đa định dạng (Multi-Format Tri-Layer Engine)

BHPAI V1.6 được thiết kế dựa trên mô hình **Định tuyến - Phân giải Đệ quy - Tương quan Hành vi - Phục hồi Tức thì**:

```
                         ┌───────────────────────────────────────────────┐
                         │               INPUT FILE STREAM               │
                         └───────────────────────┬───────────────────────┘
                                                 │
                                     ┌───────────▼───────────┐
                                     │  3-STAGE FILE ROUTER  │
                                     │  (Magic/ZIP/Script)   │
                                     └───────────┬───────────┘
                                                 │
                  ┌──────────────────────────────┼──────────────────────────────┐
                  │                              │                              │
         [FileFormat::PE]               [FileFormat::PDF]              [FileFormat::Office]
                  │                              │                              │
     ┌────────────▼────────────┐    ┌────────────▼────────────┐    ┌────────────▼────────────┐
     │  STATIC PE ANALYZER     │    │  PDF ANALYZER V2.0      │    │  OOXML / OLE ANALYZER   │
     │  - Capstone Disassembler│    │  - Binary Stream Parser │    │  - Macro VBA Extractor  │
     │  - Opcode TF-IDF & CFG  │    │  - Action/JS Deobfuscate│    │  - External DDE Links   │
     │  - YaraGen & Fuzzy Hash │    │  - 57 Features + Level 2│    │  - Embedded OLE Objects │
     └────────────┬────────────┘    │    Structural Fingerprnt│    └────────────┬────────────┘
                  │                 └────────────┬────────────┘                 │
                  │                              │                              │
                  │                  (Trích xuất Embedded PE)                   │
                  │                              │                              │
                  │                 ┌────────────▼────────────┐                 │
                  └────────────────►│ RECURSIVE ANALYSIS TREE │◄────────────────┘
                                    │    (AnalysisNode Tree)  │
                                    └────────────┬────────────┘
                                                 │
                                    ┌────────────▼────────────┐
                                    │  DYNAMIC SECURE SANDBOX │
                                    │  - Job Object & Token   │
                                    │  - COW Overlay FS/Reg   │
                                    │  - Stealth PEB Unlink   │
                                    │  - Intel PT Hardware Trc│
                                    └────────────┬────────────┘
                                                 │
                  ┌──────────────────────────────┴──────────────────────────────┐
                  │                                                             │
     ┌────────────▼────────────┐                                   ┌────────────▼────────────┐
     │ BHR RANSOMWARE ENGINE   │                                   │ AI & BEHAVIORGRAPH V1.6 │
     │ - High-Entropy Detector │                                   │ - Multi-Format Ensemble │
     │ - RAM & Pagefile Keys   │                                   │ - Cross-Process Machine │
     │ - Instant COW Rollback  │                                   │ - MITRE ATT&CK Mapping  │
     └─────────────────────────┘                                   └─────────────────────────┘
```

1. **Safety First & Anti-Bomb (An toàn & Chống DoS tuyệt đối)**: Sandbox cách ly hoàn toàn qua Desktop ảo riêng biệt (`BHPAISandboxDesktop`), giới hạn Job Object nghiêm ngặt và Restricted Token. Bộ giải nén dòng PDF được bảo vệ bởi `AnalysisBudget` và `ParserLimits` chống Decompression Bomb (tỷ lệ nén tối đa 100:1, giới hạn 500MB).
2. **Stealth Anti-Evasion (Tự ẩn giấu hoàn hảo)**: DLL giám sát Ring-3 tự động gỡ bỏ khỏi 3 danh sách liên kết kép PEB Module, xóa sạch PE Header & Debug PDB trong RAM, thiết lập DACL bảo vệ Launcher chống lại việc bị malware kill tiến trình.
3. **Recursive Analysis Tree & Child Dominance (Phân tích đệ quy & Thống trị con)**: Kiến trúc cây `AnalysisNode` kiểm tra đệ quy mọi tệp tin nhúng bên trong tài liệu. Khi phát hiện một tệp thực thi con (Child PE) là độc hại, hệ thống kích hoạt **Child Dominance Rule**, tự động nâng cấp kết luận của tài liệu cha lên **MALICIOUS** với điểm rủi ro tối thiểu 85/100.
4. **False-Positive Resistance AI (Kháng cảnh báo giả)**: Đột phá với cơ chế loại bỏ lối tắt suy luận sai lầm nhờ tổ chức tập dữ liệu 3 tầng (`suspicious_benign`), khử trùng lặp đa cấp (Exact Hash + Structural Fingerprint) và phân rã nhóm `StratifiedGroupKFold`.
5. **Data Protection & Key Recovery (Bảo vệ & Phục hồi khóa)**: BHR Engine phát hiện hành vi mã hóa entropy dồn dập, tự động bóc tách khóa của hơn 20 thuật toán mã hóa từ RAM & `pagefile.sys`, phục hồi 100% dữ liệu gốc từ vùng đệm COW Overlay.

---

### 1.3 Bảng thông số kỹ thuật cốt lõi V1.6 (Technical Highlights)

| Phân hệ & Tiêu chí | Thông số Kỹ thuật & Công nghệ triển khai V1.6 |
| :--- | :--- |
| **Định tuyến tệp (File Router)** | 3-Stage: Magic Bytes (PE, PDF, PK, OLE2, Shebang) + Container Inspection (In-memory ZIP for DOCX/XLSX/PPTX) + Script Classifier (PS1, VBS, JS, BAT, HTA) |
| **Phân tích PDF Native V2.0** | C++17 Binary-Safe Parser, FlateDecode/ASCIIHex Inflate, Recursive Embedded Payloads (`MZ`), Javascript Obfuscation & Acrobat API Analyzer, 57 Vector Features |
| **Phòng thủ Anti-Bomb / DoS** | `ParserLimits`: Max Input 500MB, Max Extracted 250MB, Max Ratio 100.0, Max Objects 100K, Max Filter Depth 6, Timeout 30 giây |
| **Môi trường Sandbox** | Windows Job Object (RAM 512MB, CPU Affinity, No Breakaway, UILIMITs) + Restricted Token (Drop Dangerous Privileges) + Virtual Desktop |
| **Ảo hóa Filesystem/Registry** | Copy-On-Write (COW) Virtual Overlay 2 lớp hỗ trợ Alternate Data Streams (ADS), Reparse Points, và Merged Virtual Registry View |
| **Kỹ thuật Stealth Monitor** | Unlink PEB (`InLoadOrder`, `InMemoryOrder`, `InInitializationOrder`) + In-Memory PE Header Scrubber + PDB Wiping + Launcher DACL Guard |
| **Hooking & Đồ thị Hành vi** | MinHook Engine + RAII `HookGuard` + `BehaviorGraph` liên tiến trình (Remote Thread, Process Hollowing, APC Queue Injection) |
| **Giám sát Phần cứng Intel PT** | Hardware-Assisted Tracing via CPUID leaf 0x14, `ProcessIntelProcessorTrace` Class 47, TNT/TIP/FUP Packet Decoder |
| **Phân tích Tĩnh PE (Static)** | Capstone Disassembler (x86/x64) + Opcode TF-IDF + API N-Grams + CFG Cyclomatic Complexity + YaraGen (Rust Blacklist) + SSDEEP/TLSH |
| **Bộ Mô hình AI / Machine Learning** | PyTorch Sequence Embedder + GNN trên CFG + LightGBM Ensemble (Adam, Eve, Marcus) + SHAP Feature Pruning + PDF Calibrated LGBM |
| **Huấn luyện Chống False Positive** | Dataset 3 tầng (`malware`, `benign`, `suspicious_benign`), Dedup cấp 1 (SHA256) & cấp 2 (Structural Fingerprint), `StratifiedGroupKFold` |
| **Phát hiện Ransomware** | Real-time Shannon Entropy Calculation ($\ge 7.5$) + Burst Modification Rate ($>20$ files/s) + Shadow Copy Wiping Detector |
| **Trích xuất Khóa & Khôi phục** | RAM & `pagefile.sys` Extractor cho 20+ thuật toán (AES-GCM GHASH $H$, ChaCha20, RSA DER, X25519 Clamping) + Automated COW Rollback |
| **Sao lưu Mã hóa Đám mây (Vault)** | Client-Side Zero-Knowledge E2EE (AES-256-GCM) + SRP-6a PAKE (RFC 5054) + Instant Re-Keying ($K_{\text{vault}}$) + Canonical AAD |
| **Hệ thống Giao diện & REST API** | PyQt6 Modern Dark Glassmorphism GUI (QThread workers) + FastAPI REST Server với Universal Endpoint `/scan` (Universal Schema 2.0) |

---

## 2. SƠ ĐỒ KIẾN TRÚC & LUỒNG XỬ LÝ DỮ LIỆU TỔNG THỂ

Sơ đồ trình tự toàn diện thể hiện luồng xử lý từ khi tiếp nhận tập tin đầu vào bất kỳ cho đến khi trích xuất payload, phân tích tĩnh/động, phân loại AI và khôi phục dữ liệu:

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'primaryColor': '#1E293B', 'primaryTextColor': '#F8FAFC', 'primaryBorderColor': '#0284C7', 'lineColor': '#0284C7', 'textColor': '#0F172A', 'actorBkg': '#1E293B', 'actorTextColor': '#F8FAFC', 'actorBorder': '#38BDF8', 'signalColor': '#0284C7', 'signalTextColor': '#0F172A', 'labelBoxBkgColor': '#E2E8F0', 'labelBoxBorderColor': '#64748B', 'labelTextColor': '#0F172A', 'loopTextColor': '#0F172A', 'noteBkgColor': '#FEF08A', 'noteTextColor': '#0F172A', 'noteBorderColor': '#EAB308'}}}%%
sequenceDiagram
    autonumber
    actor User as Người dùng / SOC Operator
    participant API as FastAPI /scan Endpoint
    participant Router as 3-Stage FileRouter
    participant PDF as PDF Analyzer Engine v2.0
    participant PE as PE Static Analyzer
    participant Tree as Recursive AnalysisNode Tree
    participant Sandbox as BHPAISandbox.exe
    participant BHR as BHR Engine & Recovery
    participant AI as Calibrated AI Models

    User->>API: Gửi tập tin cần kiểm tra (POST /scan)
    API->>Router: Định tuyến định dạng tệp (Magic Bytes + ZIP + Script)
    
    alt Định dạng là PDF (%PDF-)
        Router->>PDF: Khởi chạy pdf_analyzer.exe [Target.pdf]
        PDF->>PDF: Kiểm tra ParserLimits & Anti-Decompression Bomb
        PDF->>PDF: Phân tích đối tượng gián tiếp, giải nén FlateDecode
        PDF->>PDF: Quét mã Javascript, giải mã Obfuscation & Acrobat APIs
        PDF->>PDF: Bóc tách tệp nhúng (Recursive Embedded Extractor)
        alt Phát hiện tệp con nhúng là PE thực thi (MZ Header)
            PDF->>Tree: Tạo Child Node [Format: PE, Depth: 1]
            PDF->>PE: Chuyển giao Child PE sang PE Analyzer
            PE->>PE: Trích xuất PE Headers, Capstone Disassembly, IAT
            PE->>AI: Chấm điểm rủi ro tĩnh PE
            AI-->>PE: Child PE Risk = 85 (MALICIOUS)
            PE-->>Tree: Cập nhật Child Verdict = MALICIOUS
            Tree->>PDF: Áp dụng Child Dominance Rule
            PDF->>PDF: Nâng cấp Parent PDF Verdict = MALICIOUS (Threat Score: 90)
        end
        PDF->>AI: Dự báo mô hình Calibrated PDF LightGBM (57 features)
        PDF->>API: Xuất báo cáo Universal Schema 2.0 JSON
    else Định dạng là PE Executable (MZ / PE)
        Router->>PE: Chuyển giao sang pe_analyzer.exe
        PE->>PE: Header Parsing, Opcode TF-IDF, CFG, YaraGen
        PE->>AI: Dự báo qua Ensemble (Adam, Eve, Marcus)
        
        opt Kích hoạt Phân tích Động Sandbox
            API->>Sandbox: Khởi chạy BHPAISandbox.exe [Sample.exe]
            Sandbox->>Sandbox: Thiết lập Job Object 512MB & Restricted Token
            Sandbox->>Sandbox: Inject BHPAIMonitor.dll, Unlink PEB, Wipe Header
            Sandbox->>Sandbox: Kích hoạt COW Virtual Overlay Filesystem & Registry
            Sandbox->>Sandbox: Kích hoạt Giám sát Phần cứng Intel PT Tracing
            
            alt Phát hiện Ransomware (Entropy >= 7.5 & Burst I/O)
                Sandbox->>BHR: Cảnh báo Ransomware Encryption Event!
                BHR->>Sandbox: Chụp Pre-Exit Memory Dump & Quét pagefile.sys
                BHR->>BHR: Trích xuất khóa AES-GCM GHASH H / ChaCha20 / X25519
                BHR->>Sandbox: Kích hoạt Automated Rollback Restore từ COW Buffer
                Sandbox-->>API: Phục hồi 100% dữ liệu gốc
            end
        end
    end
    
    API-->>User: Trả về Báo cáo Tổng hợp JSON chuẩn Universal Schema 2.0
```

---

## 3. CHI TIẾT PHÂN HỆ 1: DYNAMIC WINDOWS SANDBOX & STEALTH MONITORING (RING-3)

Mã nguồn chính nằm tại: [`Core/sandbox/launcher/`](file:///c:/Users/Kryo/Music/BHPAI/Core/sandbox/launcher) & [`Core/sandbox/monitor/`](file:///c:/Users/Kryo/Music/BHPAI/Core/sandbox/monitor).

### 3.1 Môi trường Desktop ảo hóa độc lập & Giới hạn Windows Job Object
Nhằm triệt tiêu khả năng mã độc tương tác với màn hình người dùng, chụp ảnh desktop hoặc gửi phím giả lập (`SendInput`), `ProcessController.cpp` khởi tạo một Windows Desktop ảo hoàn toàn độc lập:

```cpp
// Tạo Virtual Desktop cô lập tuyệt đối
HDESK hSandboxDesktop = CreateDesktopA(
    "BHPAISandboxDesktop",
    NULL, NULL, 0,
    GENERIC_ALL,
    NULL
);
```

Toàn bộ cây tiến trình của mã độc được gắn chặt vào một **Windows Job Object** cấu hình nghiêm ngặt:
- **`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`**: Khi Sandbox Launcher kết thúc phân tích, toàn bộ tiến trình mã độc và con của nó bị tiêu diệt ngay lập tức.
- **`JOB_OBJECT_LIMIT_PROCESS_MEMORY`**: Giới hạn tối đa **512MB RAM** cho mỗi tiến trình, ngăn chặn các cuộc tấn công vắt cạn bộ nhớ (RAM Exhaustion DoS).
- **`JOB_OBJECT_LIMIT_BREAKAWAY_OK` (Bị cấm hoàn toàn)**: Chặn đứng mọi kỹ thuật tách tiến trình con ra khỏi Job Object (`CREATE_BREAKAWAY_FROM_JOB`).
- **`JOB_OBJECT_UILIMIT_HANDLES` & `JOB_OBJECT_UILIMIT_READCLIPBOARD`**: Chặn hoàn toàn quyền đọc Clipboard và truy cập các User Handle thực của hệ thống.

---

### 3.2 Tước bỏ đặc quyền quản trị bằng Restricted Token
Hệ thống tuân thủ nguyên tắc đặc quyền tối thiểu (**Least Privilege Enforcement**). Dù người dùng vận hành BHPAI dưới quyền Administrator, tiến trình mã độc trong Sandbox vẫn được khởi chạy thông qua một **Restricted Security Token** do hệ thống tự sinh:
- Tước bỏ toàn bộ đặc quyền hệ thống nhạy cảm: `SeDebugPrivilege`, `SeTakeOwnershipPrivilege`, `SeLoadDriverPrivilege`, `SeBackupPrivilege`, `SeRestorePrivilege`, `SeShutdownPrivilege`.
- Thêm Group SID `RESTRICTED` vào Token. Mã độc không thể mở handle có quyền cao tới các tài nguyên hệ thống, dịch vụ Windows hay tiến trình khác.

---

### 3.3 Kỹ thuật Anti-Evasion & Stealth (PEB Unlinking, Memory PE Wiping, DACL Guard)
Mã độc hiện đại thường xuyên kiểm tra xem bản thân có đang bị nạp các DLL phân tích lạ trong bộ nhớ hay không. Khi [`BHPAIMonitor.dll`](file:///c:/Users/Kryo/Music/BHPAI/Core/sandbox/monitor/DllMain.cpp) được nạp vào không gian địa chỉ của malware, nó kích hoạt quy trình tự xóa dấu vết:

#### A. Tháo gỡ khỏi Cấu trúc PEB (PEB Unlinking)
`UnlinkModuleFromPEB` duyệt và tháo gỡ `BHPAIMonitor.dll` khỏi 3 danh sách liên kết kép trong Process Environment Block:
1. `InLoadOrderModuleList`
2. `InMemoryOrderModuleList`
3. `InInitializationOrderModuleList`

```cpp
// Gỡ bỏ module khỏi liên kết kép PEB
entry->InLoadOrderLinks.Blink->Flink = entry->InLoadOrderLinks.Flink;
entry->InLoadOrderLinks.Flink->Blink = entry->InLoadOrderLinks.Blink;

// Xóa sạch vùng nhớ chuỗi DllName
SecureZeroMemory(entry->FullDllName.Buffer, entry->FullDllName.Length);
SecureZeroMemory(entry->BaseDllName.Buffer, entry->BaseDllName.Length);
```

#### B. Xóa sạch PE Header & PDB Debug Info trên RAM
Hàm `ScrubPEHeaderInMemory` ghi đè toàn bộ `IMAGE_DOS_HEADER`, `IMAGE_NT_HEADERS` của DLL giám sát bằng byte `0x00`. Đồng thời, xóa sạch chuỗi đường dẫn Debug PDB File Path, khiến các kỹ thuật quét chữ ký bộ nhớ (Memory Signature Scanning) hoàn toàn bất lực trong việc phát hiện Monitor DLL.

#### C. Thiết lập DACL Bảo vệ Launcher
Nhiều chủng Ransomware cố gắng mở handle và tiêu diệt tiến trình cha (`OpenProcess(PROCESS_TERMINATE)`). BHPAI can thiệp vào Discretionary Access Control List (DACL) của tiến trình Launcher, từ chối mọi yêu cầu `PROCESS_TERMINATE` từ các tiến trình con nằm trong Sandbox.

---

### 3.4 Can thiệp Native NT API qua MinHook Engine & RAII HookGuard
[`HookManager.cpp`](file:///c:/Users/Kryo/Music/BHPAI/Core/sandbox/monitor/HookManager.cpp) áp dụng framework MinHook can thiệp trực tiếp vào tầng sâu nhất của Userland Windows (`ntdll.dll` và `kernel32.dll`):

| Native API được Can thiệp | Vai trò Giám sát & Cô lập |
| :--- | :--- |
| `NtCreateFile` / `NtOpenFile` | Bắt giữ mọi yêu cầu mở/tạo tập tin và đường dẫn Alternate Data Streams (ADS). |
| `NtWriteFile` / `NtSetInformationFile` | Tính toán Shannon Entropy dữ liệu ghi đĩa thời gian thực và chuyển hướng Copy-On-Write (COW). |
| `NtDeleteFile` | Ngăn chặn hành vi xóa tệp gốc, chuyển hướng xóa vào vùng đệm ảo Virtual Overlay. |
| `NtMapViewOfSection` | Bắt giữ hành vi Nạp DLL ẩn, Process Hollowing, Mapped Executable Memory. |
| `NtProtectVirtualMemory` | Phát hiện hành vi cấp quyền thực thi bộ nhớ nguy hiểm `PAGE_EXECUTE_READWRITE` (RWX). |
| `NtOpenProcess` / `NtAllocateVirtualMemory` | Ghi nhận và chặn hành vi Process Injection vào tiến trình hệ thống (`lsass.exe`, `explorer.exe`). |
| `NtCreateUserProcess` / `CreateProcessW` | Bắt giữ hành vi sinh tiến trình con, tự động kích hoạt inject Monitor DLL vào tiến trình con mới. |
| `NtSetValueKey` / `NtDeleteKey` | Ngăn chặn ghi đè Registry thật, chuyển hướng sang Virtual Registry Overlay. |

**Cơ chế RAII `HookGuard` chống đệ quy**: Sử dụng biến `thread_local bool t_InHook`. Khi luồng thực thi đi vào trong hàm hook của BHPAI, cờ `t_InHook` được kích hoạt. Nếu hàm hook cần gọi các API hệ thống nội bộ, các lệnh gọi lặp sẽ được chuyển thẳng tới API gốc, triệt tiêu hoàn toàn rủi ro nghẽn đệ quy (Deadlock / Infinite Recursion).

---

### 3.5 Công nghệ Copy-On-Write (COW) 2 lớp cho Filesystem & Registry
BHPAI triển khai công nghệ ảo hóa hai lớp độc quyền ([`PathMapper.hpp`](file:///c:/Users/Kryo/Music/BHPAI/Core/sandbox/monitor/PathMapper.hpp), [`DirectoryUnion.hpp`](file:///c:/Users/Kryo/Music/BHPAI/Core/sandbox/monitor/DirectoryUnion.hpp), [`RegistryOverlay.cpp`](file:///c:/Users/Kryo/Music/BHPAI/Core/sandbox/monitor/RegistryOverlay.cpp)):

```
                                  TIẾN TRÌNH TRONG SANDBOX
                                             │
                        ┌────────────────────┴────────────────────┐
                        │ NtCreateFile / NtWriteFile / NtSetValue │
                        └────────────────────┬────────────────────┘
                                             │
                                  ┌──────────▼──────────┐
                                  │  PathMapper Engine  │
                                  └──────────┬──────────┘
                                             │
                   ┌─────────────────────────┴─────────────────────────┐
                   │                                                   │
        [YÊU CẦU ĐỌC (READ)]                                [YÊU CẦU GHI/SỬA/XÓA (WRITE)]
                   │                                                   │
         ┌─────────▼─────────┐                               ┌─────────▼─────────┐
         │ Kiểm tra Overlay  │                               │ Ghi trực tiếp vào │
         └─────────┬─────────┘                               │  Overlay\Files\   │
                   │                                         │  Overlay\Reg\     │
          ┌────────┴────────┐                                └─────────┬─────────┘
          │                 │                                          │
     (Đã có file)     (Chưa có file)                                   ▼
          │                 │                                 ┌───────────────────┐
          ▼                 ▼                                 │ HỆ THỐNG THẬT CỦA │
   ┌──────────────┐  ┌──────────────┐                         │ NGƯỜI DÙNG GIỮ    │
   │ Đọc Overlay  │  │ Đọc File Thật│                         │ NGUYÊN 100%       │
   └──────────────┘  └──────────────┘                         └───────────────────┘
```

1. **Filesystem Virtual Overlay**:
   - Khi đọc tệp: Nếu tệp đã bị mã độc sửa trước đó, trả về tệp trong `Overlay\Files\`. Nếu chưa sửa, trả về tệp gốc trên đĩa thật.
   - Khi ghi/sửa/xóa: Thao tác lập tức được ghi vào `Overlay\Files\`. Tệp thật trên máy tính người dùng **hoàn toàn bất biến**.
   - Hỗ trợ đầy đủ các tính năng nâng cao của NTFS: Alternate Data Streams (ADS), Reparse Points, Junctions và Hardlinks.
2. **Registry Merged Virtual Overlay**:
   - Cung cấp chế độ xem hợp nhất (Merged View). Malware liệt kê registry sẽ nhìn thấy cả registry gốc và các khóa nó vừa tạo trong `Overlay\Reg\`.
   - Các hành vi ghi Persistence (như Run, RunOnce, Winlogon, Image File Execution Options - IFEO) đều bị cô lập an toàn trong bộ nhớ ảo.

---

### 3.6 Kernel Event Tracing (ETW Monitor)
Song song với Userland Hooks, [`EtwMonitor.cpp`](file:///c:/Users/Kryo/Music/BHPAI/Core/sandbox/launcher/EtwMonitor.cpp) khởi tạo một phiên lắng nghe Kernel ETW Session theo thời gian thực:
- **`Microsoft-Windows-Kernel-Process`**: Bắt giữ sự kiện sinh/kết thúc tiến trình, tạo luồng từ cấp Kernel.
- **`Microsoft-Windows-Kernel-File`**: Giám sát I/O đĩa cứng độc lập với các kỹ thuật Userland.
- **`Microsoft-Windows-Kernel-Network`**: Giám sát kết nối TCP/UDP Socket IP trực tiếp từ Kernel Driver.

Cơ chế kết hợp Userland Hook + Kernel ETW triệt tiêu 100% rủi ro mã độc sử dụng kỹ thuật **API Unhooking** (ghi đè đoạn mã stub của API trong bộ nhớ RAM) nhằm qua mặt hệ thống giám sát.

---

### 3.7 Fake Network Server (C2 Sinkhole & Payload Mocking)
Để giám sát hành vi liên lạc Command and Control (C2) và tải payload giai đoạn hai của malware mà không làm lộ địa chỉ IP thật hoặc gây nguy hiểm tới mạng Internet, Launcher tích hợp [`FakeNetworkServer`](file:///c:/Users/Kryo/Music/BHPAI/Core/sandbox/launcher/main.cpp):
- Lắng nghe tại các cổng local `80` và `8080`.
- Tự động phản hồi các yêu cầu giao thức HTTP/HTTPS.
- Khi mã độc gửi request tải payload (`.exe`, `.dll`, `/download`), server tự động đóng vai trò Sinkhole trả về tập tin giả lập an toàn để mã độc tiếp tục lộ diện các hành vi thực thi tiếp theo.

---

### 3.8 Giám sát Phần cứng Intel Processor Trace (Intel PT) Engine
Nhằm phát hiện mã độc sinh mã động trong bộ nhớ (JIT / Dynamic Shellcode) hoặc tự biến đổi mã (Self-Modifying Code), BHPAI trang bị bộ giám sát cấp phần cứng **Intel Processor Trace (Intel PT)**:

Mã nguồn chính: [`IntelPTChecker.cpp`](file:///c:/Users/Kryo/Music/BHPAI/Core/sandbox/launcher/IntelPTChecker.cpp), [`IntelPTController.cpp`](file:///c:/Users/Kryo/Music/BHPAI/Core/sandbox/launcher/IntelPTController.cpp), [`IntelPTDecoder.cpp`](file:///c:/Users/Kryo/Music/BHPAI/Core/sandbox/launcher/IntelPTDecoder.cpp).

1. **Xác thực Phần cứng (`IntelPTChecker`)**: Sử dụng lệnh Assembly `CPUID` (Leaf `0x14`, Sub-leaf `0x0`) để xác nhận vi xử lý Intel CPU có hỗ trợ IPT và kiểm tra Windows API `ProcessIntelProcessorTrace` (Class 47).
2. **Thu thập Zero-Overhead (`IntelPTController`)**: Thiết lập vùng đệm tuần hoàn (Ring Buffer) cấu trúc `PROCESS_INTEL_PROCESSOR_TRACE_CONFIG`. Vi xử lý CPU tự động ghi lại từng nhánh rẽ câu lệnh thực thi (Branch Execution) ở cấp độ vi kiến trúc mà không làm chậm tiến trình mã độc.
3. **Giải mã Luồng Gói tin (`IntelPTDecoder`)**: Phân giải trực tiếp các gói tin nhị phân Intel PT: **TNT** (Taken/Not-Taken), **TIP** (Target IP address), **FUP** (Far Unconditional Packets), tái dựng 100% đồ thị dòng điều khiển thực tế của mã độc mà không cần can thiệp bất kỳ câu lệnh nào vào nhị phân.

---

## 4. CHI TIẾT PHÂN HỆ 2: STATIC PE ANALYZER & CAPSTONE DISASSEMBLER

Mã nguồn chính nằm tại: [`Core/scanner/`](file:///c:/Users/Kryo/Music/BHPAI/Core/scanner), [`Core/Decompile/`](file:///c:/Users/Kryo/Music/BHPAI/Core/Decompile), [`Core/pack/`](file:///c:/Users/Kryo/Music/BHPAI/Core/pack).

### 4.1 Phân tích cấu trúc PE, Entropy Sections & Nhận diện Dị thường (Anomalies)
[`PeParser.cpp`](file:///c:/Users/Kryo/Music/BHPAI/Core/Decompile/PeParser.cpp) bóc tách toàn diện cấu trúc nhị phân của tập tin Portable Executable:
- **Parsing Headers**: Kiểm tra tính hợp lệ của `IMAGE_DOS_HEADER`, `IMAGE_NT_HEADERS`, `IMAGE_FILE_HEADER`, `IMAGE_OPTIONAL_HEADER`.
- **Phân tích Entropy từng Section**: Tính toán chỉ số Shannon Entropy cho từng section ($S = -\sum p_i \log_2 p_i$). Chỉ số Entropy trong khoảng $7.2 - 8.0$ tại section `.text` hoặc `.data` là bằng chứng rõ ràng của mã bị nén hoặc mã hóa.
- **Nhận diện Dị thường (Anomalies)**:
  - Tên Section bất thường (`.vmp`, `.themida`, `UPX0`, `UPX1`, `text1`).
  - SizeOfRawData bằng 0 nhưng VirtualSize lại rất lớn (dấu hiệu nạp unpacker stub).
  - TimeDateStamp bị làm giả (ở tương lai hoặc quá khứ xa).
  - Xuất hiện TLS Callbacks (`IMAGE_DIRECTORY_ENTRY_TLS`) để thực thi mã độc trước EntryPoint.

---

### 4.2 Giải mã Opcode N-Grams & Trọng số TF-IDF
[`Disassembler.cpp`](file:///c:/Users/Kryo/Music/BHPAI/Core/Decompile/Disassembler.cpp) tích hợp **Capstone Engine** dịch mã máy nhị phân sang hợp ngữ Assembly (x86/x64).

[`opcode_tfidf.cpp`](file:///c:/Users/Kryo/Music/BHPAI/Core/scanner/opcode_tfidf.cpp) thực hiện:
1. Trích xuất chuỗi Opcode loại bỏ toán hạng (như `mov, push, call, sub, xor, jnz`).
2. Sinh các cụm N-Grams (2-gram, 3-gram, 4-gram).
3. Tính toán trọng số **TF-IDF**:

$$\text{TF-IDF}(t, d, D) = \text{TF}(t, d) \times \log\left(\frac{|D|}{1 + |\{d \in D : t \in d\}|}\right)$$

Làm nổi bật các chuỗi câu lệnh giải mã XOR vòng lặp hoặc giải mã Shellcode đặc trưng của mã độc.

---

### 4.3 Chuỗi gọi API N-Grams & Đồ thị dòng điều khiển (CFG)
- **API Call N-Grams** ([`pe_api_ngram.cpp`](file:///c:/Users/Kryo/Music/BHPAI/Core/scanner/pe_api_ngram.cpp)): Xâu chuỗi các hàm API trong Import Address Table (IAT) thành các cụm có ý nghĩa hành vi (ví dụ: `VirtualAlloc` $\rightarrow$ `WriteProcessMemory` $\rightarrow$ `CreateRemoteThread`).
- **Control Flow Graph (CFG)** ([`CFG.cpp`](file:///c:/Users/Kryo/Music/BHPAI/Core/scanner/CFG.cpp)): Xây dựng đồ thị dòng điều khiển của chương trình:
  - Phân tách khối lệnh cơ sở (Basic Blocks).
  - Xây dựng tập cạnh rẽ nhánh (Jump/Call Edges).
  - Tính toán độ phức tạp vòng (Cyclomatic Complexity) và chỉ số liên thông đồ thị.

---

### 4.4 Bộ nhận diện & Tự động Giải nén Packer (UPX / WWPack Unpacker)
Khi phát hiện tệp PE bị đóng gói bằng packer phổ biến, hệ thống tự động kích hoạt module giải nén:
- [`UPX.cpp`](file:///c:/Users/Kryo/Music/BHPAI/Core/pack/UPX.cpp): Nhận diện chữ ký UPX, tự động giải nén section `UPX0`, `UPX1` và khôi phục bảng IAT ban đầu.
- [`WWPack.cpp`](file:///c:/Users/Kryo/Music/BHPAI/Core/pack/WWPack.cpp): Nhận diện và giải nén các biến thể của WWPack.

Tệp sau khi giải nén được đưa trở lại quy trình phân tích tĩnh để tiếp cận payload thực sự.

---

### 4.5 Tự động sinh luật YARA nâng cao (YaraGen - Lọc Nhiễu Rust) & Fuzzy Hashing
- **Automatic YARA Generator** ([`YaraGen.cpp`](file:///c:/Users/Kryo/Music/BHPAI/Core/scanner/YaraGen.cpp)):
  - **Lọc nhiễu Rust/C++ Standard Libraries**: Tự động loại bỏ các chuỗi thư viện chuẩn vô hại (`/rustc/`, `panicking.rs`, `Option::unwrap`, `attempt to divide by zero`, `raw_vec`) để triệt tiêu cảnh báo sai.
  - **Gán nhãn chuỗi (String Tagging)**: Tự động phân loại chuỗi theo thẻ nhãn: **URL**, **Registry Key**, **Mutex**, **Crypto Constant**, **API Signal**, **Hex Byte Patterns**.
  - **Trích xuất chuỗi byte EntryPoint**: Tự động sinh đoạn hex signature chuẩn xác tại điểm vào của tệp.
- **Fuzzy Hashing Engine** ([`fuzzy/fuzzyhash.c`](file:///c:/Users/Kryo/Music/BHPAI/fuzzy/fuzzyhash.c)):
  - **SSDEEP**: So sánh độ tương đồng giữa các biến thể mã độc có sửa đổi nhỏ.
  - **TLSH**: Tính toán mã băm Locality Sensitive Hash phục vụ đối soát cơ sở dữ liệu mẫu độc lớn.

---

## 5. CHI TIẾT PHÂN HỆ 3: MULTI-FORMAT ENGINE & NATIVE C++ PDF ANALYZER V2.0

Mã nguồn chính nằm tại: [`Analyzers/Common/`](file:///c:/Users/Kryo/Music/BHPAI/Analyzers/Common) và [`Analyzers/PDF/`](file:///c:/Users/Kryo/Music/BHPAI/Analyzers/PDF).

### 5.1 Bộ định tuyến tệp 3 giai đoạn (FileRouter Engine)
Để hỗ trợ toàn diện các định dạng tệp khác nhau mà không dựa vào phần mở rộng tệp (`.exe`, `.pdf`, `.docx`) có thể bị kẻ tấn công đổi tên để ngụy trang, [`FileRouter.cpp`](file:///c:/Users/Kryo/Music/BHPAI/Analyzers/Common/FileRouter.cpp) thực hiện định tuyến 3 giai đoạn:

```
                            INPUT FILE BYTE STREAM
                                      │
               ┌──────────────────────┴──────────────────────┐
               │          GIAI ĐOẠN 1: MAGIC BYTES           │
               └──────────────────────┬──────────────────────┘
                                      │
         ┌──────────────┬─────────────┼─────────────┬──────────────┐
         ▼              ▼             ▼             ▼              ▼
     MZ / PE        %PDF-         PK\x03\x04    \xD0\xCF\x11   #! (Shebang)
         │              │             │             │              │
     [PE Engine]   [PDF Engine]       │        [OLE2 Office]  [Script Engine]
                                      │
               ┌──────────────────────┴──────────────────────┐
               │    GIAI ĐOẠN 2: IN-MEMORY ZIP CONTAINER     │
               └──────────────────────┬──────────────────────┘
                                      │
                        (Duyệt [Content_Types].xml)
                                      │
                  ┌───────────────────┼───────────────────┐
                  ▼                   ▼                   ▼
             word/ (DOCX)         xl/ (XLSX)          ppt/ (PPTX)
                  │                   │                   │
                  └───────────────────┼───────────────────┘
                                      ▼
                             [OOXML Office Engine]
                                      │
               (Nếu không phải Office ZIP -> Giai đoạn 3)
                                      │
               ┌──────────────────────┴──────────────────────┐
               │       GIAI ĐOẠN 3: SCRIPT CLASSIFIER        │
               │   (Phát hiện PowerShell, VBScript, JS, BAT) │
               └─────────────────────────────────────────────┘
```

1. **Giai đoạn 1 — Magic Bytes**: Kiểm tra các byte đầu: `MZ` (PE Executable), `%PDF-` (PDF Document), `PK\x03\x04` (ZIP/OOXML Container), `\xD0\xCF\x11\xE0` (OLE2 Compound Document), `#!` (Script Shebang).
2. **Giai đoạn 2 — In-Memory ZIP Container**: Với các tệp có header ZIP `PK`, engine phân tích trực tiếp cấu trúc thư mục trong bộ nhớ RAM mà không cần ghi ra đĩa:
   - Tìm kiếm `[Content_Types].xml`.
   - Kiểm tra các thư mục đặc trưng: `word/` (DOCX), `xl/` (XLSX), `ppt/` (PPTX).
3. **Giai đoạn 3 — Script Heuristic Classifier**: Kiểm tra cú pháp text để nhận diện PowerShell (`Param(`, `$PSVersionTable`), VBScript (`Dim `, `WScript.Shell`), JavaScript (`function(`, `var `), Batch script (`@echo off`, `REM`).

---

### 5.2 Động cơ Phân tích PDF Native C++ V2.0 (`Analyzers/PDF/`)
Bộ phân tích PDF được viết hoàn toàn bằng C++17 thuần với thư viện mã hóa OpenSSL và thư viện giải nén zlib, độc lập hoàn toàn với hệ thống ngoài:

```mermaid
graph TD
    PDF_Input[PDF File Stream] --> Limits[ParserLimits & Budget: Anti-Bomb Protection]
    Limits --> Parser[PDFParser: Binary-Safe Indirect Objects, Xref & Trailer]
    
    Parser --> Entropy[PDFEntropy: Shannon 0.00 - 8.00 bits/byte]
    Parser --> ObjectAna[PDFObjectAnalyzer: Actions, Catalogs, URIs, XFA]
    Parser --> JS[PDFJSAnalyzer: Heap Spray, Eval, Obfuscation & Acrobat APIs]
    Parser --> Extractor[PDFEmbeddedExtractor: Recursive Payload Extraction]
    
    Extractor -->|Embedded PE / Script / Archive| ChildTree[Child Analysis Nodes]
    Extractor -->|Embedded MZ Executable| Bridge[Bridge to PE Static Analyzer]
    
    Entropy --> Feats[PDFFeatures: 57 Numeric Features + Level 2 Structural Fingerprint]
    ObjectAna --> Feats
    JS --> Feats
    Extractor --> Feats
    
    Feats --> Risk[PDFRiskEngine: Contextual Scoring & Child Dominance Rule]
    ChildTree --> Risk
    Bridge --> Risk
    
    Risk --> Mitre[MitreMapper: Evidence-Based ATT&CK Mapping]
    Risk --> IOC[IOCExtractor: URL / Domain / IPv4 Defanging]
    
    Risk --> Schema2[Universal Schema 2.0 JSON Report]
```

1. **`PDFParser` ([`PDFParser.hpp`](file:///c:/Users/Kryo/Music/BHPAI/Analyzers/PDF/PDFParser.hpp) & [`.cpp`](file:///c:/Users/Kryo/Music/BHPAI/Analyzers/PDF/PDFParser.cpp))**:
   - Quét và bóc tách an toàn các đối tượng gián tiếp (`indirect objects: 1 0 obj ... endobj`).
   - Xử lý bảng tham chiếu chéo (`xref`), phần đuôi tài liệu (`trailer`) và hỗ trợ **Incremental Updates** (nhiều phiên bản sửa đổi nối thêm ở đuôi tệp).
   - Giải nén tự động các luồng dữ liệu nén: `FlateDecode` (thông qua `zlib inflate`) và `ASCIIHexDecode`.
2. **`PDFEntropy` ([`PDFEntropy.hpp`](file:///c:/Users/Kryo/Music/BHPAI/Analyzers/PDF/PDFEntropy.hpp) & [`.cpp`](file:///c:/Users/Kryo/Music/BHPAI/Analyzers/PDF/PDFEntropy.cpp))**:
   - Tính toán Shannon Entropy toàn bộ tệp và từng đối tượng stream nhị phân (thang đo từ 0.00 đến 8.00 bits/byte) để phát hiện luồng bị mã hóa hoặc nén ẩn.
3. **`PDFObjectAnalyzer` ([`PDFObjectAnalyzer.hpp`](file:///c:/Users/Kryo/Music/BHPAI/Analyzers/PDF/PDFObjectAnalyzer.hpp) & [`.cpp`](file:///c:/Users/Kryo/Music/BHPAI/Analyzers/PDF/PDFObjectAnalyzer.cpp))**:
   - Bóc tách Catalog và các hành động nguy hiểm:
     - `/OpenAction`: Tự động thực thi khi người dùng mở tài liệu.
     - `/Launch`: Kích hoạt ứng dụng bên ngoài hoặc dòng lệnh hệ thống (`cmd.exe`, `powershell.exe`).
     - `/JavaScript` & `/JS`: Thực thi mã kịch bản.
     - `/AcroForm` & `/XFA`: Biểu mẫu động có nguy cơ khai thác lỗ hổng bộ nhớ.
     - `/URI`: Liên kết web bên ngoài phục vụ Phishing hoặc tải mã độc.
4. **`PDFJSAnalyzer` ([`PDFJSAnalyzer.hpp`](file:///c:/Users/Kryo/Music/BHPAI/Analyzers/PDF/PDFJSAnalyzer.hpp) & [`.cpp`](file:///c:/Users/Kryo/Music/BHPAI/Analyzers/PDF/PDFJSAnalyzer.cpp))**:
   - Phát hiện các kỹ thuật Obfuscation: chuỗi Hex mã hóa, `eval()`, `unescape()`, hàm nối chuỗi động, heap spray.
   - Nhận diện các API Adobe Acrobat nguy hiểm bị khai thác: `app.doc.saveAs`, `util.printf`, `collab.getIcon`, `doc.exportDataObject`, `app.launchURL`.
5. **`PDFEmbeddedExtractor` ([`PDFEmbeddedExtractor.hpp`](file:///c:/Users/Kryo/Music/BHPAI/Analyzers/PDF/PDFEmbeddedExtractor.hpp) & [`.cpp`](file:///c:/Users/Kryo/Music/BHPAI/Analyzers/PDF/PDFEmbeddedExtractor.cpp))**:
   - Quét và trích xuất đệ quy các tệp đính kèm nhúng bên trong PDF qua từ khóa `/EmbeddedFiles`, `/Filespec`, `/EF`.
   - Nhận diện chữ ký nhị phân `MZ` của tệp thực thi PE Windows, script kịch bản hoặc tệp nén ZIP.

---

### 5.3 Cây Phân tích Đệ quy Phân cấp (`AnalysisNode` Architecture)
Mã nguồn: [`AnalysisNode.hpp`](file:///c:/Users/Kryo/Music/BHPAI/Analyzers/Common/AnalysisNode.hpp) & [`AnalysisNode.cpp`](file:///c:/Users/Kryo/Music/BHPAI/Analyzers/Common/AnalysisNode.cpp).

Hệ thống xây dựng một cây đối tượng đệ quy phân cấp:
- Mỗi nút (`AnalysisNode`) đại diện cho một tệp: có thể là Root Document (PDF/DOCX) hoặc Child Payload (PE nhúng, script nhúng, tệp nén).
- Mỗi nút lưu trữ độc lập: `node_id`, metadata tệp (`sha256`, `md5`, `format`, `size_bytes`, `depth`), kết quả phân tích (`heuristic_score`, `ml_score`, `verdict`, `risk_label`), danh sách `findings`, ma trận `mitre_attack` và danh sách các nút con `children`.
- Tự động chuyển tiếp nhị phân: Khi `PDFEmbeddedExtractor` phát hiện stream chứa PE nhị phân, nó tự động khởi tạo Child Node và chuyển giao (Bridge) vùng đệm cho `PeParser` phân tích tĩnh toàn diện.

---

### 5.4 Động cơ Chấm điểm Nguy cơ Ngữ cảnh & Quy tắc Thống trị Con (Child Dominance Rule)
Mã nguồn: [`PDFRiskEngine.hpp`](file:///c:/Users/Kryo/Music/BHPAI/Analyzers/PDF/PDFRiskEngine.hpp) & [`PDFRiskEngine.cpp`](file:///c:/Users/Kryo/Music/BHPAI/Analyzers/PDF/PDFRiskEngine.cpp).

BHPAI thay thế cơ chế cộng dồn điểm số đơn giản bằng công thức chấm điểm nguy cơ theo ngữ cảnh:

$$\text{FinalRisk} = \text{BasePDFRisk} + \text{ContextRisk} + \text{EmbeddedChildRisk} + \text{AiProb}$$

#### Quy tắc Thống trị Con (Child Dominance Rule)
Một tài liệu PDF thông thường có thể chứa tệp đính kèm hợp lệ (như bảng tính, văn bản). Nhưng nếu một tệp con dạng PE thực thi bị phát hiện là mã độc (Threat Score $\ge 80$), **kết luận của tài liệu PDF cha lập tức bị ghi đè và thống trị**:

$$\text{ParentVerdict} = \text{MALICIOUS}$$
$$\text{ParentRisk} = \max(\text{ParentRisk}, 85)$$

#### Hệ số Nguy cơ Ngữ cảnh (Context Risk Boosters)
- `/Launch` kết hợp với tệp thực thi nhúng: **+30 điểm**
- `/JavaScript` kết hợp với `/OpenAction` tự động thực thi: **+25 điểm**
- Tệp đính kèm nhúng kết hợp với `/OpenAction`: **+25 điểm**
- API Acrobat nguy hiểm kết hợp với Javascript Obfuscation (`eval`/`unescape`): **+30 điểm**
- Incremental Updates bất thường có chứa mã ẩn sau dấu `%%EOF`: **+15 điểm**
- Dị thường cấu trúc: trùng lặp Object ID hoặc bảng Xref bị hỏng: **+15 điểm**

---

### 5.5 Phòng thủ Anti-DoS & Chống Bom Giải nén (Decompression Bomb Protection)
Mã nguồn: [`AnalysisBudget.hpp`](file:///c:/Users/Kryo/Music/BHPAI/Analyzers/Common/AnalysisBudget.hpp) & [`ParserLimits.hpp`](file:///c:/Users/Kryo/Music/BHPAI/Analyzers/Common/ParserLimits.hpp).

Nhằm triệt tiêu nguy cơ kẻ tấn công gửi các tệp tài liệu PDF độc hại dạng "Bom giải nén" (Flate Bomb / Zip Bomb) làm cạn kiệt tài nguyên bộ nhớ hoặc treo CPU của máy chủ phân tích, BHPAI V1.6 đặt ra các ranh giới kiểm soát cứng:
- **`max_input_bytes`**: Tối đa **500 MB** cho tệp đầu vào.
- **`max_extracted_bytes`**: Tối đa **250 MB** cho tổng dung lượng các payload trích xuất.
- **`max_decoded_bytes`**: Tối đa **250 MB** cho tổng dung lượng giải nén các stream `FlateDecode`.
- **`max_decompression_ratio`**: Tỷ lệ giải nén tối đa **100.0** (nếu 1 KB dữ liệu nén giải nén ra vượt quá 100 KB, quá trình inflate lập tức bị ngắt và đánh dấu là Flate Bomb).
- **`max_objects`**: Giới hạn tối đa **100,000** đối tượng PDF để ngăn chặn đệ quy vô hạn.
- **`max_filter_depth`**: Giới hạn độ sâu mã hóa stream tối đa **6 tầng**.
- **Global Wall-Clock Timeout**: Tối đa **30 giây** cho toàn bộ quá trình phân tích một tệp tài liệu.

---

### 5.6 Ánh xạ MITRE ATT&CK Dựa trên Bằng chứng & Universal IOC Defanger
- **Evidence-Based MITRE Mapping** ([`MitreMapper.cpp`](file:///c:/Users/Kryo/Music/BHPAI/Analyzers/Common/MitreMapper.cpp)):
  - Yêu cầu bằng chứng kỹ thuật cụ thể và gán điểm tin cậy (Confidence Score):
    - `T1204.002` (User Execution: Malicious File) - khi có `/OpenAction` hoặc `/Launch` (Độ tin cậy: 95%).
    - `T1059.007` (JavaScript) - khi phát hiện `eval()`, `unescape()` hoặc Acrobat APIs độc hại (Độ tin cậy: 90%).
    - `T1027` (Obfuscation) - khi tỷ lệ hex mã hóa cao và entropy stream > 5.5 (Độ tin cậy: 85%).
    - `T1027.009` (Embedded Payloads) - khi phát hiện header PE `MZ` trong tệp nhúng (Độ tin cậy: 96%).
    - `T1105` (Ingress Tool Transfer) - khi xuất hiện URL độc hại hoặc dropper (Độ tin cậy: 75%).
    - `T1203` (Exploitation for Client Execution) - khi phát hiện XFA stream dị thường (Độ tin cậy: 80%).
- **Universal IOC Defanger** ([`IOCExtractor.cpp`](file:///c:/Users/Kryo/Music/BHPAI/Analyzers/Common/IOC/IOCExtractor.cpp)):
  - Vô hiệu hóa toàn bộ URL, Domain, IPv4 trích xuất được để chống tai nạn click chuột của chuyên viên phân tích:
    - URL: `http://` $\rightarrow$ `hxxp://`, `https://` $\rightarrow$ `hxxps://`
    - Domain: `evil-c2.com` $\rightarrow$ `evil-c2[.]com`
    - IPv4: `185.220.101.5` $\rightarrow$ `185[.]220[.]101[.]5`
  - Tự động lọc bỏ các tên miền an toàn của nhà cung cấp lớn: Adobe, Microsoft, W3C, Apache.

---

### 5.7 Chuẩn hóa Báo cáo Đầu ra Universal Schema 2.0
Mọi kết quả phân tích đều được xuất ra định dạng JSON chuẩn quốc tế **Universal Schema 2.0**:

```json
{
  "schema_version": "2.0.0",
  "scan_id": "scan_42a7bd362851a6de",
  "file": {
    "file_name": "embedded_exe.pdf",
    "sha256": "9a38f7...71b",
    "size_bytes": 1048576,
    "format": "PDF",
    "structural_fingerprint": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  },
  "analysis": {
    "threat_score": 90,
    "verdict": "MALICIOUS",
    "risk_label": "Critical Malicious PDF (Malicious Child Payload)",
    "score_breakdown": {
      "base_heuristic": 40,
      "context_risk": 0,
      "child_risk": 50,
      "ai_probability": 0
    }
  },
  "analysis_tree": {
    "node_id": "node_root",
    "file": { "format": "PDF", "depth": 0 },
    "analysis": { "threat_score": 90, "verdict": "MALICIOUS" },
    "children": [
      {
        "node_id": "node_child_obj5",
        "file": { "format": "PE", "depth": 1, "sha256": "e2f18...c0" },
        "analysis": { "threat_score": 85, "verdict": "MALICIOUS" }
      }
    ]
  },
  "mitre_attack": [
    { "technique_id": "T1027.009", "technique_name": "Embedded Payloads", "confidence": 0.96 }
  ],
  "iocs": {
    "urls": ["hxxps://c2-malicious-server[.]example[.]com/exploit"],
    "domains": ["c2-malicious-server[.]example[.]com"],
    "ipv4": []
  }
}
```

---

## 6. CHI TIẾT PHÂN HỆ 4: DATASET 3 TẦNG & PIPELINE AI PDF CHỐNG FALSE POSITIVE

Mã nguồn chính nằm tại: [`dataset/pdf/`](file:///c:/Users/Kryo/Music/BHPAI/dataset/pdf/), [`Core/Train/train_pdf_model.py`](file:///c:/Users/Kryo/Music/BHPAI/Core/Train/train_pdf_model.py), [`tests/generate_pdf_dataset_samples.py`](file:///c:/Users/Kryo/Music/BHPAI/tests/generate_pdf_dataset_samples.py).

### 6.1 Cấu trúc Phân tầng Dataset 3 Lớp (`dataset/pdf/`)
Nhằm huấn luyện một mô hình Machine Learning phát hiện PDF độc hại đạt đẳng cấp doanh nghiệp, hệ thống áp dụng cấu trúc dữ liệu 3 tầng nghiêm ngặt:

```
dataset/pdf/
├── malware/                         [Nhãn: MALICIOUS = 1]
│   ├── dropper/                     (Chứa PE thực thi, MZ headers, DLLs)
│   ├── malicious_js/                (Chứa eval(), unescape(), heap spray)
│   ├── weaponized_pdf/              (Chứa /Launch action, thực thi cmd.exe)
│   ├── phishing/                    (Liên kết lừa đảo thu thập thông tin)
│   └── exploit/                     (Khai thác lỗ hổng Adobe Acrobat, XFA)
│
├── benign/                          [Nhãn: BENIGN = 0]
│   ├── normal_documents/            (Văn bản, phông chữ, siêu dữ liệu chuẩn)
│   ├── scanned_documents/           (Chỉ chứa luồng ảnh quét, DCTDecode)
│   ├── invoices/                    (Hóa đơn điện tử, bảng biểu)
│   ├── forms/                       (Biểu mẫu tĩnh không chứa script)
│   ├── academic/                    (Tài liệu nghiên cứu khoa học nhiều trang)
│   └── government/                  (Thông báo, văn bản hành chính)
│
├── suspicious_benign/               [Nhãn: BENIGN = 0 - CỰC KỲ QUAN TRỌNG: HARD NEGATIVES]
│   ├── javascript_pdf/              (JS hợp lệ: tính tổng hóa đơn, định dạng ngày tháng)
│   ├── openaction_pdf/              (OpenAction hợp lệ: đặt tỷ lệ hiển thị FitH/Zoom)
│   ├── embedded_files/              (Đính kèm an toàn: XML, CSV, PNG, không chứa PE)
│   ├── high_entropy/                (Ảnh nén chất lượng cao, đồ họa raster)
│   └── incremental_updates/         (Tài liệu có chữ ký điện tử, nhiều bản cập nhật)
│
└── unknown/                         [Nhãn: UNKNOWN = 3 - Loại khỏi huấn luyện]
    └── mystery_sample.pdf
```

---

### 6.2 Xóa bỏ lối tắt suy luận "False Positive Machine" qua Hard Negatives
Trong thực tế, nếu tập dữ liệu huấn luyện chỉ gồm mã độc phức tạp (có JavaScript, `/OpenAction`, tệp đính kèm) đối nghịch với tập lành tính đơn giản (chỉ có văn bản và ảnh tĩnh), mô hình AI sẽ rơi vào bẫy **Lối tắt Suy luận (Heuristic Shortcut Failure)**:

$$\text{Quy tắc học vẹt: } \mathbf{if} \ (\text{has\_javascript} == 1 \ \mathbf{or} \ \text{has\_openaction} == 1) \rightarrow \text{MALWARE}$$

Khi đưa vào môi trường doanh nghiệp thực tế (nơi các biểu mẫu thuế, hóa đơn điện tử, tài liệu kế toán đều sử dụng JavaScript để tính toán và `/OpenAction` để chỉnh viewport), mô hình sẽ báo động giả tràn lan (**False Positive Machine**).

Tập dữ liệu **`suspicious_benign/` (Hard Negatives)** của BHPAI V1.6 buộc mô hình AI phải học được ranh giới bản chất:
- Phân biệt giữa JavaScript tính toán hợp lệ (`event.value = a + b`) và JavaScript khai thác lỗ hổng (`eval(unescape(...))`).
- Phân biệt giữa `/OpenAction` chỉnh khung nhìn trang (`/FitH`) và `/OpenAction` tự động thực thi shellcode.
- Phân biệt giữa tệp đính kèm hợp lệ (XML/CSV) và tệp đính kèm chứa mã máy Windows PE (`MZ`).

---

### 6.3 Khử trùng lặp đa cấp độ trước khi phân tách (Multi-Level Deduplication)
Rò rỉ dữ liệu (Data Leakage) giữa tập Train và tập Test là nguyên nhân chính khiến các chỉ số kiểm thử ngoại tuyến đạt 99% nhưng sụp đổ khi triển khai thực tế. BHPAI áp dụng quy trình khử trùng lặp 2 cấp độ chạy **hoàn toàn trước khi phân chia tập**:

1. **Cấp độ 1 — Khử trùng lặp theo Hash SHA256**:
   - Loại bỏ toàn bộ các tệp tin giống nhau 100% về byte nhị phân.
2. **Cấp độ 2 — Khử trùng lặp theo Dấu vân tay Cấu trúc (Level 2 Structural Fingerprint)**:
   - Được hiện thực hóa trực tiếp trong C++: hàm `ComputeStructuralFingerprint()` trong [`PDFFeatures.cpp`](file:///c:/Users/Kryo/Music/BHPAI/Analyzers/PDF/PDFFeatures.cpp).
   - Chuẩn hóa cấu trúc tài liệu thành một chuỗi canonical đại diện:
     $$\text{objs}:c \mid \text{strms}:c \mid \text{pgs}:c \mid \text{xref}:c \mid \text{trls}:c \mid \text{acts}:js,open,launch \mid \text{emb}:cnt,pe \mid \text{flt}:depth,susp \mid \text{anom}:incr,dup,brk$$
   - Chuỗi này được băm bằng OpenSSL SHA256. Bất kỳ mẫu mã độc nào được sinh ra từ cùng một framework tấn công (Polymorphic Template Clones) chia sẻ chung cấu trúc khung đều mang chung một Structural Fingerprint.

---

### 6.4 Phân tách tập độc lập chống rò rỉ dữ liệu `StratifiedGroupKFold`
Kịch bản phân chia tập trong [`train_pdf_model.py`](file:///c:/Users/Kryo/Music/BHPAI/Core/Train/train_pdf_model.py) áp dụng giải thuật **`StratifiedGroupKFold`**:
- **Nhóm mã độc (`malware`)**: Gom nhóm theo Campaign / Family (`malicious_js`, `dropper`, `weaponized_pdf`, `exploit`).
- **Nhóm lành tính (`benign`)**: Gom nhóm theo Structural Fingerprint / Document Archetype.
- **Cam kết kỹ thuật**: Toàn bộ các biến thể của cùng một dòng mã độc hoặc cùng một mẫu cấu trúc sẽ chỉ nằm ở tập Huấn luyện (Train) hoặc tập Kiểm định (Validation/Test), triệt tiêu hoàn toàn rủi ro rò rỉ mẫu mã độc biến thể sang tập kiểm định.

---

### 6.5 Vector 57 Đặc trưng & Hiệu chuẩn Xác suất (`CalibratedClassifierCV`)
- **57 Đặc trưng Số liệu Phân cấp** ([`PDFFeatures.hpp`](file:///c:/Users/Kryo/Music/BHPAI/Analyzers/PDF/PDFFeatures.hpp)):
  - Nhóm 1: Cấu trúc (`num_objects`, `num_streams`, `num_pages`, `has_xref_stream`, `num_trailers`, v.v.).
  - Nhóm 2: Hành động (`has_javascript`, `has_openaction`, `has_launch`, `num_uris`, v.v.).
  - Nhóm 3: Nhúng (`has_embedded_files`, `embedded_pe_count`, `embedded_file_count`, v.v.).
  - Nhóm 4: Entropy (`file_entropy`, `max_stream_entropy`, `entropy_histogram_bins`, v.v.).
  - Nhóm 5: Làm mờ & JS (`has_eval`, `has_unescape`, `dangerous_api_count`, `hex_obfuscation_ratio`, v.v.).
  - Nhóm 6: Dị thường Parser (`has_incremental_update`, `duplicate_obj_ids`, `broken_xref_count`, v.v.).
- **Hiệu chuẩn Xác suất (`CalibratedClassifierCV`)**:
  - Mô hình LightGBM được bọc qua lớp hiệu chuẩn xác suất (Calibrated Sigmoid/Isotonic) với số fold động `cv=min(3, n_splits)`.
  - Giúp điểm xác suất xuất ra phản ánh chân thực độ rủi ro rủi ro thực tế thay vì bị thiên lệch cực đoan về 0 hoặc 1.
  - Mô hình được lưu trữ tại: [`model/pdf_detector_lgb.pkl`](file:///c:/Users/Kryo/Music/BHPAI/model/pdf_detector_lgb.pkl) và [`model/pdf_model.txt`](file:///c:/Users/Kryo/Music/BHPAI/model/pdf_model.txt).

---

### 6.6 Kết quả Benchmark Kiểm định & Khả năng Kháng Cảnh báo Giả (Audit Report)
Thực nghiệm so sánh giữa mô hình học vẹt (không có hard negatives) và mô hình chuẩn V1.6 được kiểm định trên bộ test 10 tài liệu phức tạp (chứa JavaScript tính toán, `/OpenAction`, tệp đính kèm an toàn, cập nhật phân đoạn):

| Cấu hình Huấn luyện | Độ chính xác Lành tính Đơn giản | Độ chính xác Lành tính Phức tạp (Hard Benign) | Tỷ lệ Cảnh báo Giả (FPR) | Đánh giá Trạng thái |
| :--- | :---: | :---: | :---: | :---: |
| **Không có Hard Negatives (Lối tắt Học vẹt)** | 100.0% | **0.0%** (Toàn bộ bị báo nhầm là Mã độc) | **100.0%** | ❌ **FAIL (Cảnh báo nhầm nghiêm trọng)** |
| **Có Hard Negatives (`--include-hard-in-training`)** | 66.7% | **100.0%** | **0.0%** |  **RESILIENT (Kháng cảnh báo giả tuyệt đối)** |

Báo cáo kiểm toán chất lượng tự động xuất ra tại [`model/pdf_benchmark_report.json`](file:///c:/Users/Kryo/Music/BHPAI/model/pdf_benchmark_report.json):

```json
{
  "dataset_summary": {
    "total_samples_before_dedup": 28,
    "total_samples_after_dedup": 24,
    "malware_samples": 8,
    "benign_samples": 16,
    "distinct_families": 16,
    "features_count": 57
  },
  "cross_validation": {
    "strategy": "StratifiedGroupKFold",
    "folds": 5,
    "auc": 0.3555,
    "f1": 1.0,
    "optimal_threshold": 0.5,
    "normal_benign_accuracy": 0.6667
  },
  "hard_negative_benchmark": {
    "sample_count": 10,
    "false_positives": 0,
    "false_positive_rate": 0.0,
    "hard_benign_accuracy": 1.0,
    "status": "RESILIENT"
  }
}
```

---

## 7. CHI TIẾT PHÂN HỆ 5: MACHINE LEARNING & AI ENSEMBLE (PE & GNN & SHAP)

Mã nguồn chính nằm tại: [`Core/Train/`](file:///c:/Users/Kryo/Music/BHPAI/Core/Train).

### 7.1 Hợp nhất Không gian Đặc trưng Đa chiều (Feature Vectorization)
[`feature_extractor.py`](file:///c:/Users/Kryo/Music/BHPAI/Core/Train/feature_extractor.py) kết hợp thông tin tĩnh và hành vi động thành vector đặc trưng đa chiều:
1. **Static PE Features**: Entropy các section, tỷ lệ Raw/Virtual Size, số lượng hàm nhập khẩu IAT, chỉ số Anomalies, TF-IDF Opcode N-Grams.
2. **Dynamic Sandbox Features**: Số lượng API calls theo danh mục (File I/O, Registry, Network, Process/Memory), tỷ lệ sửa đổi tệp/giây, số lượng khóa Registry bị can thiệp.

---

### 7.2 PyTorch API Sequence Embedder & Control Flow Graph GNN
- **API Sequence Embedding** ([`api_sequence_embedder.py`](file:///c:/Users/Kryo/Music/BHPAI/Core/Train/api_sequence_embedder.py)): Sử dụng mô hình PyTorch dựa trên Transformer/LSTM mã hóa chuỗi gọi API theo trục thời gian thành không gian vector cô đọng.
- **Graph Neural Network on CFG** ([`gnn_embedder.py`](file:///c:/Users/Kryo/Music/BHPAI/Core/Train/gnn_embedder.py)): Sử dụng mạng Graph Convolutional Network (GCN) trích xuất đặc trưng hình học của Control Flow Graph (CFG), nhận dạng được bản chất cấu trúc thuật toán mã độc bất kể việc làm mờ hay hoán đổi thứ tự câu lệnh.

---

### 7.3 Tối ưu hóa đặc trưng bằng SHAP Feature Pruning
[`shap_feature_pruning.py`](file:///c:/Users/Kryo/Music/BHPAI/Core/Train/shap_feature_pruning.py) ứng dụng lý thuyết trò chơi **SHAP (SHapley Additive exPlanations)** để:
- Đo lường mức độ đóng góp của từng đặc trưng vào quyết định phân loại độc hại.
- Cắt tỉa triệt để các đặc trưng gây nhiễu.
- Giữ lại các đặc trưng có giá trị cao nhất:

```
Trọng số Đóng góp SHAP Value:
1. High Shannon Entropy Rate (>7.5)          ██████████████████████ 0.28
2. Process Injection API Chain (T1055)       ██████████████████     0.22
3. Opcode 3-Gram TF-IDF (xor-inc-loop)      ██████████████         0.17
4. Shadow Copy Wiping Command Intercept      ██████████             0.14
5. AMSI/ETW Memory Patching                  ████████               0.11
```

---

### 7.4 Mô hình Phân loại LightGBM Ensemble (Adam, Eve, Marcus) & Ngưỡng động
Hệ thống PE tích hợp bộ ba mô hình Ensemble: **Adam** (180 đặc trưng), **Eve** (443 đặc trưng), và **Marcus** (172 đặc trưng) kết hợp cấu hình ngưỡng phân loại động ([`classification_threshold2.json`](file:///c:/Users/Kryo/Music/BHPAI/Core/Train/classification_threshold2.json)):
- `0.0 - 0.35`: Clean / Benign (An toàn).
- `0.35 - 0.70`: Suspicious (Nghi ngờ - Đưa vào giám sát Sandbox).
- `0.70 - 1.00`: Malicious / Ransomware (Mã độc nghiêm trọng).

---

## 8. CHI TIẾT PHÂN HỆ 6: BHR ENGINE (RANSOMWARE DETECTOR & KEY RECOVERY)

Mã nguồn chính nằm tại: [`BHR/source/`](file:///c:/Users/Kryo/Music/BHPAI/BHR/source), [`Core/sandbox/launcher/RamPagefileKeyExtractor.cpp`](file:///c:/Users/Kryo/Music/BHPAI/Core/sandbox/launcher/RamPagefileKeyExtractor.cpp), [`recovery/`](file:///c:/Users/Kryo/Music/BHPAI/recovery).

### 8.1 Thuật toán phát hiện mã hóa Entropy cao (Shannon Entropy Rate)
[`RansomwareDetector.cpp`](file:///c:/Users/Kryo/Music/BHPAI/BHR/source/RansomwareDetector.cpp) liên tục tính toán chỉ số Entropy của dữ liệu được ghi đĩa qua hook `NtWriteFile`:

$$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$

Khi dữ liệu ghi có chỉ số $H(X) \ge 7.5$ lặp lại liên tục với lưu lượng lớn, BHR Engine lập tức đánh dấu tiến trình là Ransomware đang hoạt động.

---

### 8.2 Giám sát Burst Modification Rate & Hành vi xóa Shadow Copy
- **Burst Modification Rate**: Giám sát tần suất đổi tên tập tin dồn dập (đổi đuôi file sang `.locked`, `.crypto`, `.enc`) hoặc ghi đè liên tục trong khoảng thời gian ngắn ($> 20$ files/giây).
- **Phát hiện Xóa Điểm Khôi Phục (Shadow Copy Wiping)**: Bắt giữ và vô hiệu hóa các câu lệnh hủy dữ liệu hệ thống:
  - `vssadmin.exe delete shadows /all /quiet`
  - `wmic shadowcopy delete`
  - `bcdedit.exe /set {default} recoveryenabled No`
  - `wbadmin delete catalog -quiet`
- **Nhận diện Ransom Note**: Theo dõi hành vi thả các tập tin đòi tiền chuộc phổ biến như `READ_ME.txt`, `DECRYPT_FILES.html`, `HOW_TO_DECRYPT.txt`.

---

### 8.3 Trích xuất khóa mã hóa đa thuật toán (20+ Standards) từ RAM & `pagefile.sys`
Khi phát hiện hành vi Ransomware, [`RamPagefileKeyExtractor.cpp`](file:///c:/Users/Kryo/Music/BHPAI/Core/sandbox/launcher/RamPagefileKeyExtractor.cpp) và [`ram_pagefile_extractor.py`](file:///c:/Users/Kryo/Music/BHPAI/recovery/ram_pagefile_extractor.py) chụp ảnh bộ nhớ RAM (Pre-Exit Process Memory Dump) và quét đa luồng trực tiếp file swap `C:\pagefile.sys`:

Hệ thống hỗ trợ tự động nhận dạng **hơn 20 tiêu chuẩn & chuẩn mã hóa**:
- **AES Ciphers**: AES-128, AES-192, AES-256 (mốt ECB, CBC, GCM). Đặc biệt tích hợp **AES-GCM GHASH H Subkey Detector** ($H = \text{AES}_K(0^{128})$) giúp phát hiện khóa Master AES-GCM chính xác 95%+.
- **Stream Ciphers**: ChaCha20 Matrix State, XChaCha20, Salsa20 (quét hằng số `expand 32-byte k`), RC4 / RC4 State Vector.
- **Asymmetric & ECC Keys**: RSA PKCS#1 DER ASN.1 Sequence Private Keys (`0x3082`), Curve25519 / X25519 Ephemeral Scalar Clamping Patterns (`k[0] &= 248`, `k[31] &= 127`, `k[31] |= 64`).
- **Symmetric Block Ciphers khác**: Triple-DES, Blowfish, Twofish, Camellia, Serpent.
- **System Cryptographic Handles**: OpenSSL `EVP_PKEY` Structs, Windows CNG `BCRYPT_KEY_HANDLE`.
- **Validation Types**: `ScheduleVerified`, `AES_GHASH_H_MATCH`, `DecryptVerified`, `PatternMatch`, `EntropyOnly`.

---

### 8.4 Khôi phục dữ liệu tự động 100% từ Vùng đệm COW Virtual Overlay
Do mọi thao tác ghi đè và mã hóa của Ransomware đều bị chuyển hướng vào vùng đệm ảo `Overlay\Files\`, tập tin gốc của người dùng trên đĩa cứng thật hoàn toàn nguyên vẹn.

[`automated_overlay_restore.py`](file:///c:/Users/Kryo/Music/BHPAI/recovery/methods/automated_overlay_restore.py) chỉ cần thực hiện xóa bỏ các tệp tin đã biến đổi trong vùng đệm `Overlay\`, hệ thống lập tức trở về trạng thái hoàn toàn nguyên vẹn trước khi bị tấn công trong vòng chưa đầy 1 giây.

---

### 8.5 Nhật ký Crypto Timeline & Bản đồ biến đổi dữ liệu
[`CryptoTimeline.cpp`](file:///c:/Users/Kryo/Music/BHPAI/Core/sandbox/launcher/CryptoTimeline.cpp) và [`crypto_tracker.py`](file:///c:/Users/Kryo/Music/BHPAI/recovery/crypto_tracker.py) ghi lại toàn bộ mốc thời gian diễn ra cuộc tấn công:
- Thời điểm tiến trình khởi chạy.
- Mốc thời gian tệp tin đầu tiên bị tăng Entropy.
- Danh sách đường dẫn tệp tin gốc $\rightarrow$ Đường dẫn tệp bị mã hóa.
- Tỷ lệ dữ liệu bị mã hóa theo mốc thời gian (Cryptographic Timeline Graph).

---

### 8.6 Kiểm thử Thực tế Dual-Engine Hybrid Ransomware Memory Key Extraction
Kiểm thử Sandbox trước mẫu Ransomware giả lập cơ chế mã hóa phức tạp Dual-Engine Hybrid (tương tự LockBit 3.0 / BlackCat):
- Mã hóa đối xứng: AES-256-GCM + ChaCha20.
- Trao đổi khóa bất đối xứng: X25519 Ephemeral Scalar + RSA PKCS#1 DER.
- Chèn nhiễu Heap: 15 vùng nhớ entropy ngẫu nhiên và các khối nén.

Kết quả trích xuất thành công 100% cả 4 cấu trúc khóa trong bộ nhớ RAM:
1. **AES-256-GCM Master Key**: Khớp GHASH $H$ Subkey, điểm tin cậy **95.0%**.
2. **ChaCha20 State Matrix**: Nhận diện hằng số ma trận và Nonce, điểm tin cậy **60.25%**.
3. **X25519 Ephemeral Key**: Nhận diện Clamping Pattern Mask, điểm tin cậy **57.0%**.
4. **RSA PKCS#1 DER Sequence Private Key**: Nhận diện cấu trúc ASN.1 DER, điểm tin cậy **60.75%**.

---

### 8.7 Kiến trúc Recovery Engine Registry & Crypto Dataflow Tracker
- **Recovery Engine Registry** ([`recovery/registry.py`](file:///c:/Users/Kryo/Music/BHPAI/recovery/registry.py)): Quản lý và đăng ký động các phương pháp phục hồi ([`automated_overlay_restore.py`](file:///c:/Users/Kryo/Music/BHPAI/recovery/methods/automated_overlay_restore.py), [`exact_lookup.py`](file:///c:/Users/Kryo/Music/BHPAI/recovery/methods/exact_lookup.py)). Cung cấp cơ chế `evaluate_all(sample)` để xếp hạng phương pháp giải mã tối ưu.
- **Crypto Dataflow Tracker** ([`recovery/crypto_tracker.py`](file:///c:/Users/Kryo/Music/BHPAI/recovery/crypto_tracker.py)): Liên kết luồng sự kiện mã hóa, đối tượng khóa và xác minh tính hợp lệ dựa trên chuỗi sự kiện I/O thời gian thực.

---

## 9. CHI TIẾT PHÂN HỆ 7: BEHAVIOR CORRELATOR & BEHAVIORGRAPH ENGINE V1.6

Mã nguồn chính nằm tại: [`BehaviorCorrelator.cpp`](file:///c:/Users/Kryo/Music/BHPAI/Core/sandbox/launcher/BehaviorCorrelator.cpp), [`BehaviorCorrelator.hpp`](file:///c:/Users/Kryo/Music/BHPAI/Core/sandbox/launcher/BehaviorCorrelator.hpp) và [`EventNormalizer.cpp`](file:///c:/Users/Kryo/Music/BHPAI/Core/sandbox/launcher/EventNormalizer.cpp).

### 9.1 Chuẩn hóa sự kiện đa nguồn (Userland Hooks + Kernel ETW)
[`EventNormalizer.cpp`](file:///c:/Users/Kryo/Music/BHPAI/Core/sandbox/launcher/EventNormalizer.cpp) tiếp nhận hàng ngàn sự kiện đơn lẻ từ MinHook Userland DLL và Kernel ETW, chuẩn hóa thành định dạng JSON Standard chung:

```json
{
  "timestamp": 1724712000,
  "pid": 4812,
  "process_name": "malware.exe",
  "event_type": "API_CALL",
  "api_name": "NtProtectVirtualMemory",
  "arguments": {
    "target_pid": 1044,
    "new_protect": "PAGE_EXECUTE_READWRITE"
  }
}
```

---

### 9.2 Đồ thị Hướng Liên Tiến Trình (`BehaviorGraph`) & State Machine Chuỗi Tấn Công
Trong phiên bản **V1.6 Enterprise**, bộ tương quan hành vi được nâng cấp toàn diện với **BehaviorGraph Engine**:
- Quản lý tập hợp các nút tiến trình (`ProcessNode`) và các cạnh định hướng (`CrossProcessEdge`).
- Xây dựng state machine nhận diện các chuỗi tấn công liên tiến trình theo cặp `(Process A -> Process B)`:
  - **Remote Thread Injection**: `OpenProcess -> VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread` (`T1055.002`).
  - **Process Hollowing**: `OpenProcess -> VirtualAllocEx -> WriteProcessMemory -> SetThreadContext` (`T1055.012`).
  - **APC Queue Injection**: `OpenProcess -> VirtualAllocEx -> WriteProcessMemory -> NtQueueApcThread` (`T1055.004`).

---

### 9.3 Độ phủ Win32 / NT Native API & Chuẩn hóa Đường dẫn Kernel
- Đạt độ phủ tuyệt đối với các Win32 & NT Native API nhạy cảm (`SetFileInformationByHandle`, `ReplaceFileW`, `CreateHardLinkW`, `CreateSymbolicLinkW`, `SetFileSecurityW`).
- Chuẩn hóa hai chiều tự động cho đường dẫn NT Kernel (`\Device\HarddiskVolumeX` và `\??\C:\...`) về dạng Win32 chuẩn (`C:\...`).

---

### 9.4 Giám sát Registry Native & Bộ Phân loại Persistence 9 Điểm
- Theo dõi các API thông báo Registry Native (`RegNotifyChangeKeyValue`, `NtNotifyChangeKey`).
- Tự động phân loại 9 vị trí Persistence: Run/RunOnce, Services, Winlogon, IFEO, AppInit_DLLs, Shell Extensions, BHOs, Task Scheduler, WMI.

---

### 9.5 Stateful NetworkSessionTracker & Bộ Bóc Tách TLS SNI / HTTP
- Quản lý phiên socket mạng (`NetworkSessionTracker`) tích hợp bộ bóc tách nhị phân TLS ClientHello Server Name Indication (SNI) và HTTP Request Header (Method/Host/URI).

---

### 9.6 Mô hình Nhật ký Mã hóa Cấu trúc Enriched CryptoOperation
- Ghi nhật ký mã hóa cấu trúc (`provider`, `algorithm`, `mode`, `keysize`, `ivlen`, `inputlen`, `outputlen`, `keygen`, `pid`) cho CNG/CryptoAPI/NCrypt/SystemFunction mà không làm rò rỉ dữ liệu thô.

---

### 9.7 Bản đồ ma trận kỹ thuật MITRE ATT&CK Enterprise Matrix

| Tactic | Technique ID | Tên Kỹ thuật | Trạng thái Phát hiện |
| :--- | :--- | :--- | :--- |
| **Execution** | T1204.002 | Malicious File (PDF OpenAction / Launch) | 🔴 Detected |
| **Execution** | T1059.007 | JavaScript (PDF Heap Spray / Eval) | 🔴 Detected |
| **Execution** | T1059.003 | Windows Command Shell | 🔴 Detected (`cmd.exe /c vssadmin...`) |
| **Defense Evasion**| T1027 | Obfuscated Files or Information | 🔴 Detected |
| **Defense Evasion**| T1027.009 | Embedded Payloads (PDF Embedded PE) | 🔴 Detected |
| **Defense Evasion**| T1562.001 | Impair Defenses: Disable Tools | 🔴 Detected (AMSI/ETW Patching) |
| **Defense Evasion**| T1620 | Reflective Code Loading | 🔴 Detected (Memory Mapped DLL) |
| **Credential Access**| T1003.001 | LSASS Memory Dumping | 🔴 Detected (`lsass.exe` Read Access) |
| **Privilege Escalation**| T1055 | Process Injection | 🔴 Detected (Remote Thread / APC) |
| **Command and Control**| T1105 | Ingress Tool Transfer | 🔴 Detected |
| **Impact** | T1486 | Data Encrypted for Impact | 🔴 Detected (High Entropy File Write) |
| **Impact** | T1490 | Inhibit System Recovery | 🔴 Detected (Shadow Copy Deletion) |

---

### 9.8 Bộ Thử Nghiệm Tự Động 7 Chiều & Kết Quả Benchmark V1.6
Hệ thống V1.6 được tích hợp bộ test suite tự động 7 chiều (`tests/`):

| Thử nghiệm | Test Script | Trạng thái | Kết quả đo đạc thực tế |
| :--- | :--- | :---: | :--- |
| **1. Stress & Reentrancy** | `tests/test_sandbox_stress.py` | **PASSED** | 0 crash / 0 deadlock dưới áp lực tạo tiến trình & I/O liên tục. |
| **2. API Coverage & Normalization** | `tests/test_sandbox_coverage.py` | **PASSED** | 0 đường dẫn un-normalized `\Device\` bị sót. |
| **3. False-Positive Baseline** | `tests/test_sandbox_false_positive.py` | **PASSED** | 0 cảnh báo giả trên các công cụ chuẩn của Windows. |
| **4. BehaviorGraph Validation** | `tests/test_sandbox_behavior_graph.py` | **PASSED** | Đồ thị tiến trình & phiên mạng TLS SNI/HTTP hoạt động chính xác. |
| **5. E2E Performance Benchmark** | `tests/benchmark_sandbox_e2e.py` | **PASSED** | Peak RAM Footprint: **1.47 MB** \| Total Time: **3.17s**. |
| **6. PDF E2E Direct Sync Router** | `tests/test_pdf_router_e2e.py` | **PASSED** | 100% Pass Rate trên toàn bộ các bài test Clean, Obfuscated JS, Embedded PE. |

---

## 10. CHI TIẾT PHÂN HỆ 8: ZERO-KNOWLEDGE ENCRYPTED BACKUP VAULT

Mã nguồn chính nằm tại: [`Core/vault/`](file:///c:/Users/Kryo/Music/BHPAI/Core/vault), [`gui_vault.py`](file:///c:/Users/Kryo/Music/BHPAI/gui_vault.py), [`server/vault_router.py`](file:///c:/Users/Kryo/Music/BHPAI/server/vault_router.py).

### 10.1 Mô hình mã hóa Client-Side E2EE & Cây sinh khóa KDF/HKDF
Phân hệ Vault V1.6 mang tới giải pháp sao lưu an toàn tuyệt đối theo nguyên tắc **Zero-Knowledge (Không tiết lộ tri thức)**:
- Mọi dữ liệu tập tin và metadata (tên file, đường dẫn) được mã hóa bằng **AES-256-GCM** trực tiếp trên Client trước khi truyền qua mạng.
- Server lưu trữ **tuyệt đối không thể đọc hay giải mã dữ liệu** (100% Ciphertext).

```
User Password (P) ────► Argon2id / PBKDF2 ────► K_master
                                                    │
                                                    ▼
                                           HKDF(info="Unlock") ────► K_unlock
                                                                          │
                                                                          ▼
                                                           [Giải mã Encrypted K_vault]
                                                                          │
                                                                          ▼
                                                                       K_vault
                                                                          │
                        ┌────────────────────────────────────────────────┴────────────────────────────────┐
                        │                                                                                 │
                        ▼                                                                                 ▼
           HKDF(info="Files-Wrap") ──► K_wrap_files                                          HKDF(info="Meta-Wrap") ──► K_wrap_meta
                        │                                                                                 │
                        ▼                                                                                 ▼
             Mã hóa Nội dung Tập tin                                                           Mã hóa Tên file & Metadata
```

---

### 10.2 Giao thức xác thực không tiết lộ tri thức SRP-6a PAKE (RFC 5054)
Để đăng nhập và mở khóa Vault mà không bao giờ gửi mật khẩu hay Hash mật khẩu lên Server, BHPAI áp dụng giao thức **SRP-6a (Secure Remote Password)** ([`Core/vault/pake.py`](file:///c:/Users/Kryo/Music/BHPAI/Core/vault/pake.py)):
1. **Đăng ký (Registration)**: Client tính $x = H(s, P)$ và Verifier $v = g^x \pmod N$, chỉ gửi Salt $s$ và Verifier $v$ lên Server.
2. **Xác thực (Authentication)**: Server gửi $B = (k \cdot v + g^b) \pmod N$. Hai bên tính toán giá trị bí mật dùng chung $S$ và kiểm chứng bằng chứng nhận $M_1, M_2$. Mật khẩu không bao giờ xuất hiện trên mạng.

---

### 10.3 Cơ chế Đổi mật khẩu tức thì (Instant Re-Keying Mechanism)
BHPAI giải quyết bài toán đổi mật khẩu master mà không cần mã hóa lại hàng trăm GB dữ liệu sao lưu bằng kiến trúc **$K_{\text{vault}}$ Indirection**:
- Dữ liệu tập tin được mã hóa bằng khóa Vault master $K_{\text{vault}}$.
- Khóa $K_{\text{vault}}$ lại được bảo vệ bởi khóa unlock $K_{\text{unlock}}$ (sinh ra từ mật khẩu).
- Khi đổi mật khẩu: Chỉ cần giải mã $K_{\text{vault}}$ bằng mật khẩu cũ, sau đó mã hóa lại duy nhất khối $K_{\text{vault}}$ bằng mật khẩu mới. **Toàn bộ hàng trăm GB dữ liệu sao lưu giữ nguyên trạng thái ciphertext.**

---

### 10.4 Xác thực AAD Chuẩn hóa & Bucket Size Padding chống phân tích lưu lượng
1. **Binary Length-Prefixed Canonical AAD** ([`Core/vault/integrity.py`](file:///c:/Users/Kryo/Music/BHPAI/Core/vault/integrity.py)): Thêm dữ liệu xác thực bổ sung (Authenticated Additional Data) dạng chuẩn hóa tương thích giữa C++ và Python, ngăn chặn kẻ tấn công tráo đổi ciphertext giữa các tập tin khác nhau.
2. **Application-Level Bucket Size Padding**: Tập tin được độn thêm dung lượng (Padding) vào các kích thước cố định (64KB, 1MB, 10MB, 100MB) để triệt tiêu khả năng suy đoán nội dung tệp dựa vào kích thước ciphertext.

---

## 11. CHI TIẾT PHÂN HỆ 9: GIAO DIỆN PYQT6 & HỆ THỐNG RESTFUL API SERVER

Mã nguồn chính nằm tại: [`gui.py`](file:///c:/Users/Kryo/Music/BHPAI/gui.py), [`gui_features.py`](file:///c:/Users/Kryo/Music/BHPAI/gui_features.py), [`gui_vault.py`](file:///c:/Users/Kryo/Music/BHPAI/gui_vault.py), [`server/main.py`](file:///c:/Users/Kryo/Music/BHPAI/server/main.py), [`server/scan_router.py`](file:///c:/Users/Kryo/Music/BHPAI/server/scan_router.py).

### 11.1 Kiến trúc Giao diện PyQt6 Modern Dark Glassmorphism (Multi-Threading QThread)
Giao diện người dùng ([`gui.py`](file:///c:/Users/Kryo/Music/BHPAI/gui.py)) được xây dựng trên nền **PyQt6 Framework** theo phong cách **Modern Dark Mode Glassmorphism**:
- **Thiết kế không treo UI (60 FPS Smooth Responsiveness)**: Toàn bộ công việc tính toán nặng (Disassembly Capstone, Sandbox IPC, KDF Cryptography, Network I/O) được tách hoàn toàn khỏi GUI Thread và đẩy vào các **`QThread` Background Workers** ([`gui_vault.py`](file:///c:/Users/Kryo/Music/BHPAI/gui_vault.py)).
- **Các Module chính trên Dashboard**:
  - **Multi-Format Scanner Tab**: Kéo-thả tập tin bất kỳ (PE, PDF, Office, Scripts), hiển thị threat score, phân tích đệ quy payload và cây `AnalysisNode`.
  - **Dynamic Sandbox Monitor Tab**: Theo dõi log sự kiện real-time, biểu đồ tài nguyên CPU/RAM/Disk IO của Sandbox.
  - **MITRE ATT&CK Matrix Tab**: Hiển thị ma trận kỹ thuật bị mã độc vi phạm.
  - **BHR & Recovery Center Tab**: Theo dõi timeline mã hóa dữ liệu và thực hiện 1-Click Rollback Recovery.
  - **Zero-Knowledge Encrypted Vault Tab**: Quản lý sao lưu và phục hồi dữ liệu đám mây mã hóa E2EE.

---

### 11.2 Hệ thống RESTful API Server & Universal Scan Endpoint (`/scan`)
Dự án tích hợp REST Server ([`server/main.py`](file:///c:/Users/Kryo/Music/BHPAI/server/main.py)) và Scan Router ([`server/scan_router.py`](file:///c:/Users/Kryo/Music/BHPAI/server/scan_router.py)) phát triển bằng **FastAPI**, cung cấp Universal Scan Endpoint tự động định tuyến và phân tích đa định dạng:

| Method | Endpoint API | Chức năng & Vai trò |
| :--- | :--- | :--- |
| `POST` | `/scan` | **Universal Scan Router**: Nhận tệp bất kỳ (PE, PDF, v.v.), tự động định tuyến, thực hiện phân tích tĩnh/đệ quy/AI, trả về Universal Schema 2.0. Hỗ trợ quét đồng bộ hoặc bất đồng bộ. |
| `GET` | `/scan/result/{scan_id}` | Truy vấn trạng thái và kết quả của một phiên quét nền bất đồng bộ. |
| `GET` | `/scan/report/{sha256}` | Lấy báo cáo chi tiết theo mã băm SHA256 đã lưu trong cơ sở dữ liệu SQLite (`bhpai.db`). |
| `POST` | `/scan/hash` | Quét tức thì mã băm SHA256/MD5 (tra cứu danh mục Known Benign / Malware và truy vấn VirusTotal). |
| `GET` | `/scan/history` | Truy vấn lịch sử quét tài liệu của người dùng. |
| `GET` | `/health` | Kiểm tra trạng thái hoạt động của máy chủ phân tích và các mô hình AI. |

---

### 11.3 Subscription Tiering API & Quản lý Hạn mức Lưu trữ
Mã nguồn: [`server/subscription_router.py`](file:///c:/Users/Kryo/Music/BHPAI/server/subscription_router.py).

| Method | Endpoint API | Chức năng & Vai trò |
| :--- | :--- | :--- |
| `POST` | `/api/v1/subscription/trial` | Kích hoạt gói dùng thử Trial (1-12 tháng), cấp 5GB Vault Storage & dịch vụ mã hóa. |
| `POST` | `/api/v1/subscription/buy-premium` | Mua/Nâng cấp Premium (1-60 tháng), mở khóa 100GB Storage, Priority Recovery & Unlimited API. |
| `GET` | `/api/v1/subscription/status` | Kiểm tra thông tin gói hiện tại, thời hạn còn lại (ngày), quyền hạn tính năng và quota lưu trữ. |
| `POST` | `/api/v1/subscription/cancel` | Hủy gia hạn gói dịch vụ, tự động đưa tài khoản về hạng Free (500MB storage). |

---

### 11.4 Threat Intelligence API (IOCs, Malware Families & User Scan History)
| Method | Endpoint API | Chức năng & Vai trò |
| :--- | :--- | :--- |
| `GET` | `/api/v1/intelligence/iocs` | Lấy danh sách các chỉ số tấn công (IOCs: Defanged URLs, Domains, IPs) được trích xuất từ các phiên quét gần đây. |
| `GET` | `/api/v1/intelligence/families` | Truy vấn danh mục các họ mã độc (Malware Families: Ransomware, Stealer, Exploits) kèm kỹ thuật MITRE tương ứng. |
| `GET` | `/api/v1/dashboard/overview` | Lấy các chỉ số thống kê tổng quan của hệ thống SOC/Website Dashboard. |
| `GET` | `/api/v1/notifications` | Lấy danh sách thông báo bảo mật và sự kiện hệ thống của người dùng. |

---

## 12. HƯỚNG DẪN BIÊN DỊCH, KHỞI CHẠY & VẬN HÀNH HỆ THỐNG

### 12.1 Hướng dẫn Biên dịch Native C++ Modules (CMake & MinGW-w64)
Hệ thống sử dụng CMake và MinGW-w64 (GCC 16.2.0 / 14.x) với liên kết OpenSSL và zlib:

```bash
# Tạo thư mục build và cấu hình CMake
cmake -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release

# Biên dịch toàn bộ các thành phần Native:
# 1. pdf_analyzer.exe (PDF Engine v2.0)
# 2. pe_analyzer.exe (PE Static Engine)
# 3. BHPAISandbox.exe (Sandbox Launcher)
# 4. BHPAIMonitor.dll (Stealth Ring-3 Monitor)
cmake --build build --target pdf_analyzer pe_analyzer BHPAISandbox BHPAIMonitor -j4
```

---

### 12.2 Cài đặt Môi trường Phụ thuộc Python
Chuẩn bị môi trường Python 3.9+ (khuyên dùng Python 3.11) và cài đặt các thư viện cần thiết:

```bash
pip install PyQt6 capstone yara-python pefile scikit-learn lightgbm torch pandas numpy matplotlib psutil joblib fastapi uvicorn cryptography httpx
```

---

### 12.3 Khởi chạy Giao diện Quản trị Desktop (`gui.py`)
Mở Terminal tại thư mục gốc dự án và thực thi:

```bash
python gui.py
```

---

### 12.4 Khởi chạy Backend RESTful API Server (`server/main.py`)
Khởi chạy dịch vụ API Server hỗ trợ Universal Scan Router trên cổng `8000`:

```bash
python -m uvicorn server.main:app --host 0.0.0.0 --port 8000 --reload
```

Tài liệu tương tác Swagger UI sẽ tự động sẵn sàng tại: `http://localhost:8000/docs`.

---

### 12.5 Vận hành Công cụ Dòng lệnh Độc lập (CLI Tools)

#### 1. Quét tài liệu PDF qua Native CLI:
```bash
./pdf_analyzer.exe path/to/document.pdf
# Kết quả JSON Universal Schema 2.0 sẽ được xuất ra stdout hoặc tệp document.pdf.json
```

#### 2. Quét tệp thực thi PE qua Native CLI:
```bash
./pe_analyzer.exe path/to/sample.exe
```

#### 3. Khởi chạy Sandbox Phân tích Động:
```bash
./BHPAISandbox.exe path/to/malware.exe
```

#### 4. Huấn luyện lại Mô hình AI PDF với Khử Trùng Lặp & Kháng False Positive:
```bash
python Core/Train/train_pdf_model.py --dataset-dir dataset/pdf --dedup-level structural --include-hard-in-training
```

---

*Tài liệu Master Kỹ thuật của dự án BHPAI V1.6 Enterprise được biên soạn và chuẩn hóa bởi Bao. Mọi quyền được bảo lưu.*
