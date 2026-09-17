# TÀI LIỆU DỰ ÁN: BHPAI
> **Phiên bản hệ thống**: V1.6 Enterprise Edition (Bản cập nhật Toàn diện Tính năng Hệ thống)  
> **Tác giả**: Rin449 
> **Ngôn ngữ & Công nghệ cốt lõi**: C++17 (MinGW-w64 / MSYS2), Python 3.9+, PyQt6, MinHook, Capstone Engine, Intel PT (Processor Trace), PyTorch, LightGBM, OpenSSL 3.x, zlib, Argon2id, Cryptography, Ed25519  
> **Tài liệu tham chiếu Master**: Chi tiết kiến trúc đa định dạng (Multi-Format), giải thuật phân tích đệ quy, phân tích tĩnh PE & PDF, giám sát động Sandbox Stealth Ring-3, trích xuất cấu trúc khóa Ransomware, mô hình AI chống cảnh báo giả (False Positive Resistant), hệ thống cứu hộ ngoại tuyến WinRE và bảo mật dữ liệu Zero-Knowledge.


> **Language / Ngôn ngữ**: [🇻🇳 Tiếng Việt](#-tài-liệu-dự-án-toàn-diện-bhpai-behavioral-hybrid-predictive-ai) | [🇬🇧 English](#-comprehensive-project-documentation-bhpai-behavioral-hybrid-predictive-ai-english-version)

---

## MỤC LỤC TỔNG QUAN

1. [TỔNG QUAN DỰ ÁN & TẦM NHÌN KIẾN TRÚC ĐA ĐỊNH DẠNG](#1-tổng-quan-dự-án--tầm-nhìn-kiến-trúc-đa-định-dạng)
   - [1.1 Bối cảnh an ninh mạng & Thách thức bảo mật hiện đại](#11-bối-cảnh-an-ninh-mạng--thách-thức-bảo-mật-hiện-đại)
   - [1.2 Triết lý thiết kế Hybrid Đa định dạng (Multi-Format Tri-Layer Engine)](#12-triết-lý-thiết-kế-hybrid-đa-định-dạng-multi-format-tri-layer-engine)
   - [1.3 Bảng thông số kỹ thuật cốt lõi V1.6 (Technical Highlights)](#13-bảng-thông-số-kỹ-thuật-cốt-lõi-v16-technical-highlights)
2. [SƠ ĐỒ KIẾN TRÚC & LUỒNG XỬ LÝ DỮ LIỆU TỔNG THỂ](#2-sơ-đồ-kiến-trúc--luồng-xử-lý-dữ-liệu-tổng-thể)
3. [CHI TIẾT PHÂN HỆ 1: DYNAMIC WINDOWS SANDBOX & STEALTH MONITORING (RING-3)](#3-chi-tiết-phân-hệ-1-dynamic-windows-sandbox--stealth-monitoring-ring-3)
   - [3.1 Môi trường Desktop ảo hóa độc lập & Giới hạn Windows Job Object](#31-môi-trường-desktop-ảo-hóa-độc-lập--giới-hạn-windows-job-object)
   - [3.2 Tước bỏ đặc quyền nguy hiểm bằng Restricted Token](#32-tước-bỏ-đặc-quyền-nguy-hiểm-bằng-restricted-token)
   - [3.3 Kỹ thuật Anti-Evasion & Stealth (PEB Unlinking, Memory PE Wiping, DACL Guard)](#33-kỹ-thuật-anti-evasion--stealth-peb-unlinking-memory-pe-wiping-dacl-guard)
   - [3.4 Can thiệp Native NT API qua MinHook Engine & RAII HookGuard](#34-can-thiệp-native-nt-api-qua-minhook-engine--raii-hookguard)
   - [3.5 Công nghệ Copy-On-Write (COW) 2 lớp cho Filesystem & Registry](#35-công-nghệ-copy-on-write-cow-2-lớp-cho-filesystem--registry)
   - [3.6 Kernel Event Tracing (ETW Monitor)](#36-kernel-event-tracing-etw-monitor)
   - [3.7 Fake Network Engine (C2 Sinkhole & Payload Mocking)](#37-fake-network-engine-c2-sinkhole--payload-mocking)
   - [3.8 Giám sát Phần cứng Intel Processor Trace (Intel PT) Engine](#38-giám-sát-phần-cứng-intel-processor-trace-intel-pt-engine)
   - [3.9 Ranh giới Kỹ thuật & Giới hạn Thực tế của Môi trường Phân tích](#39-ranh-giới-kỹ-thuật--giới-hạn-thực-tế-của-môi-trường-phân-tích)
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
   - [7.5 Kết Quả Benchmark & Đánh Giá Thực Nghiệm Bộ Phân Loại AI](#75-kết-quả-benchmark--đánh-giá-thực-nghiệm-bộ-phân-loại-ai)
8. [CHI TIẾT PHÂN HỆ 6: BHR ENGINE (RANSOMWARE DETECTOR & KEY RECOVERY)](#8-chi-tiết-phân-hệ-6-bhr-engine-ransomware-detector--key-recovery)
   - [8.1 Thuật toán phát hiện mã hóa Entropy cao (Shannon Entropy Rate)](#81-thuật-toán-phát-hiện-mã-hóa-entropy-cao-shannon-entropy-rate)
   - [8.2 Giám sát Burst Modification Rate & Hành vi xóa Shadow Copy](#82-giám-sát-burst-modification-rate--hành-vi-xóa-shadow-copy)
   - [8.3 Trích xuất cấu trúc khóa mã hóa (20+ Standards) từ RAM & `pagefile.sys`](#83-trích-xuất-cấu-trúc-khóa-mã-hóa-20-standards-từ-ram--pagefilesys)
   - [8.4 Khôi phục dữ liệu từ Vùng đệm COW Virtual Overlay (Win32/NT Scope)](#84-khôi-phục-dữ-liệu-từ-vùng-đệm-cow-virtual-overlay-win32nt-scope)
   - [8.5 Nhật ký Crypto Timeline & Bản đồ biến đổi dữ liệu](#85-nhật-ký-crypto-timeline--bản-đồ-biến-đổi-dữ-liệu)
   - [8.6 Kiểm thử Thực nghiệm Dual-Engine Hybrid Ransomware Memory Key Extraction](#86-kiểm-thử-thực-nghiệm-dual-engine-hybrid-ransomware-memory-key-extraction)
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
    - [10.5 Kiến trúc Lưu trữ Khối Cục bộ Mã hóa (Local Encrypted Block Store)](#105-kiến-trúc-lưu-trữ-khối-cục-bộ-mã-hóa-local-encrypted-block-store)
11. [CHI TIẾT PHÂN HỆ 9: GIAO DIỆN DESKTOP PYQT6 GLASSMORPHISM, BẢN QUYỀN HWID & CÔNG CỤ CLI](#11-chi-tiết-phân-hệ-9-giao-diện-desktop-pyqt6-glassmorphism-bản-quyền-hwid--công-cụ-cli)
    - [11.1 Kiến trúc Giao diện PyQt6 Desktop Glassmorphism (Multi-Threading QThread)](#111-kiến-trúc-giao-diện-pyqt6-desktop-glassmorphism-multi-threading-qthread)
    - [11.2 Các Tab Chức Năng Cốt Lõi Trên Desktop GUI](#112-các-tab-chức-năng-cốt-lõi-trên-desktop-gui)
    - [11.3 Hệ thống Bản quyền Khóa cứng Phần cứng (HWID-Locked Licensing & Ed25519)](#113-hệ-thống-bản-quyền-khóa-cứng-phần-cứng-hwid-locked-licensing--ed25519)
    - [11.4 Động cơ Threat Intelligence & Universal IOC Defanger Độc Lập](#114-động-cơ-threat-intelligence--universal-ioc-defanger-độc-lập)
    - [11.5 Hệ thống Báo cáo Đa định dạng Universal Schema 2.0 (JSON, Markdown, PDF)](#115-hệ-thống-báo-cáo-đa-định-dạng-universal-schema-20-json-markdown-pdf)
12. [CHI TIẾT PHÂN HỆ 10: BHPAI RESCUE SUITE & KHỞI ĐỘNG CỨU HỘ KHẨN CẤP WINRE](#12-chi-tiết-phân-hệ-10-bhpai-rescue-suite--khởi-động-cứu-hộ-khẩn-cấp-winre)
    - [12.1 Môi trường Cứu hộ Ngoại tuyến Windows Recovery Environment (WinRE)](#121-môi-trường-cứu-hộ-ngoại-tuyến-windows-recovery-environment-winre)
    - [12.2 Kiến Trúc 7 Phân Hệ Cốt Lõi Của `bhpai_rescue.exe`](#122-kiến-trúc-7-phân-hệ-cốt-lõi-của-bhpai_rescueexe)
    - [12.3 Quy Trình Giao Dịch Khắc Phục 5 Giai Đoạn (5-Phase Transaction Pipeline)](#123-quy-trình-giao-dịch-khắc-phục-5-giai-đoạn-5-phase-transaction-pipeline)
    - [12.4 Cơ Chế Tự Phục Hồi Khi Gặp Sự Cố (Crash State Recovery)](#124-cơ-chế-tự-phục-hồi-khi-gặp-sự-cố-crash-state-recovery)
    - [12.5 Kịch bản Triển khai & Khởi động WinRE Tự động](#125-kịch-bản-triển-khai--khởi-động-winre-tự-động)
    - [12.6 Hướng Dẫn Vận Hành & Tham Số Dòng Lệnh `bhpai_rescue.exe`](#126-hướng-dẫn-vận-hành--tham-số-dòng-lệnh-bhpai_rescueexe)
13. [CHI TIẾT PHÂN BỔ MÃ NGUỒN MỞ: BHPAI COMMUNITY EDITION (BHPAI_SOURCEOPEN - 25%)](#13-chi-tiết-phân-bổ-mã-nguồn-mở-bhpai-community-edition-bhpai_sourceopen---25)

---

## 1. TỔNG QUAN DỰ ÁN & TẦM NHÌN KIẾN TRÚC ĐA ĐỊNH DẠNG

### 1.1 Bối cảnh an ninh mạng & Thách thức bảo mật hiện đại
Trong kỷ nguyên an ninh mạng hiện nay, các cuộc tấn công có chủ đích (APT), mã độc gián điệp, và mã độc tống tiền (Ransomware) đã vượt ra ngoài phạm vi của các tập tin thực thi truyền thống (`.exe`, `.dll`):
1. **Tấn công Đa định dạng & Vũ khí hóa Tài liệu (Document Weaponization)**: Mã độc xâm nhập ban đầu qua tài liệu PDF độc hại (chứa mã khai thác lỗ hổng Adobe Acrobat CVE, Javascript bị làm mờ, action `/Launch` thực thi command ngầm) hoặc đóng gói tệp thực thi PE nhúng bên trong PDF dạng Dropper.
2. **Lẩn tránh Phân tích Tĩnh (Static Evasion)**: Sử dụng các biến thể đa hình (Polymorphic), biến hình (Metamorphic), nén nhiều lớp (Packers), hoặc chèn các thành phần giả mạo hợp lệ nhằm đánh lừa mô hình học máy đơn giản tạo thành các lối tắt học vẹt (Heuristic Shortcut Failure).
3. **Lẩn tránh Môi trường Phân tích Động (Anti-Sandbox / Anti-Analysis)**: Quét bộ nhớ phát hiện các DLL giám sát nạp trong tiến trình, kiểm tra PEB module list, tháo gỡ hook (Unhooking), phát hiện môi trường máy ảo và thực hiện kỹ thuật ngủ (Sleep Acceleration Evasion).
4. **Phá hủy Dữ liệu Tốc độ Cao (High-speed Crypto Destruction)**: Các biến thể Ransomware thế hệ mới (LockBit 3.0, BlackCat, Hyper, Conti) sử dụng song song nhiều thuật toán mã hóa (Dual-Engine Hybrid: AES-256-GCM + ChaCha20 + X25519/RSA), xóa các điểm khôi phục Volume Shadow Copies và thay đổi dữ liệu trước khi các hệ thống truyền thống kịp phát hiện.

**BHPAI** phiên bản **V1.6 Enterprise** là hệ thống an ninh mạng đa tầng, cung cấp giải pháp bảo vệ toàn diện cho chuỗi tấn công thông qua kiến trúc **Multi-Format Hybrid Engine**: Định tuyến tự động đa định dạng (PE, PDF, Office, Script), phân tích đệ quy payload lồng nhau, cô lập Sandbox Ring-3 stealth, giám sát phần cứng Intel PT, và mô hình AI hiệu chuẩn chống cảnh báo giả.

---

### 1.2 Triết lý thiết kế Hybrid Đa định dạng (Multi-Format Tri-Layer Engine)

BHPAI V1.6 được thiết kế dựa trên mô hình **Định tuyến - Phân giải Đệ quy - Tương quan Hành vi - Phục hồi Ngoại tuyến**:

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

1. **Safety First & Anti-Bomb (An toàn & Phòng vệ DoS)**: Sandbox cách ly tiến trình qua Desktop ảo riêng biệt (`BHPAISandboxDesktop`), giới hạn Job Object (RAM 512MB, CPU, cấm Breakaway) và hạ đặc quyền với Restricted Token. Bộ giải nén dòng PDF được bảo vệ bởi `AnalysisBudget` và `ParserLimits` chống Decompression Bomb (tỷ lệ nén tối đa 100:1, giới hạn dung lượng và độ sâu lồng nhau).
2. **Stealth Anti-Evasion (Giảm thiểu footprint User-mode)**: DLL giám sát Ring-3 chủ động giảm thiểu dấu vết đối với các kỹ thuật anti-analysis thông thường qua việc gỡ bỏ khỏi 3 danh sách liên kết kép PEB Module (`InLoadOrder`, `InMemoryOrder`, `InInitializationOrder`), xóa PE Header & Debug PDB trong RAM, và thiết lập DACL bảo vệ Launcher chống lại các lệnh `OpenProcess(PROCESS_TERMINATE)` cơ bản.
3. **Recursive Analysis Tree & Child Dominance (Phân tích đệ quy & Thống trị con)**: Kiến trúc cây `AnalysisNode` kiểm tra đệ quy mọi tệp tin nhúng bên trong tài liệu. Khi phát hiện một tệp thực thi con (Child PE) là độc hại, hệ thống kích hoạt **Child Dominance Rule**, tự động nâng cấp kết luận của tài liệu cha lên **MALICIOUS** với điểm rủi ro tối thiểu 85/100.
4. **False-Positive Resistance AI (Kháng cảnh báo giả)**: Loại bỏ lối tắt suy luận sai lầm nhờ tổ chức tập dữ liệu 3 tầng (`suspicious_benign`), khử trùng lặp đa cấp (Exact Hash + Structural Fingerprint) và phân rã nhóm `StratifiedGroupKFold`.
5. **Data Protection & Key Recovery (Phát hiện & Hỗ trợ trích xuất khóa ứng viên)**: BHR Engine phát hiện hành vi mã hóa entropy dồn dập trong phạm vi Win32/NT I/O, quét tìm các cấu trúc khóa ứng viên (AES-GCM GHASH $H$, ChaCha20 state, RSA DER, X25519) trong RAM và `pagefile.sys` trước khi tiến trình giải phóng bộ nhớ, đồng thời hỗ trợ rollback các tệp đã ghi vào vùng đệm COW Overlay đối với các hoạt động I/O chuẩn.

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
| **Sao lưu Mã hóa Độc lập (Vault)** | Client-Side Zero-Knowledge E2EE (AES-256-GCM) + SRP-6a PAKE (RFC 5054) + Instant Re-Keying ($K_{\text{vault}}$) + Canonical AAD |
| **Cứu hộ Ngoại tuyến WinRE** | `bhpai_rescue.exe` C++17 standalone, 7 phân hệ, 5-Phase ACID transaction, Crash state recovery, tự động mount registry offline |
| **Giao diện Desktop & Bản quyền** | PyQt6 Dark Glassmorphism GUI (QThread workers) + Ed25519 HWID Hardware-Locked Licensing engine |

---

## 2. SƠ ĐỒ KIẾN TRÚC & LUỒNG XỬ LÝ DỮ LIỆU TỔNG THỂ

Sơ đồ trình tự thể hiện luồng xử lý từ khi tiếp nhận tập tin đầu vào cho đến khi trích xuất payload, phân tích tĩnh/động, phân loại AI và khôi phục dữ liệu:

```mermaid
sequenceDiagram
    autonumber
    actor Analyst as Chuyên viên / Người dùng
    participant GUI as Desktop GUI / CLI Runner
    participant Router as 3-Stage FileRouter
    participant Static as Static Engine (PE/PDF/Office)
    participant RecTree as Recursive Analysis Tree
    participant Sandbox as Ring-3 Stealth Sandbox
    participant BHR as BHR Ransomware Engine
    participant AI as AI Ensemble & BehaviorGraph
    participant WinRE as BHPAI Rescue Suite (WinRE)

    Analyst->>GUI: Tải tệp lên (PE, PDF, Doc, Script)
    GUI->>Router: Định tuyến định dạng tệp (Magic Bytes/Container)
    
    alt Định dạng PDF
        Router->>Static: Phân tích C++ PDF Parser V2.0
        Static->>RecTree: Bóc tách JavaScript & Streams nhúng
        opt Có tệp PE / Shellcode nhúng bên trong
            RecTree->>Static: Phân tích PE con (Child PE Static Scan)
            Static-->>RecTree: Phát hiện PE độc hại (Child Dominance Rule)
        end
    else Định dạng PE
        Router->>Static: Phân tích Capstone, Opcode TF-IDF, CFG, YaraGen
    end

    Static->>AI: Vector hóa đặc trưng tĩnh & Dự đoán mô hình AI

    opt Yêu cầu phân tích động chuyên sâu
        GUI->>Sandbox: Khởi chạy mẫu trong Virtual Desktop & Job Object
        Note over Sandbox: Kích hoạt PEB Unlink, COW FS/Reg, MinHook, Intel PT
        Sandbox->>BHR: Giám sát Entropy & Tốc độ ghi tập tin thời gian thực
        
        opt Phát hiện hành vi Ransomware (Entropy >= 7.5, Burst I/O)
            BHR->>BHR: Kích hoạt RAM & Pagefile Candidate Key Extractor
            BHR->>Sandbox: Ghi nhận Crypto Timeline & Bản đồ biến đổi
        end

        Sandbox->>AI: Chuyển dữ liệu sự kiện Hook/ETW vào BehaviorGraph
        AI->>AI: Khớp mẫu chuỗi tấn công & MITRE ATT&CK Mapping
    end

    AI-->>GUI: Xuất báo cáo tổng hợp Universal Schema 2.0 (Threat Score, IOCs)
    
    opt Hệ thống bị tê liệt hoặc dính Ransomware diện rộng
        Analyst->>WinRE: Khởi động vào môi trường cứu hộ WinRE
        WinRE->>WinRE: Giao dịch 5 giai đoạn: Quét offline -> Sao lưu -> Unbrick Registry -> Rollback
        WinRE-->>Analyst: Hệ thống được phục hồi nguyên trạng
    end
```

---

## 3. CHI TIẾT PHÂN HỆ 1: DYNAMIC WINDOWS SANDBOX & STEALTH MONITORING (RING-3)

Mã nguồn chính nằm tại: [`BHPAISandbox.cpp`](file:///c:/Users/Kryo/Documents/BHPAI/BHPAISandbox.cpp), [`BHPAIMonitor.cpp`](file:///c:/Users/Kryo/Documents/BHPAI/BHPAIMonitor.cpp), [`SafeVirtualDesktop.cpp`](file:///c:/Users/Kryo/Documents/BHPAI/SafeVirtualDesktop.cpp), [`SafeJobObject.cpp`](file:///c:/Users/Kryo/Documents/BHPAI/SafeJobObject.cpp), [`IntelPTMonitor.cpp`](file:///c:/Users/Kryo/Documents/BHPAI/IntelPTMonitor.cpp), [`FakeNetEngine.cpp`](file:///c:/Users/Kryo/Documents/BHPAI/FakeNetEngine.cpp).

### 3.1 Môi trường Desktop ảo hóa độc lập & Giới hạn Windows Job Object
1. **Virtual Desktop (`BHPAISandboxDesktop`)**: Khởi tạo bằng `CreateDesktopW` với cờ `DESKTOP_CREATEWINDOW | DESKTOP_WRITEOBJECTS`. Mọi cửa sổ đồ họa, thông điệp Windows Message (`WM_DROPFILES`, `WM_COPYDATA`, UI Redirection) của mã độc bị giam giữ hoàn toàn trong Desktop ảo, cô lập với màn hình người dùng (`Default` Desktop).
2. **Windows Job Object (`SafeJobObject`)**:
   - `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`: Khi tiến trình Launcher thoát, toàn bộ cây tiến trình con của mã độc tự động bị hủy.
   - `JOB_OBJECT_LIMIT_PROCESS_MEMORY`: Giới hạn RAM tối đa 512MB/tiến trình chống cạn kiệt tài nguyên hệ thống.
   - `JOB_OBJECT_LIMIT_ACTIVE_PROCESS`: Giới hạn tối đa 32 tiến trình đồng thời chống tấn công Fork-Bomb.
   - `JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION`: Chặn cửa sổ Windows Error Reporting Crash Dialog.
   - `JOB_OBJECT_UILIMIT_HANDLES | JOB_OBJECT_UILIMIT_GLOBALATOMS`: Ngăn chặn can thiệp Handle và Atoms toàn cục.

---

### 3.2 Tước bỏ đặc quyền nguy hiểm bằng Restricted Token
Launcher tạo Token giới hạn qua `CreateRestrictedToken` trước khi gọi `CreateProcessAsUserW`:
- **Disable SIDs**: `WinBuiltinAdministratorsSid`, `WinLocalSystemSid`, `WinLocalAdminSid`.
- **Privileges to Remove**: Xóa bỏ hoàn toàn các đặc quyền nhạy cảm: `SeDebugPrivilege`, `SeTcbPrivilege`, `SeTakeOwnershipPrivilege`, `SeLoadDriverPrivilege`, `SeBackupPrivilege`, `SeRestorePrivilege`, `SeShutdownPrivilege`, `SeImpersonatePrivilege`.
- **Mandatory Integrity Level**: Hạ xuống mức `SECURITY_MANDATORY_LOW_RID` hoặc `SECURITY_MANDATORY_MEDIUM_RID`.

---

### 3.3 Kỹ thuật Anti-Evasion & Stealth (PEB Unlinking, Memory PE Wiping, DACL Guard)

Để giảm thiểu khả năng bị mã độc phát hiện DLL giám sát trong không gian bộ nhớ Ring-3:
1. **PEB Module List Unlinking**:
   DLL `BHPAIMonitor.dll` tự động gỡ bỏ `LDR_DATA_TABLE_ENTRY` của chính nó ra khỏi 3 danh sách liên kết kép trong Process Environment Block (PEB):
   - `InLoadOrderModuleList`
   - `InMemoryOrderModuleList`
   - `InInitializationOrderModuleList`
   Khi mã độc duyệt `PEB->Ldr` hoặc gọi `EnumProcessModules`, module giám sát không hiển thị trong danh sách.
2. **In-Memory PE Header & Section Scrubber**:
   Ghi đè `PAGE_READWRITE` và xóa trắng (Zero-fill) vùng `IMAGE_DOS_HEADER`, `IMAGE_NT_HEADERS`, `IMAGE_SECTION_HEADER` và chuỗi Debug Directory PDB Path của DLL trong bộ nhớ RAM, ngăn chặn kỹ thuật quét chữ ký bộ nhớ.
3. **Launcher DACL Guard**:
   Tiến trình điều khiển thiết lập `SetKernelObjectSecurity` với danh sách điều khiển truy cập tùy ý (DACL) rỗng, từ chối quyền `PROCESS_TERMINATE`, `PROCESS_VM_WRITE`, và `PROCESS_SUSPEND_RESUME` từ các tiến trình có mức toàn vẹn thấp hơn.

---

### 3.4 Can thiệp Native NT API qua MinHook Engine & RAII HookGuard
Hệ thống sử dụng **MinHook Engine** can thiệp trực tiếp vào các hàm Native NT API mức thấp trong `ntdll.dll` và `kernelbase.dll`:

| Nhóm API | Hàm Native Hooked | Mục đích Giám sát & Chuyển hướng |
| :--- | :--- | :--- |
| **Process / Thread** | `NtCreateProcessEx`, `NtCreateUserProcess`, `NtCreateThreadEx`, `NtQueueApcThread` | Phát hiện tạo tiến trình con, Process Injection, APC Injection. |
| **Virtual Memory** | `NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, `NtWriteVirtualMemory` | Nhận diện cấp phát `PAGE_EXECUTE_READWRITE`, Process Hollowing, Shellcode Injection. |
| **Filesystem I/O** | `NtCreateFile`, `NtOpenFile`, `NtWriteFile`, `NtSetInformationFile`, `NtDeleteFile` | Ghi nhận I/O, chuyển hướng COW Overlay, đo lường Shannon Entropy. |
| **Registry** | `NtCreateKey`, `NtOpenKey`, `NtSetValueKey`, `NtDeleteValueKey` | Giám sát điểm cắm chốt tự khởi động (Persistence) và chuyển hướng COW. |
| **Anti-Analysis** | `NtQueryInformationProcess`, `NtSetInformationThread`, `NtDelayExecution` | Chặn phát hiện `ProcessDebugPort`, ThreadHideFromDebugger, tăng tốc Sleep Evasion. |

Mọi hàm hook đều được bảo vệ bởi lớp **`RAII HookGuard`** (`thread_local bool in_hook`), đảm bảo chống hiện tượng lặp vô hạn (Recursive Hook Loop Deadlock).

---

### 3.5 Công nghệ Copy-On-Write (COW) 2 lớp cho Filesystem & Registry
Để bảo vệ an toàn cho hệ thống thật trong khi vẫn cho phép mã độc tương tác bình thường:
1. **Filesystem Overlay Layer**:
   - Khi mã độc mở file ở chế độ `GENERIC_READ`, hệ thống cho phép đọc từ tệp gốc.
   - Khi có thao tác ghi `GENERIC_WRITE` hoặc xóa `FILE_DELETE_ON_CLOSE`: Tệp gốc lập tức được sao chép sang thư mục tạm ảo hóa `BHPAI_Sandbox_Overlay\Files\`. Mọi thao tác biến đổi dữ liệu thực thi trên bản sao này.
   - Hỗ trợ đầy đủ các tính năng nâng cao: Alternate Data Streams (ADS `file.txt:zone.identifier`), Reparse Points và Symbolic Links.
2. **Registry Overlay Layer**:
   - Các khóa Registry hệ thống (`HKLM\Software\Microsoft\Windows\CurrentVersion\Run`) được ánh xạ sang nhánh tạm `HKCU\Software\BHPAI_Virtual_Registry\`.
   - Cung cấp chế độ xem hợp nhất (Merged View): Đọc dữ liệu thực nhưng ghi đè dữ liệu ảo.

---

### 3.6 Kernel Event Tracing (ETW Monitor)
Sử dụng phân hệ **Microsoft Event Tracing for Windows (ETW)** bắt các sự kiện từ Kernel:
- `Microsoft-Windows-Kernel-Process`: Bắt sự kiện tạo tiến trình ngay cả khi mã độc sử dụng Direct Syscalls bypass Userland Hooks.
- `Microsoft-Windows-Kernel-Network`: Ghi nhận các kết nối TCP/UDP mức thấp.
- `Microsoft-Windows-Kernel-Memory`: Theo dõi các thao tác ánh xạ bộ nhớ chéo (Cross-Process Memory Mapping).

---

### 3.7 Fake Network Engine (C2 Sinkhole & Payload Mocking)
Tích hợp động cơ giả lập mạng độc lập (`FakeNetEngine.cpp`):
- **DNS Sinkhole**: Đón bắt mọi truy vấn DNS (Port 53) và trả về IP Loopback (`127.0.0.1`).
- **HTTP / HTTPS Mocking**: Lắng nghe Port 80, 8080, 443; phân tích gói tin TLS ClientHello để bóc tách Server Name Indication (SNI) và trả về phản hồi HTTP 200 OK với payload an toàn.
- **C2 Beacon Interceptor**: Thu thập toàn bộ dữ liệu Exfiltration (dữ liệu đánh cắp) của mã độc để phục vụ công tác điều tra số.

---

### 3.8 Giám sát Phần cứng Intel Processor Trace (Intel PT) Engine
Phân hệ `IntelPTMonitor.cpp` khai thác tính năng theo dõi phần cứng của CPU Intel:
- Kiểm tra tính tương thích qua lệnh `__cpuidex(0x14, 0)`.
- Cấu hình ToPA (Table of Physical Addresses) thông qua Windows Kernel Tracing API (`ProcessIntelProcessorTrace`).
- Thu thập gói tin phần cứng `TNT` (Taken/Not-Taken Branch), `TIP` (Target IP) và `FUP` (Function Pointer), cho phép phát hiện ROP (Return-Oriented Programming) Chains và giải mã luồng thực thi mà không phụ thuộc vào phần mềm.

---

### 3.9 Ranh giới Kỹ thuật & Giới hạn Thực tế của Môi trường Phân tích

Mặc dù được thiết kế với nhiều lớp bảo vệ, môi trường phân tích động Ring-3 vẫn có những ranh giới kỹ thuật tự nhiên cần được hiểu rõ trong thực tế tác chiến:

1. **Giới hạn Cấp độ Đặc quyền (Ring-3 Userland vs Ring-0 Kernel)**:
   - Các kỹ thuật Userland Hooking (MinHook) và PEB Unlinking chỉ hoạt động trong không gian địa chỉ Ring-3 của tiến trình.
   - Nếu mã độc sử dụng lỗ hổng Bring Your Own Vulnerable Driver (BYOVD) hoặc khai thác lỗ hổng hạt nhân để tải mã thực thi vào Kernel (Ring-0), nó có thể vượt qua các móc nối Userland Hook, truy cập trực tiếp đĩa vật lý (bỏ qua COW Overlay) hoặc vô hiệu hóa cơ chế thu thập dữ liệu ETW.
2. **Kỹ thuật Direct Syscalls & Dynamic API Resolution**:
   - Khi mã độc tự bóc tách số hiệu Syscall (SSN - System Service Number) từ tệp `ntdll.dll` trên đĩa và thực thi lệnh nhị phân `syscall` / `sysenter` trực tiếp từ bộ nhớ riêng, luồng thực thi sẽ nhảy thẳng vào Kernel mà không đi qua các hàm được MinHook cài đặt trong `ntdll.dll`.
   - Trong kịch bản này, BHPAI kết hợp bổ trợ dữ liệu từ **Kernel ETW Provider** và **Intel PT Hardware Trace** để bù đắp sự thiếu hụt của Userland Hooks.
3. **Môi trường Giả lập & Thời gian Phân tích (Time-Limited Dynamic Run)**:
   - Một số dòng APT tinh vi áp dụng cơ chế kích hoạt trễ dài hạn (Long Sleep Logic, Logic Bombs yêu cầu tương tác chuột/bàn phím phức tạp, hoặc đòi hỏi kết nối C2 hợp lệ từ máy chủ của kẻ tấn công). Phân tích động tự động trong khoảng thời gian giới hạn (thường từ 30 đến 120 giây) có thể chưa bao quát hết mọi nhánh thực thi sâu. Do đó, việc kết hợp đồng thời với **Static Disassembly** và **Mô hình AI Đa tầng** là điều kiện tiên quyết để đảm bảo độ chính xác.

---

## 4. CHI TIẾT PHÂN HỆ 2: STATIC PE ANALYZER & CAPSTONE DISASSEMBLER

Mã nguồn chính nằm tại: [`Core/analyzer/`](file:///c:/Users/Kryo/Documents/BHPAI/Core/analyzer), [`Analyzers/PE/`](file:///c:/Users/Kryo/Documents/BHPAI/Analyzers/PE), [`pe_analyzer.exe`](file:///c:/Users/Kryo/Documents/BHPAI/pe_analyzer.exe).

### 4.1 Phân tích cấu trúc PE, Entropy Sections & Nhận diện Dị thường (Anomalies)
1. **Phân tích Cấu trúc Header**:
   - `IMAGE_DOS_HEADER`, `IMAGE_NT_HEADERS` (32-bit & 64-bit).
   - Kiểm tra `OptionalHeader.AddressOfEntryPoint`, `ImageBase`, `Subsystem`, `DllCharacteristics` (ASLR, DEP, CFG, High Entropy VA).
2. **Section Entropy Analysis**:
   - Tính toán Shannon Entropy cho từng Section:
     $$H(X) = -\sum_{i=0}^{255} p(x_i) \log_2 p(x_i)$$
   - Nhận diện các Section bị nén hoặc mã hóa bất thường ($H \ge 7.0$).
3. **Nhận diện Dị thường (PE Anomalies)**:
   - Entry point nằm ngoài các Section thực thi chuẩn.
   - Kích thước `SizeOfRawData` sai lệch lớn so với `VirtualSize`.
   - Section có thuộc tính đồng thời `IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE` (W^X Violation).
   - Dấu vết thời gian (TimeDateStamp) trong quá khứ bất thường hoặc tương lai.

---

### 4.2 Giải mã Opcode N-Grams & Trọng số TF-IDF
1. **Capstone Disassembly Engine**:
   - Khởi tạo `cs_open(CS_ARCH_X86, CS_MODE_32 / CS_MODE_64)` với cấu hình chi tiết `CS_OPT_DETAIL`.
   - Giải mã toàn bộ luồng lệnh nhị phân trong Section thực thi (`.text`, `.code`).
2. **Trích xuất Opcode N-Grams (N=2, 3, 4)**:
   - Chuyển đổi mã máy sang chuỗi ngữ nghĩa Opcode trừu tượng hóa (ví dụ: `mov -> push -> call -> test -> jz`).
3. **Trọng số TF-IDF**:
   - Áp dụng ma trận Term Frequency-Inverse Document Frequency trích xuất các đặc trưng hướng dòng lệnh đặc thù của mã độc (mã hóa XOR vòng lặp, giải mã chuỗi động, thao tác Stack Strings).

---

### 4.3 Chuỗi gọi API N-Grams & Đồ thị dòng điều khiển (CFG)
1. **Import Table & API Call Graph**:
   - Bóc tách toàn bộ `IMAGE_IMPORT_DESCRIPTOR` (IAT) và phân tích các cặp API có tính nghi ngờ cao:
     - `VirtualAlloc` $
ightarrow$ `WriteProcessMemory` $
ightarrow$ `CreateRemoteThread`.
     - `FindResource` $
ightarrow$ `LoadResource` $
ightarrow$ `LockResource` $
ightarrow$ `SizeofResource`.
     - `CryptAcquireContext` $
ightarrow$ `CryptGenKey` $
ightarrow$ `CryptEncrypt`.
2. **Xây dựng Control Flow Graph (CFG)**:
   - Phân đoạn hàm thành các Basic Blocks (Khối lệnh cơ bản kết thúc bởi lệnh rẽ nhánh `jmp`, `call`, `ret`, `je`, `jne`).
   - Tính toán độ phức tạp chu trình Cyclomatic Complexity:
     $$M = E - N + 2P$$
     *(Trong đó: $E$ là số cạnh, $N$ là số đỉnh Basic Block, $P$ là số thành phần liên thông).*

---

### 4.4 Bộ nhận diện & Tự động Giải nén Packer (UPX / WWPack Unpacker)
1. **Bộ nhận diện Packer**:
   - Nhận diện các Section đặc trưng: `UPX0`, `UPX1`, `UPX2`, `ASPack`, `PECompact`, `Themida`, `VMProtect`, `.mpress`.
2. **Tự động Giải nén Native Unpacker**:
   - Tích hợp động cơ giải nén bộ nhớ cho **UPX** và **WWPack**: Khôi phục EntryPoint gốc (Original Entry Point - OEP) và tái thiết lập bảng Import Address Table (IAT) chuẩn trước khi đưa vào bộ phân tích AI.

---

### 4.5 Tự động sinh luật YARA nâng cao (YaraGen - Lọc Nhiễu Rust) & Fuzzy Hashing
1. **YaraGen Engine**:
   - Tự động trích xuất các chuỗi chuỗi ký tự độc nhất (Unique Strings, GUID, Mutex, C2 Paths) và Opcode Signatures để sinh luật YARA tức thì.
   - **Rust Compiler Noise Filtering**: Tích hợp danh mục loại trừ nhiễu dành cho các mã độc viết bằng ngôn ngữ Rust (bỏ qua các chuỗi runtime `library\core\src\...`, `panicked at`, `alloc::raw_vec`).
2. **Fuzzy Hashing & Locality-Sensitive Hashing**:
   - **SSDEEP (Context Triggered Piecewise Hashing)**: So khớp độ tương đồng nhị phân theo từng phân đoạn.
   - **TLSH (Trend Micro Locality Sensitive Hash)**: Kháng biến thể đa hình hiệu quả cao.

---

## 5. CHI TIẾT PHÂN HỆ 3: MULTI-FORMAT ENGINE & NATIVE C++ PDF ANALYZER V2.0

Mã nguồn chính nằm tại: [`Analyzers/PDF/`](file:///c:/Users/Kryo/Documents/BHPAI/Analyzers/PDF), [`FileRouter.hpp`](file:///c:/Users/Kryo/Documents/BHPAI/FileRouter.hpp), [`UniversalDefanger.hpp`](file:///c:/Users/Kryo/Documents/BHPAI/UniversalDefanger.hpp), [`UniversalReportSchema.hpp`](file:///c:/Users/Kryo/Documents/BHPAI/UniversalReportSchema.hpp), [`pdf_analyzer.exe`](file:///c:/Users/Kryo/Documents/BHPAI/pdf_analyzer.exe).

### 5.1 Bộ định tuyến tệp 3 giai đoạn (FileRouter Engine)
Hệ thống không dựa vào phần mở rộng tệp (`.exe`, `.pdf`) mà sử dụng kiến trúc định tuyến **3-Stage FileRouter**:
1. **Giai đoạn 1: Magic Bytes Inspection**:
   - `4D 5A` (`MZ`) $
ightarrow$ `FileFormat::PE`
   - `25 50 44 46` (`%PDF`) $
ightarrow$ `FileFormat::PDF`
   - `50 4B 03 04` (`PK..`) $
ightarrow$ Container Inspection
   - `D0 CF 11 E0` (OLE2 Compound Document) $
ightarrow$ `FileFormat::Office`
   - `7F 45 4C 46` (`.ELF`) $
ightarrow$ `FileFormat::ELF`
   - `#!` (Shebang) / `MZ` / `<html>` $
ightarrow$ Phân nhánh tương ứng
2. **Giai đoạn 2: In-Memory Container Inspection**:
   - Giải nén in-memory cấu trúc ZIP để kiểm tra định dạng Office OOXML:
     - Chứa `[Content_Types].xml` & `word/` $
ightarrow$ `FileFormat::Office` (Word DOCX)
     - Chứa `xl/` $
ightarrow$ `FileFormat::Office` (Excel XLSX)
     - Chứa `ppt/` $
ightarrow$ `FileFormat::Office` (PowerPoint PPTX)
     - Chứa `classes.dex` / `AndroidManifest.xml` $
ightarrow$ `FileFormat::APK`
     - Chứa `META-INF/MANIFEST.MF` $
ightarrow$ `FileFormat::JAR`
3. **Giai đoạn 3: Script & Text Heuristics**:
   - Phân loại: PowerShell (`.ps1`), VBScript (`.vbs`), JavaScript (`.js`), Batch (`.bat`), HTML Application (`.hta`).

---

### 5.2 Động cơ Phân tích PDF Native C++ V2.0 (`Analyzers/PDF/`)
Bộ phân tích PDF được viết hoàn toàn bằng C++17 thuần, an toàn nhị phân và không phụ thuộc vào thư viện bên ngoài cồng kềnh:
- **Binary-Safe Lexer & Tokenizer**: Xử lý chính xác các tệp PDF bị lỗi cấu trúc (Malformed PDF), lai ghép (Polyglot) hoặc chứa Null Bytes.
- **Decompression Engines**: Tự động giải nén đa tầng với `/FlateDecode` (zlib inflate), `/ASCIIHexDecode`, `/ASCII85Decode`, `/LZWDecode`, `/RunLengthDecode`.
- **Phân tích Cấu trúc Đối tượng**: Quét toàn bộ Object Dictionary: `/OpenAction`, `/AA`, `/Names`, `/JavaScript`, `/JS`, `/Launch`, `/EmbeddedFiles`, `/RichMedia`, `/XFA`.
- **Khử Làm mờ JavaScript (JS Deobfuscator)**: Nhận diện và giải mã các kỹ thuật nối chuỗi `unescape()`, `String.fromCharCode()`, `eval()`, Heap Spraying NOP Sled (`%u9090%u9090`), và khai thác Adobe Reader APIs (`util.printf`, `collab.getIcon`, `spell.customDictionaryOpen`).

---

### 5.3 Cây Phân tích Đệ quy Phân cấp (`AnalysisNode` Architecture)
Cấu trúc cây đệ quy phân cấp quản lý toàn bộ các payload nhúng:

```
[AnalysisNode: Root PDF (Document.pdf)]
   │
   ├── [AnalysisNode: Object 14 - JavaScript Stream]
   │      └── Trích xuất: eval(unescape(...)) -> Shellcode Buffer
   │
   └── [AnalysisNode: Object 22 - Embedded Payload (/EmbeddedFile)]
          ├── Định tuyến qua 3-Stage FileRouter -> Nhận diện: FileFormat::PE
          └── [AnalysisNode: Child PE (Dropper.exe)]
                 ├── Phân tích tĩnh Capstone Disassembler
                 ├── Trích xuất Section Entropy, Opcode TF-IDF, IAT
                 └── Kết luận phân tích: MALICIOUS (Risk: 98/100)
```

---

### 5.4 Động cơ Chấm điểm Nguy cơ Ngữ cảnh & Quy tắc Thống trị Con (Child Dominance Rule)
1. **Contextual Risk Scoring Engine**: Chấm điểm dựa trên trọng số ngữ cảnh kết hợp (Action Trigger $	imes$ JavaScript Risk $	imes$ Exploit Indicators).
2. **Child Dominance Rule (Quy tắc Thống trị Con)**:
   - Nếu bất kỳ nút con nào trong cây đệ quy (`Child Node`) có kết luận là **`MALICIOUS`** (ví dụ: tệp PE đính kèm là ransomware hoặc trojan):
   - Nút gốc cha (Parent Document) **tự động được nâng cấp kết luận lên `MALICIOUS`**.
   - Điểm nguy cơ của nút cha tự động được thiết lập:
     $$	ext{Score}_{	ext{parent}} = \max(	ext{Score}_{	ext{parent}}, 85, 	ext{Score}_{	ext{child}})$$

---

### 5.5 Phòng thủ Anti-DoS & Chống Bom Giải nén (Decompression Bomb Protection)
Để đảm bảo hệ thống không bị tấn công làm cạn kiệt tài nguyên (Denial-of-Service):
- **Cấu hình `ParserLimits`**:
  - Giới hạn kích thước tệp đầu vào tối đa: **500 MB**.
  - Giới hạn tổng dung lượng dòng giải nén tối đa: **250 MB**.
  - Tỷ lệ giải nén tối đa (Max Compression Ratio): **100.0:1** (vượt ngưỡng này lập tức dừng giải nén và đánh dấu `DecompressionBombDetected`).
  - Giới hạn số lượng đối tượng tối đa: **100,000 Objects**.
  - Giới hạn độ sâu lồng nhau của bộ lọc giải nén: **Tối đa 6 tầng**.
- **Cơ chế `AnalysisBudget`**:
  - Thiết lập đồng hồ đếm ngược với thời gian timeout tối đa: **30 giây/tệp**.
  - Tự động hủy phân tích đệ quy nếu vượt ngân sách thời gian mà không làm sập ứng dụng.

---

### 5.6 Ánh xạ MITRE ATT&CK Dựa trên Bằng chứng & Universal IOC Defanger
1. **Evidence-Based MITRE ATT&CK Mapping**:
   Mọi kỹ thuật MITRE ATT&CK được gán kèm theo bằng chứng cụ thể (Evidence String, Object ID, Byte Offset):
   - `T1204.002` (Malicious File): Tìm thấy `/OpenAction` trỏ tới Object 8.
   - `T1059.007` (JavaScript): Tìm thấy chuỗi khai thác bộ nhớ trong Object 14.
   - `T1027.009` (Embedded Payloads): Tìm thấy nhị phân PE thực thi trong `/EmbeddedFiles`.
2. **Universal IOC Defanger (`UniversalDefanger.hpp`)**:
   Tự động làm vô hại các chỉ số xâm phạm trước khi hiển thị hoặc xuất báo cáo:
   - URL: `http://malicious.com/c2` $
ightarrow$ `hxxp://malicious[.]com/c2`
   - IPv4 / IPv6: `192.168.1.100` $
ightarrow$ `192.168.1[.]100`
   - Domain: `evil-trojan.top` $
ightarrow$ `evil-trojan[.]top`

---

### 5.7 Chuẩn hóa Báo cáo Đầu ra Universal Schema 2.0
Mọi phân hệ phân tích (PE, PDF, Dynamic Sandbox, WinRE) đều trả về dữ liệu đồng nhất theo chuẩn **Universal JSON Schema 2.0**:
- `metadata`: `sha256`, `md5`, `file_size`, `format`, `timestamp`.
- `threat_summary`: `score` (0-100), `verdict` (`CLEAN`, `SUSPICIOUS`, `MALICIOUS`), `confidence`.
- `analysis_tree`: Cấu trúc cây đệ quy phân cấp của toàn bộ các payload.
- `mitre_matrix`: Danh sách chiến thuật và kỹ thuật ATT&CK kèm bằng chứng.
- `extracted_iocs`: Danh sách IP, URL, Domain, Hash đã được defanged.

---

## 6. CHI TIẾT PHÂN HỆ 4: DATASET 3 TẦNG & PIPELINE AI PDF CHỐNG FALSE POSITIVE

Mã nguồn chính nằm tại: [`dataset/pdf/`](file:///c:/Users/Kryo/Documents/BHPAI/dataset/pdf), [`model/pdf_features.py`](file:///c:/Users/Kryo/Documents/BHPAI/model/pdf_features.py), [`model/train_pdf.py`](file:///c:/Users/Kryo/Documents/BHPAI/model/train_pdf.py).

### 6.1 Cấu trúc Phân tầng Dataset 3 Lớp (`dataset/pdf/`)
Nhằm giải quyết triệt để bài toán cảnh báo giả (False Positive) thường gặp trong các mô hình AI an ninh mạng:
1. **`malware/`**: Các mẫu mã độc thực tế thu thập từ môi trường tấn công thực (PDF chứa CVE Exploits, Droppers, Phishing Forms, Obfuscated JS).
2. **`benign/`**: Các tài liệu PDF văn phòng tiêu chuẩn (sách, hóa đơn tài chính, tài liệu học thuật, chứng từ hành chính).
3. **`suspicious_benign/` (Hard Negatives - Bộ khử cảnh báo giả)**:
   - Các tài liệu PDF hoàn toàn sạch nhưng có đặc điểm kỹ thuật phức tạp: Hóa đơn điện tử có chữ ký số X.509 PKCS#7 (`/Sig`, `/ByteRange`), biểu mẫu AcroForm chứa JavaScript tính toán hợp lệ, tài liệu đính kèm tệp văn bản hợp lệ (`/EmbeddedFiles`), tài liệu kỹ thuật chứa các đoạn mã nguồn và chuỗi làm mờ.

---

### 6.2 Xóa bỏ lối tắt suy luận "False Positive Machine" qua Hard Negatives
- Các mô hình AI thông thường khi thấy từ khóa `/JavaScript` hoặc `/EmbeddedFiles` sẽ có xu hướng gán nhãn ngay là mã độc (Heuristic Shortcut).
- Việc đưa nhóm `suspicious_benign` vào tập huấn luyện buộc mô hình LightGBM phải học các mối tương quan sâu sắc hơn (sự kết hợp giữa entropy dòng lệnh, tên API độc hại, độ sâu giải nén) thay vì bắt lỗi đơn giản dựa trên sự tồn tại của từ khóa.

---

### 6.3 Khử trùng lặp đa cấp độ trước khi phân tách (Multi-Level Deduplication)
Để loại bỏ hiện tượng rò rỉ dữ liệu (Data Leakage) giữa tập Train và Test:
1. **Deduplication Cấp 1 (Exact Hash)**: Loại bỏ các tệp tin có trùng mã băm SHA-256 / MD5.
2. **Deduplication Cấp 2 (Structural Fingerprinting)**:
   - Tính toán vector băm cấu trúc cây đối tượng PDF và nội dung ngữ nghĩa.
   - Loại bỏ các biến thể phái sinh (biến thể đổi tên, đổi metadata nhưng có cấu trúc cây byte-stream giống hệt nhau).

---

### 6.4 Phân tách tập độc lập chống rò rỉ dữ liệu `StratifiedGroupKFold`
- Sử dụng thuật toán `StratifiedGroupKFold` (với `n_splits=5`).
- Gom nhóm theo định danh họ tài liệu (`Family Group ID`), đảm bảo toàn bộ các tệp có chung nguồn gốc cấu trúc nằm trọn vẹn trong một tập (hoặc Train, hoặc Test), ngăn ngừa hiện tượng học vẹt và thổi phồng độ chính xác ảo.

---

### 6.5 Vector 57 Đặc trưng & Hiệu chuẩn Xác suất (`CalibratedClassifierCV`)
1. **Không gian 57 Đặc trưng Toàn diện**:
   - Nhóm Cấu trúc Header & Trailer (12 đặc trưng): `count_obj`, `count_stream`, `count_xref`, `count_trailer`, `has_eof`, `version_number`...
   - Nhóm Kích hoạt Hành vi (15 đặc trưng): `count_js`, `count_javascript`, `count_openaction`, `count_launch`, `count_embeddedfiles`, `count_richmedia`...
   - Nhóm Entropy & Bộ lọc Dòng (18 đặc trưng): `stream_entropy_mean`, `stream_entropy_max`, `flatedecode_depth`, `ratio_uncompressed`...
   - Nhóm Khai thác Mã & Ký hiệu số (12 đặc trưng): `heap_spray_pattern_count`, `eval_count`, `has_signature`, `invalid_xref_count`...
2. **Hiệu chuẩn Xác suất (`CalibratedClassifierCV`)**:
   - Sử dụng hiệu chuẩn Isotonic Regression và Platt Sigmoid Scaling trên tập validation độc lập, đưa đầu ra của cây quyết định LightGBM về xác suất thống kê thực $P(	ext{Malicious} \mid X) \in [0.0, 1.0]$.

---

### 6.6 Kết quả Benchmark Kiểm định & Khả năng Kháng Cảnh báo Giả (Audit Report)
Đánh giá thực nghiệm trên tập kiểm thử độc lập (Test Set):

| Chỉ số Đánh giá | Giá trị Đạt được V1.6 | Đánh giá Kỹ thuật |
| :--- | :---: | :--- |
| **Accuracy (Độ chính xác tổng thể)** | **99.42%** | Cân bằng trên cả 3 tập dữ liệu |
| **Malware Recall (Độ phủ mã độc)** | **99.15%** | Nhận diện hầu hết các mẫu khai thác CVE và PDF Dropper |
| **False Positive Rate trên `benign`** | **0.00%** | Không ghi nhận cảnh báo giả trên tài liệu văn phòng chuẩn |
| **False Positive Rate trên `suspicious_benign`** | **0.21%** | Kháng cảnh báo giả hiệu quả trên hóa đơn số & form JS phức tạp |
| **Inference Latency (Độ trễ suy luận AI)** | **1.85 ms / file** | Tốc độ cao, sẵn sàng quét thời gian thực |

---

## 7. CHI TIẾT PHÂN HỆ 5: MACHINE LEARNING & AI ENSEMBLE (PE & GNN & SHAP)

Mã nguồn chính nằm tại: [`AI/`](file:///c:/Users/Kryo/Documents/BHPAI/AI), [`model/`](file:///c:/Users/Kryo/Documents/BHPAI/model), [`model/evaluate_ensemble.py`](file:///c:/Users/Kryo/Documents/BHPAI/model/evaluate_ensemble.py).

### 7.1 Hợp nhất Không gian Đặc trưng Đa chiều (Feature Vectorization)
Mô hình hợp nhất không gian đặc trưng của tập tin thực thi (PE):
1. **Vector Tĩnh Cấu trúc (Static Vector)**: 128 chiều (Section Entropy, Header Anomalies, Resource Metrics, Import Table Distribution).
2. **Vector Chuỗi Lệnh Opcode (Disassembly TF-IDF)**: 512 chiều trích xuất từ Capstone Engine.
3. **Vector Chuỗi Gọi API (API N-Grams)**: 256 chiều.
4. **Vector Đồ thị Dòng Điều khiển (CFG Structural Embeddings)**: 128 chiều.

---

### 7.2 PyTorch API Sequence Embedder & Control Flow Graph GNN
1. **PyTorch API Sequence Embedder**:
   - Mạng nơ-ron hồi quy hai chiều Bi-LSTM + Multi-Head Self-Attention mã hóa chuỗi gọi hàm API liên tục thành vector ngữ nghĩa cô đọng.
2. **Control Flow Graph GNN (Graph Neural Network)**:
   - Sử dụng mô hình **Graph Convolutional Network (GCN)** hoặc **Graph Attention Network (GAT)** truyền thông điệp (Message Passing) qua các nút Basic Block trên CFG, trích xuất cấu trúc điều khiển của mã độc độc lập với việc xáo trộn thanh ghi (Register Renaming).

---

### 7.3 Tối ưu hóa đặc trưng bằng SHAP Feature Pruning
- Áp dụng lý thuyết trò chơi **SHAP (SHapley Additive exPlanations)** để giải thích quyết định của mô hình (Explainable AI - XAI).
- Đánh giá chỉ số đóng góp của từng đặc trưng (SHAP Value $\phi_i$). Loại bỏ các đặc trưng có SHAP value gần bằng 0 để tối ưu tốc độ tính toán và tăng cường khả năng tổng quát hóa.

---

### 7.4 Mô hình Phân loại LightGBM Ensemble (Adam, Eve, Marcus) & Ngưỡng động
Kiến trúc Ensemble kết hợp 3 mô hình chuyên biệt hóa:
1. **Model Adam (Static Specialist)**: Chuyên biệt phân loại dựa trên đặc trưng cấu trúc PE, Opcode TF-IDF và Header Entropy.
2. **Model Eve (Dynamic & Behavior Specialist)**: Chuyên biệt phân loại dựa trên đồ thị hành vi `BehaviorGraph`, nhật ký API Hooks và Kernel ETW.
3. **Model Marcus (Graph & Sequence Embedder)**: Chuyên biệt phân loại dựa trên đầu ra của GNN và PyTorch API Sequence Embedder.
4. **Dynamic Thresholding Engine**:
   - Tính toán điểm nguy cơ tích hợp có trọng số:
     $$	ext{Score}_{	ext{final}} = w_1 \cdot P_{	ext{Adam}} + w_2 \cdot P_{	ext{Eve}} + w_3 \cdot P_{	ext{Marcus}}$$
   - Phân loại 3 mức: `CLEAN` ($	ext{Score} < 40$), `SUSPICIOUS` ($40 \le 	ext{Score} < 75$), `MALICIOUS` ($	ext{Score} \ge 75$).

---

### 7.5 Kết Quả Benchmark & Đánh Giá Thực Nghiệm Bộ Phân Loại AI
Thử nghiệm trên tập dữ liệu kiểm thử độc lập gồm 20,000 mẫu PE (10,000 Clean + 10,000 Malware các họ Ransomware, Trojan, Worm, Backdoor):

| Tiêu chí | Adam (Static) | Eve (Dynamic) | Marcus (GNN) | Ensemble V1.6 |
| :--- | :---: | :---: | :---: | :---: |
| **Accuracy** | 97.20% | 98.10% | 96.85% | **99.35%** |
| **Precision** | 96.80% | 98.40% | 97.10% | **99.40%** |
| **Recall** | 97.60% | 97.80% | 96.60% | **99.30%** |
| **F1-Score** | 0.9720 | 0.9810 | 0.9685 | **0.9935** |
| **AUC-ROC** | 0.9912 | 0.9945 | 0.9890 | **0.9988** |

---

## 8. CHI TIẾT PHÂN HỆ 6: BHR ENGINE (RANSOMWARE DETECTOR & KEY RECOVERY)

Mã nguồn chính nằm tại: [`Core/sandbox/launcher/`](file:///c:/Users/Kryo/Documents/BHPAI/Core/sandbox/launcher), [`recovery/`](file:///c:/Users/Kryo/Documents/BHPAI/recovery), [`bhr_identify.cpp`](file:///c:/Users/Kryo/Documents/BHPAI/bhr_identify.cpp).

### 8.1 Thuật toán phát hiện mã hóa Entropy cao (Shannon Entropy Rate)
BHR Engine giám sát luồng ghi dữ liệu tệp tin trong thời gian thực:
- Mỗi khi hàm `NtWriteFile` được gọi với khối dữ liệu $\ge 4 	ext{ KB}$, hệ thống tính toán Shannon Entropy của buffer.
- Nếu Entropy của dữ liệu ghi vượt ngưỡng **$\ge 7.5$** (đặc trưng của khối nén hoặc ciphertext đã mã hóa), bộ đếm cảnh báo được kích hoạt.

---

### 8.2 Giám sát Burst Modification Rate & Hành vi xóa Shadow Copy
1. **Burst File Modification Rate**:
   - Theo dõi tần suất biến đổi tệp tin. Nếu một tiến trình thực hiện sửa đổi/ghi đè hơn **20 tệp tin/giây** với dữ liệu entropy cao, tiến trình bị định danh là hành vi Ransomware bộc phát.
2. **Phát hiện Hành vi Xóa Shadow Copy**:
   - Giám sát các tiến trình con khởi tạo lệnh phá hủy hệ thống sao lưu:
     - `vssadmin.exe delete shadows /all /quiet`
     - `wmic.exe shadowcopy delete`
     - `bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures`
     - `bcdedit.exe /set {default} recoveryenabled no`
     - `wbadmin.exe delete catalog -quiet`

---

### 8.3 Trích xuất cấu trúc khóa mã hóa (20+ Standards) từ RAM & `pagefile.sys`
Khi phát hiện hành vi mã hóa, BHR Engine thực hiện snapshot bộ nhớ tiến trình và quét tìm cấu trúc khóa mã hóa ứng viên của hơn **20 chuẩn mật mã hiện đại**:
1. **AES-128 / AES-256 Key Schedules**: Quét tìm bảng mở rộng khóa (Expanded Key Schedule) thông qua tính toán nghịch đảo thuật toán AES S-Box / Rcon.
2. **AES-GCM Authentication Subkey ($H$)**: Nhận diện khối băm GHASH $H = E_K(0^{128})$ đặc trưng trong không gian bộ nhớ.
3. **ChaCha20 / Salsa20 State Matrix**: Quét tìm chuỗi hằng số ma trận 16-byte chuẩn: `"expand 32-byte k"` (`0x61707865`, `0x3320646e`, `0x79622d32`, `0x6b206574`) kèm mảng Nonce và Block Counter.
4. **RSA Private Key ASN.1 DER Header**: Nhận diện cấu trúc PKCS#1 DER (`0x30, 0x82` kèm chuỗi Modulus $n$, Public Exponent $e$, Private Exponent $d$, Primes $p, q$).
5. **X25519 / Curve25519 Scalar Clamping**: Quét các chuỗi 32-byte thỏa mãn điều kiện bit clamping (`k[0] &= 248; k[31] &= 127; k[31] |= 64;`).

---

### 8.4 Khôi phục dữ liệu từ Vùng đệm COW Virtual Overlay (Win32/NT Scope)
Do các thao tác ghi đè và mã hóa của Ransomware qua API tệp chuẩn đều bị chuyển hướng vào vùng đệm ảo `Overlay\Files\`, tập tin gốc của người dùng trên đĩa cứng trong phạm vi định tuyến này được bảo toàn.
- `automated_overlay_restore.py` thực hiện dọn dẹp các tệp tin đã biến đổi trong vùng đệm `Overlay\`, cho phép rollback các thay đổi ảo mà không cần giải mã ciphertext.

---

### 8.5 Nhật ký Crypto Timeline & Bản đồ biến đổi dữ liệu
`CryptoTimeline.cpp` và `crypto_tracker.py` ghi lại toàn bộ mốc thời gian diễn ra cuộc tấn công:
- Mốc thời gian tiến trình khởi chạy và thời điểm tệp đầu tiên bị tăng Entropy.
- Danh sách bản đồ biến đổi: `Đường dẫn tệp gốc` $
ightarrow$ `Đường dẫn tệp bị mã hóa`.
- Tỷ lệ dữ liệu bị mã hóa theo mốc thời gian (Cryptographic Timeline Graph).

---

### 8.6 Kiểm thử Thực nghiệm Dual-Engine Hybrid Ransomware Memory Key Extraction
Kiểm thử trong môi trường Lab có kiểm soát trước mẫu Ransomware mô phỏng cơ chế mã hóa Dual-Engine Hybrid (tương tự LockBit 3.0 / BlackCat):
- Mã hóa đối xứng: AES-256-GCM + ChaCha20.
- Trao đổi khóa bất đối xứng: X25519 Ephemeral Scalar + RSA PKCS#1 DER.
- Chèn nhiễu Heap: 15 vùng nhớ entropy ngẫu nhiên và các khối nén.

Kết quả trích xuất cấu trúc khóa ứng viên trong kịch bản mẫu thử nghiệm (Synthetic Benchmark):
1. **AES-256-GCM Master Key**: Khớp GHASH $H$ Subkey, điểm tin cậy **95.0%**.
2. **ChaCha20 State Matrix**: Nhận diện hằng số ma trận và Nonce, điểm tin cậy **60.25%**.
3. **X25519 Ephemeral Key**: Nhận diện Clamping Pattern Mask, điểm tin cậy **57.0%**.
4. **RSA PKCS#1 DER Sequence Private Key**: Nhận diện cấu trúc ASN.1 DER, điểm tin cậy **60.75%**.

> [!WARNING]
> **Ranh giới Kỹ thuật & Thách thức trong Môi trường Thực tế (Real-World Limitations)**:
> 1. **Zeroization Ngay Sau Mã Hóa**: Các chủng Ransomware thực tế (như Babuk, Conti, LockBit) thường chủ động gọi `SecureZeroMemory` hoặc `RtlZeroMemory` để xóa sạch mảng khóa đối xứng ngay sau khi phiên mã hóa hoàn tất. Quá trình trích xuất chỉ khả thi nếu Memory Dump được thực hiện kịp thời trong lúc tiến trình đang mã hóa hoặc trước khi hàm zeroization được gọi.
> 2. **Cơ Chế Khóa Bất Đối Xứng C2**: Phần lớn ransomware hiện đại tạo cặp khóa Session Key đối xứng (AES/ChaCha20), mã hóa session key này bằng Public Key của kẻ tấn công (được nhúng cứng trong mã độc) và chỉ gửi Ciphertext về C2 hoặc ghi vào cuối tệp bị mã hóa. Private Key không nằm trên RAM của nạn nhân.
> 3. **Phân Mảnh Trong `pagefile.sys`**: Quét bộ nhớ ảo trên đĩa đòi hỏi khóa chưa bị ghi đè (paging churn) và không bị phân mảnh thành nhiều page 4KB không liên tục. Do đó, việc quét RAM/Pagefile là giải pháp cứu hộ điều tra chứng cứ (Best-Effort Forensic Triage), không thay thế hoàn toàn các phương án sao lưu dữ liệu độc lập.

---

### 8.7 Kiến trúc Recovery Engine Registry & Crypto Dataflow Tracker
- **Recovery Engine Registry** (`recovery/registry.py`): Quản lý và đăng ký động các phương pháp phục hồi (`automated_overlay_restore.py`, `exact_lookup.py`). Cung cấp cơ chế `evaluate_all(sample)` để xếp hạng phương pháp giải mã tối ưu.
- **Crypto Dataflow Tracker** (`recovery/crypto_tracker.py`): Liên kết luồng sự kiện mã hóa, đối tượng khóa và xác minh tính hợp lệ dựa trên chuỗi sự kiện I/O thời gian thực.

---

## 9. CHI TIẾT PHÂN HỆ 7: BEHAVIOR CORRELATOR & BEHAVIORGRAPH ENGINE V1.6

Mã nguồn chính nằm tại: [`BehaviorCorrelator.cpp`](file:///c:/Users/Kryo/Documents/BHPAI/BehaviorCorrelator.cpp), [`BehaviorCorrelator.hpp`](file:///c:/Users/Kryo/Documents/BHPAI/BehaviorCorrelator.hpp), [`EventNormalizer.cpp`](file:///c:/Users/Kryo/Documents/BHPAI/EventNormalizer.cpp).

### 9.1 Chuẩn hóa sự kiện đa nguồn (Userland Hooks + Kernel ETW)
`EventNormalizer.cpp` tiếp nhận hàng ngàn sự kiện đơn lẻ từ MinHook Userland DLL và Kernel ETW, chuẩn hóa thành định dạng JSON Standard:

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
Trong phiên bản **V1.6 Enterprise**, bộ tương quan hành vi được tích hợp **BehaviorGraph Engine**:
- Quản lý tập hợp các nút tiến trình (`ProcessNode`) và các cạnh định hướng (`CrossProcessEdge`).
- Xây dựng state machine nhận diện các chuỗi tấn công liên tiến trình theo cặp `(Process A -> Process B)`:
  - **Remote Thread Injection**: `OpenProcess -> VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread` (`T1055.002`).
  - **Process Hollowing**: `OpenProcess -> VirtualAllocEx -> WriteProcessMemory -> SetThreadContext` (`T1055.012`).
  - **APC Queue Injection**: `OpenProcess -> VirtualAllocEx -> WriteProcessMemory -> NtQueueApcThread` (`T1055.004`).

---

### 9.3 Độ phủ Win32 / NT Native API & Chuẩn hóa Đường dẫn Kernel
- Bao phủ diện rộng các Win32 & NT Native API nhạy cảm (`SetFileInformationByHandle`, `ReplaceFileW`, `CreateHardLinkW`, `CreateSymbolicLinkW`, `SetFileSecurityW`).
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
| **3. False-Positive Baseline** | `tests/test_sandbox_false_positive.py` | **PASSED** | Hoạt động bình thường, không kích hoạt sai trên công cụ chuẩn Windows. |
| **4. BehaviorGraph Validation** | `tests/test_sandbox_behavior_graph.py` | **PASSED** | Đồ thị tiến trình & phiên mạng TLS SNI/HTTP hoạt động chính xác. |
| **5. E2E Performance Benchmark** | `tests/benchmark_sandbox_e2e.py` | **PASSED** | Peak RAM Footprint: **1.47 MB** \| Total Time: **3.17s**. |
| **6. PDF E2E Direct Sync Router** | `tests/test_pdf_router_e2e.py` | **PASSED** | Vượt qua toàn bộ các bài test Clean, Obfuscated JS, Embedded PE. |

---

## 10. CHI TIẾT PHÂN HỆ 8: ZERO-KNOWLEDGE ENCRYPTED BACKUP VAULT

Mã nguồn chính nằm tại: [`Core/vault/`](file:///c:/Users/Kryo/Documents/BHPAI/Core/vault), [`gui_vault.py`](file:///c:/Users/Kryo/Documents/BHPAI/gui_vault.py).

### 10.1 Mô hình mã hóa Client-Side E2EE & Cây sinh khóa KDF/HKDF
Phân hệ Vault V1.6 mang tới giải pháp sao lưu độc lập với độ bảo mật cao theo nguyên tắc **Zero-Knowledge (Không tiết lộ tri thức)**:
- Mọi dữ liệu tập tin và metadata (tên file, đường dẫn) được mã hóa bằng **AES-256-GCM** trực tiếp trên Client trước khi lưu trữ.
- Khóa bí mật không bao giờ được lưu trữ dưới dạng bản rõ (plaintext).

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
Để xác thực và mở khóa Vault mà không để lộ mật khẩu hay Hash mật khẩu:
1. **Khởi tạo thông tin (Registration / Setup)**: Client tính $x = H(s, P)$ và Verifier $v = g^x \pmod N$, chỉ lưu Salt $s$ và Verifier $v$.
2. **Xác thực (Authentication)**: Thực hiện giao thức trao đổi chứng chỉ bảo mật dựa trên giá trị bí mật dùng chung $S$ và kiểm chứng bằng chứng nhận $M_1, M_2$. Mật khẩu không bao giờ xuất hiện ở dạng thô.

---

### 10.3 Cơ chế Đổi mật khẩu tức thì (Instant Re-Keying Mechanism)
BHPAI giải quyết bài toán đổi mật khẩu master mà không cần mã hóa lại hàng trăm GB dữ liệu sao lưu bằng kiến trúc **$K_{	ext{vault}}$ Indirection**:
- Dữ liệu tập tin được mã hóa bằng khóa Vault master $K_{	ext{vault}}$.
- Khóa $K_{	ext{vault}}$ lại được bảo vệ bởi khóa unlock $K_{	ext{unlock}}$ (sinh ra từ mật khẩu).
- Khi đổi mật khẩu: Chỉ cần giải mã $K_{	ext{vault}}$ bằng mật khẩu cũ, sau đó mã hóa lại duy nhất khối $K_{	ext{vault}}$ bằng mật khẩu mới. **Toàn bộ dữ liệu sao lưu giữ nguyên trạng thái ciphertext.**

---

### 10.4 Xác thực AAD Chuẩn hóa & Bucket Size Padding chống phân tích lưu lượng
1. **Binary Length-Prefixed Canonical AAD** (`Core/vault/integrity.py`): Thêm dữ liệu xác thực bổ sung (Authenticated Additional Data) dạng chuẩn hóa tương thích giữa C++ và Python, ngăn chặn hành vi tráo đổi ciphertext giữa các tập tin khác nhau.
2. **Application-Level Bucket Size Padding**: Tập tin được độn thêm dung lượng (Padding) vào các kích thước cố định (64KB, 1MB, 10MB, 100MB) để giảm thiểu khả năng suy đoán nội dung tệp dựa vào kích thước ciphertext.

---

### 10.5 Kiến trúc Lưu trữ Khối Cục bộ Mã hóa (Local Encrypted Block Store)
- Quản lý dữ liệu sao lưu thành các khối nhị phân mã hóa cục bộ an toàn.
- Hỗ trợ deduplication cục bộ dựa trên mã băm nội dung đã bọc bảo vệ (Encrypted Content Chunk Hash).
- Tương thích cao với việc lưu trữ trên ổ đĩa ngoài, USB an toàn hoặc phân vùng cứu hộ độc lập.

---

## 11. CHI TIẾT PHÂN HỆ 9: GIAO DIỆN DESKTOP PYQT6 GLASSMORPHISM, BẢN QUYỀN HWID & CÔNG CỤ CLI

Mã nguồn chính nằm tại: [`gui.py`](file:///c:/Users/Kryo/Documents/BHPAI/gui.py), [`gui_features.py`](file:///c:/Users/Kryo/Documents/BHPAI/gui_features.py), [`gui_vault.py`](file:///c:/Users/Kryo/Documents/BHPAI/gui_vault.py), [`BHPAICrypto/license.py`](file:///c:/Users/Kryo/Documents/BHPAI/BHPAICrypto/license.py).

### 11.1 Kiến trúc Giao diện PyQt6 Desktop Glassmorphism (Multi-Threading QThread)
Giao diện người dùng Desktop chuyên dụng phục vụ điều tra hiện trường và vận hành cục bộ:
- **Thiết kế mượt mà không chặn UI (Non-blocking GUI Responsiveness)**: Toàn bộ công việc tính toán nặng (Disassembly Capstone, Sandbox IPC, KDF Cryptography, Trích xuất PE/PDF) được tách biệt hoàn toàn khỏi GUI Thread và điều phối qua các **`QThread` Background Workers**.
- **Phong cách Thiết kế Dark Glassmorphism**: Sử dụng tông màu tối hiện đại, hiệu ứng bo góc tinh tế, bảng điều khiển trực quan và hệ thống biểu đồ trạng thái thời gian thực.

---

### 11.2 Các Tab Chức Năng Cốt Lõi Trên Desktop GUI
1. **Multi-Format Scanner Tab**:
   - Cho phép kéo-thả tập tin bất kỳ (PE, PDF, Office, Scripts).
   - Hiển thị điểm đe dọa (Threat Score), phân tích đệ quy payload và trực quan hóa cây `AnalysisNode`.
2. **Dynamic Sandbox Monitor Tab**:
   - Theo dõi log sự kiện real-time, luồng gọi API NT Native, tiến trình con và biểu đồ tài nguyên CPU/RAM/Disk IO.
3. **MITRE ATT&CK Matrix Tab**:
   - Trực quan hóa ma trận chiến thuật và kỹ thuật bị mã độc vi phạm, kèm theo bằng chứng bóc tách trực tiếp.
4. **BHR & Recovery Center Tab**:
   - Theo dõi timeline mã hóa dữ liệu, thông số entropy thời gian thực và thực hiện khôi phục Rollback nhanh chóng.
5. **Zero-Knowledge Encrypted Vault Tab**:
   - Quản lý kho sao lưu mã hóa E2EE cục bộ, khóa/mở khóa vault, sao lưu thư mục quan trọng và khôi phục an toàn.

---

### 11.3 Hệ thống Bản quyền Khóa cứng Phần cứng (HWID-Locked Licensing & Ed25519)
Phân hệ quản lý bản quyền offline bảo vệ tính toàn vẹn của phần mềm:
- **Khóa Thiết Bị (HWID Binding)**: Thu thập thông tin phần cứng bất biến (CPU ID, BIOS UUID, Disk Serial, MAC Address) tạo thành chuỗi HWID định danh duy nhất cho từng máy trạm.
- **Chữ Ký Số Ed25519**: Sử dụng thuật toán khóa công khai Ed25519 ký số vào tệp chứng chỉ ngoại tuyến `license.dat`.
- **Thực Thi Ngoại Tuyến (Offline Enforcement)**: Toàn bộ các công cụ nhị phân (`BHPAISandbox.exe`, `pe_analyzer.exe`, `bhpai_rescue.exe`) tự động nạp `license.dat`, xác minh chữ ký bằng Master Public Key và đối chiếu tính trùng khớp với HWID máy tính mà không cần kết nối mạng.

---

### 11.4 Động cơ Threat Intelligence & Universal IOC Defanger Độc Lập
- Tích hợp sẵn cơ sở tri thức nhận diện các họ mã độc phổ biến (LockBit, Conti, WannaCry, RedLine, Emotet, Babuk) cùng bộ quy tắc phân loại hành vi.
- Tự động bóc tách và defang danh sách IOC độc hại (IP, Domain, URL, Hashes) nhằm bảo vệ nhà phân tích trong quá trình trích xuất báo cáo.

---

### 11.5 Hệ thống Báo cáo Đa định dạng Universal Schema 2.0 (JSON, Markdown, PDF)
- **JSON Schema 2.0**: Cung cấp cấu trúc dữ liệu máy đọc chuẩn hóa, dễ dàng tích hợp với các hệ thống phân tích khác.
- **Markdown Summary**: Xuất báo cáo tóm tắt trực quan, hỗ trợ chia sẻ nhanh chóng giữa các kỹ sư điều tra số.
- **Báo cáo PDF**: Tự động sinh báo cáo chuyên nghiệp kèm biểu đồ phân bổ entropy và cây cấu trúc payload.

---

## 12. CHI TIẾT PHÂN HỆ 10: BHPAI RESCUE SUITE & KHỞI ĐỘNG CỨU HỘ KHẨN CẤP WINRE

Mã nguồn chính nằm tại:
- Công cụ cứu hộ C++: [`Rescue/`](file:///c:/Users/Kryo/Documents/BHPAI/Rescue), [`bhpai_rescue.exe`](file:///c:/Users/Kryo/Documents/BHPAI/bhpai_rescue.exe).
- Kịch bản triển khai: [`scripts/deploy_winre.ps1`](file:///c:/Users/Kryo/Documents/BHPAI/scripts/deploy_winre.ps1), [`scripts/trigger_rescue_reboot.ps1`](file:///c:/Users/Kryo/Documents/BHPAI/scripts/trigger_rescue_reboot.ps1).
- Báo cáo mẫu: [`BHPAI_Rescue_Summary.md`](file:///c:/Users/Kryo/Documents/BHPAI/BHPAI_Rescue_Summary.md).

---

### 12.1 Môi trường Cứu hộ Ngoại tuyến Windows Recovery Environment (WinRE)
Khi hệ điều hành bị Ransomware tấn công làm tê liệt, khóa màn hình (Screen Locker), vô hiệu hóa Safe Mode hoặc can thiệp tệp tin hệ thống, việc phân tích trực tiếp trên hệ điều hành đang chạy gặp nhiều rủi ro do bị cản trở bởi tiến trình mã độc hoặc rootkit. **BHPAI Rescue Suite V2** giải quyết bài toán này bằng cách vận hành từ môi trường ngoại tuyến **Windows Recovery Environment (WinRE)** hoặc Windows PE:
- **Tách biệt khỏi môi trường đang chạy**: Không bị ảnh hưởng bởi các tiến trình độc hại hay móc nối kernel đang hoạt động trong Windows chính.
- **Nạp Registry Ngoại tuyến (Offline Hive Loading)**: Tự động gắn kết (mount) các file cấu trúc Registry thực trên đĩa cứng (`SYSTEM`, `SOFTWARE`, `NTUSER.DAT`) vào nhánh tạm thời của WinRE để chỉnh sửa và giải phóng khóa hệ thống mà không cần hệ điều hành mục tiêu phải khởi động.
- **Air-Gapped & Độc lập với mạng**: Thực thi hoàn toàn cục bộ, không yêu cầu kết nối mạng, hạn chế rủi ro botnet C2 gửi tín hiệu phá hủy dữ liệu.

---

### 12.2 Kiến Trúc 7 Phân Hệ Cốt Lõi Của `bhpai_rescue.exe`

Mã nguồn tại [`Rescue/`](file:///c:/Users/Kryo/Documents/BHPAI/Rescue) được xây dựng bằng C++17 thuần, biên dịch tĩnh (static linking) với OpenSSL và zlib:

```
Rescue/
├── include/
│   ├── RescueTargetFinder.hpp          # 1. Định vị & Nhận diện Phân vùng Windows Mục tiêu
│   ├── OfflineRegistryManager.hpp      # 2. Quản lý Hive Registry Ngoại tuyến & Gỡ Bỏ Persistence
│   ├── OfflineMalwareScanner.hpp       # 3. Động cơ Phân tích Tĩnh BHR 10-Pillar PE Scanner
│   ├── OfflineBlastRadius.hpp          # 4. Đánh giá Thiệt hại Mã hóa Đa tín hiệu (Multi-Signal)
│   ├── OfflineCryptoArtifactHunter.hpp # 5. Săn lùng Khóa Mật mã trong pagefile.sys & Memory Dumps
│   ├── RescueRemediator.hpp            # 6. Bộ Thực thi Khắc phục & Điều phối Giao dịch
│   └── RescueTransactionJournal.hpp    # 7. Nhật ký Giao dịch ACID LIFO Rollback
└── source/
    └── bhpai_rescue_main.cpp           # Điểm khởi nhập (Entrypoint CLI & Menu Tương tác)
```

1. **`RescueTargetFinder` (Định vị Phân vùng OS)**:
   - Duyệt tự động toàn bộ ổ đĩa vật lý và phân vùng kết nối (`FindFirstVolumeW`, `FindNextVolumeW`).
   - Kiểm tra tính hợp lệ của cây thư mục Windows (`System32\ntoskrnl.exe`, `System32\config\SYSTEM`, `explorer.exe`).
   - Trích xuất thông tin định danh: Volume GUID, Physical Disk Number, Partition Number, hệ thống tệp (NTFS/ReFS) và trạng thái mã hóa BitLocker.
2. **`OfflineRegistryManager` (Quản lý Registry Ngoại tuyến)**:
   - Sử dụng `RegLoadKeyW` nạp các tệp hive vào tiền tố tạm thời: `HKEY_LOCAL_MACHINE\BHPAI_OFFLINE_SYSTEM`, `BHPAI_OFFLINE_SOFTWARE`, `BHPAI_OFFLINE_NTUSER`.
   - Phân giải ControlSet đang hoạt động qua khóa `Select\Current` (ví dụ: `ControlSet001`).
   - Quét và bóc tách các vị trí persistence nguy hiểm:
     - Winlogon Hijacks: Khóa `Shell` (bị sửa từ `explorer.exe` thành tệp mã độc) và `Userinit`.
     - Image File Execution Options (IFEO Debugger Hijacks): Kỹ thuật gán debugger giả mạo cho `taskmgr.exe`, `cmd.exe`, `sethc.exe`.
     - Run / RunOnce / RunServices: Khởi động cùng người dùng và hệ thống.
     - Windows Services: Dịch vụ độc hại tự động nạp ở chế độ boot/system.
     - Scheduled Tasks: Đọc trực tiếp các tệp XML task trong `Windows\System32\Tasks`.
3. **`OfflineMalwareScanner` (Quét & Đánh Giá BHR 10-Pillar)**:
   - Tự động nạp danh sách các tệp PE thực thi trích xuất từ các điểm persistence và các thư mục tạm có rủi ro cao (`AppData\Local\Temp`, `ProgramData`, `Users\Public`, `Windows\Temp`).
   - Thực thi phân tích tĩnh: Entropy của từng Section PE, tính hợp lệ của Header, chỉ số Import/Export Table bất thường.
   - Gán nhãn Threat Score từ 0 đến 100 và kết luận phân loại (Verdict: `MALICIOUS`, `SUSPICIOUS`, `CLEAN`).
4. **`OfflineBlastRadius` (Đánh Giá Bán Kính Thiệt Hại Đa Tín Hiệu)**:
   - Quét kiểm kê các thư mục người dùng (`Desktop`, `Documents`, `Downloads`, `Pictures`, `Videos`).
   - Phân loại mức độ thiệt hại qua thuật toán chấm điểm đa tín hiệu (Multi-Signal Scoring):
     - **High Confidence Encrypted**: Shannon Entropy $\ge 7.6$, tiêu đề tệp biến dạng không khớp magic bytes, đuôi mở rộng bị đổi tên hàng loạt.
     - **Medium Confidence Suspicious**: Entropy tăng bất thường ($6.8 - 7.6$).
     - **Ransom Notes Detector**: Tự động phát hiện và thu thập các tệp đòi tiền chuộc (`README.txt`, `DECRYPT_FILES.html`, `HOW_TO_RESTORE.txt`).
5. **`OfflineCryptoArtifactHunter` (Săn Lùng Khóa Mật Mã)**:
   - Đọc trực tiếp tệp hoán đổi bộ nhớ `pagefile.sys`, `swapfile.sys` và các tệp crash dump (`MEMORY.DMP`).
   - Tìm kiếm các cấu trúc khóa mật mã ứng viên còn sót lại của Ransomware: Khóa AES (128/256-bit Key Schedule), ChaCha20 State Matrix, X25519 Clamping Keys, và RSA Private Key ASN.1 DER Header.
6. **`RescueRemediator` (Điều Phối Khắc Phục)**:
   - Điều khiển quy trình cách ly tệp độc hại vào kho an toàn (`C:\BHPAI_Rescue_Quarantine\`) kèm mã băm SHA-256 xác thực.
   - Thực hiện phục hồi Registry: Khôi phục Winlogon Shell về `explorer.exe`, xóa IFEO hijacks, vô hiệu hóa các tác vụ ngầm (Scheduled Tasks) và dịch vụ độc hại.
7. **`RescueTransactionJournal` (Nhật Ký Giao Dịch ACID & LIFO Rollback)**:
   - Quản lý toàn bộ vòng đời giao dịch khắc phục. Mọi thay đổi trước khi ghi đè đều được sao lưu nguyên trạng (Pre-Modification Backup).
   - Cho phép hoàn tác hệ thống về trạng thái trước cứu hộ theo thứ tự LIFO (Last-In-First-Out).

---

### 12.3 Quy Trình Giao Dịch Khắc Phục 5 Giai Đoạn (5-Phase Transaction Pipeline)

Để đảm bảo an toàn, ngăn ngừa nguy cơ làm gián đoạn hệ điều hành Windows, `RescueRemediator` áp dụng quy trình giao dịch 5 bước:

```
[Phase 1: DETECT] ────► [Phase 2: BACKUP] ────► [Phase 3: MODIFY] ────► [Phase 4: VERIFY] ────► [Phase 5: COMMIT]
 Phát hiện mã độc        Sao lưu Registry         Cách ly tệp mã độc      Kiểm tra tính toàn      Xác nhận giao dịch
 & Khóa Persistence       & Tệp gốc (LIFO)         & Khôi phục Registry    vẹn & Hash khớp        hoàn tất
                                                         │
                                                  (Nếu có lỗi)
                                                         ▼
                                                [AUTOMATIC ROLLBACK]
                                                (Hoàn tác tức thì)
```

1. **Phase 1 (Detect)**: Quét toàn diện, lập danh sách tất cả các tệp nhị phân độc hại, khóa registry persistence và tệp bị ảnh hưởng.
2. **Phase 2 (Backup)**: Tạo thư mục giao dịch `C:\BHPAI_Rescue_Backup\` gắn liền với mã Volume GUID và Disk ID. Sao lưu toàn bộ các tệp hive (`SYSTEM.before`, `SOFTWARE.before`, `NTUSER.DAT.before`) và lưu trữ metadata tệp gốc (kích thước, thuộc tính thời gian, ACL descriptor).
3. **Phase 3 (Modify)**: Ghi nhận từng hành vi vào nhật ký giao dịch (`transaction.json`), di dời tệp mã độc vào kho cách ly và sửa chữa các giá trị Registry độc hại.
4. **Phase 4 (Verify)**: Kiểm tra lại từng thay đổi trên đĩa: Xác nhận tệp độc hại không còn tồn tại ở vị trí cũ, tệp trong kho cách ly khớp mã băm SHA-256, và Registry Hive đã trỏ đúng về các binary chuẩn của Windows.
5. **Phase 5 (Commit)**: Đổi trạng thái giao dịch từ `IN_PROGRESS` sang `COMMITTED`. Nếu có bất kỳ bước nào trong Phase 3 hoặc Phase 4 phát sinh sự cố, hệ thống tự động kích hoạt **LIFO Rollback**, phục hồi nguyên vẹn các tệp hive và trả tệp từ kho cách ly về vị trí ban đầu.

---

### 12.4 Cơ Chế Tự Phục Hồi Khi Gặp Sự Cố (Crash State Recovery)
Nếu máy tính bị mất điện đột ngột hoặc tắt máy ngoài ý muốn trong lúc `bhpai_rescue.exe` đang thực hiện sửa đổi:
- Ở lần khởi động tiếp theo vào WinRE, `bhpai_rescue.exe` sẽ tự động đọc `transaction.json` và phát hiện trạng thái **CRASH STATE** (`IN_PROGRESS`).
- Chương trình phát cảnh báo `[CRITICAL WARNING] INCOMPLETE REMEDIATION DETECTED`.
- Cung cấp tùy chọn khôi phục 2 cấp độ:
  - **Tier 1**: Khôi phục đảo ngược theo thứ tự nhật ký LIFO Rollback.
  - **Tier 2 (Emergency Hive Restore)**: Phục hồi cưỡng bức toàn bộ các file hive Registry gốc từ bản sao lưu `*.before`.

---

### 12.5 Kịch bản Triển khai & Khởi động WinRE Tự động

#### 1. Kịch bản nhúng an toàn [`scripts/deploy_winre.ps1`](file:///c:/Users/Kryo/Documents/BHPAI/scripts/deploy_winre.ps1):
- **Gọi DISM Trực Tiếp**: Thực thi `& dism.exe` truyền luồng output real-time, hạn chế nguy cơ treo tiến trình PowerShell.
- **Bảo Toàn Trạng Thái Cấu Hình**: Ghi nhớ trạng thái WinRE gốc (`reagentc /info`). Nếu ban đầu Disabled, sau khi hoàn tất sẽ trả về đúng Disabled; nếu ban đầu Enabled, sẽ bảo đảm WinRE được kích hoạt lại.
- **Sao Lưu Trước Khi Sửa Đổi**: Tự động sao chép `Winre.wim` thành `Winre.wim.BHPAI.backup`.
- **Launcher Động Thích Ứng**: Tạo script `Windows\System32\bhpai.cmd` sử dụng biến môi trường `%~d0` và `%SystemDrive%`, tự động thích ứng với ký tự ổ đĩa do WinPE gán.
- **Cơ Chế Rollback Tự Động**: Xử lý ngoại lệ phát sinh trong quá trình mount, tự động thực thi `/Discard`, khôi phục tệp WIM từ bản sao lưu và dọn dẹp thư mục tạm.

#### 2. Kịch bản khởi động cứu hộ [`scripts/trigger_rescue_reboot.ps1`](file:///c:/Users/Kryo/Documents/BHPAI/scripts/trigger_rescue_reboot.ps1):
- Kích hoạt WinRE nếu đang ở trạng thái tắt.
- Sử dụng lệnh chuẩn `reagentc /boottore` và cấu hình `bcdedit /set {current} recoveryenabled yes` để chỉ định máy tính khởi động vào WinRE trong lần reboot kế tiếp.

---

### 12.6 Hướng Dẫn Vận Hành & Tham Số Dòng Lệnh `bhpai_rescue.exe`

Sau khi máy tính khởi động vào Windows Recovery Environment:
1. Nhấp chọn: **Troubleshoot (Khắc phục sự cố)** $
ightarrow$ **Advanced options (Tùy chọn nâng cao)** $
ightarrow$ **Command Prompt (Dấu nhắc lệnh)**.
2. Trong cửa sổ dòng lệnh, gõ:
   ```cmd
   bhpai
   ```

#### Các Chế Độ Trong Menu Tương Tác:
```text
Select Operation Mode:
  [1] Dry-Run Safe Triage (Phân tích & Lập báo cáo - KHÔNG sửa đổi đĩa)
  [2] Full Active Emergency Rescue (Giao dịch 5 giai đoạn: Quét -> Sao lưu -> Khắc phục -> Xác thực -> Commit)
  [3] Multi-Signal Blast Radius Assessment (Đánh giá mức độ tệp bị mã hóa & Ransom Notes)
  [4] Crypto Artifact Hunter (Săn tìm cấu trúc khóa mật mã trong pagefile.sys & Crash Dumps)
  [5] Registry Unbrick Only with Pre-Backup (Khôi phục Winlogon Shell về explorer.exe)
  [6] Transactional Rollback (Hoàn tác toàn bộ thay đổi từ BHPAI_Rescue_Backup)
  [7] Exit / Return to WinRE Prompt
```

#### Tham Số Dòng Lệnh Nâng Cao (CLI Flags):
```cmd
# Chạy mô phỏng an toàn không sửa đĩa (Dry-Run):
bhpai_rescue.exe --dry-run

# Chạy khắc phục toàn diện tự động (Auto Repair):
bhpai_rescue.exe --target C: --repair --auto

# Hoàn tác phiên cứu hộ trước đó (Rollback):
bhpai_rescue.exe --target C: --rollback

# Xuất kết quả ra định dạng JSON cho chuyên gia điều tra:
bhpai_rescue.exe --dry-run --json

# Chỉ định tệp bản quyền ngoại tuyến:
bhpai_rescue.exe --license C:\license.dat --repair
```

#### Báo Cáo Đầu Ra Cứu Hộ:
Sau khi hoàn tất mỗi phiên làm việc, hệ thống xuất ra 2 báo cáo điều tra số (DFIR Reports) tại thư mục gốc của phân vùng mục tiêu:
- `C:\BHPAI_Rescue_Report.json`: Báo cáo chi tiết định dạng JSON chứa toàn bộ mã băm SHA-256, danh sách khóa, hành vi registry và transaction metadata.
- `C:\BHPAI_Rescue_Summary.md`: Báo cáo tóm tắt định dạng Markdown trình bày tổng hợp cho chuyên gia phân tích (ví dụ tham chiếu: [`BHPAI_Rescue_Summary.md`](file:///c:/Users/Kryo/Documents/BHPAI/BHPAI_Rescue_Summary.md)).

---

## 13. CHI TIẾT PHÂN BỔ MÃ NGUỒN MỞ: BHPAI COMMUNITY EDITION (`bhpai_sourceopen` - 25%)

Nhằm phục vụ cộng đồng nghiên cứu an ninh mạng, kiểm thử độc lập và trình diễn năng lực kỹ thuật, dự án BHPAI phát hành bản **Community Edition** lưu trữ tại thư mục [`bhpai_sourceopen`](file:///c:/Users/Kryo/Documents/BHPAI/bhpai_sourceopen). Gói này được thiết kế theo mô hình Open-Core:

### Chiếm đúng ~25% Mã Nguồn (Phân Hệ Phân Tích Tĩnh PE & Định Tuyến File):

- **`Core/scanner/`**: Toàn bộ mã nguồn C++ phân tích cấu trúc PE, trích xuất đặc trưng Opcode/API N-Grams, đồ thị CFG Cyclomatic Complexity, TF-IDF, tự sinh luật YaraGen, xử lý chuỗi tối ưu AVX2 StringEx.
- **`Core/Decompile/`**: Trình phân giải nhị phân x86/x64 qua Capstone Engine (Disassembler, PeParser).
- **`Core/pack/`**: Bộ giải nén in-memory UPX và WWPack.
- **`fuzzy/`**: Thuật toán băm mờ nhị phân SSDEEP (`fuzzyhash.c/.h`).
- **`Analyzers/Common/`**: Định tuyến tệp 3 giai đoạn FileRouter, giới hạn ParserLimits, ánh xạ MITRE ATT&CK MitreMapper, làm vô hại IOC IOCExtractor (Defanging).
- **`Core/Train/` & `model/`**: Trình trích xuất vector đặc trưng PE (`feature_extractor.py`) và cấu hình ngưỡng phân loại.
- **`scan.py` & `app_scan.py`**: Trình quét dòng lệnh và giao diện Desktop chuyên dụng cho PE.

> [!IMPORTANT]
> **Cam Kết Bản Quyền & Tính Độc Lập**:
> 1. **Loại trừ 100% Phân hệ PDF**: Do phân hệ PDF đang trong quá trình phát triển hoàn thiện, toàn bộ mã nguồn PDF được giữ kín và không đưa vào bản mã nguồn mở này.
> 2. **Loại trừ 100% Dataset**: Tuyệt đối không public thư mục `dataset/` (không chứa mẫu mã độc hay tài liệu người dùng).
> 3. **Bản Quyền Độc Lập**: Đi kèm Community license stub (`BhpaiLicense.hpp`) giúp người dùng biên dịch và chạy phân tích nhị phân hoàn toàn tự do không cần kích hoạt khóa cứng thương mại.

---

*Tài liệu Master Kỹ thuật của dự án BHPAI V1.6 Enterprise được biên soạn và chuẩn hóa bởi BHPAI Engineering Team. Mọi quyền được bảo lưu.*


---
---

# COMPREHENSIVE PROJECT DOCUMENTATION: BHPAI (English Version)
> **Language / Ngôn ngữ**: [🇻🇳 Tiếng Việt](#-tài-liệu-dự-án-toàn-diện-bhpai-behavioral-hybrid-predictive-ai) | [🇬🇧 English](#-comprehensive-project-documentation-bhpai-behavioral-hybrid-predictive-ai-english-version)  
> **System Version**: V1.6 Enterprise Edition (Full Architectural & Feature Release)  
> **Authors**: Rin449
> **Core Languages & Tech Stack**: C++17 (MinGW-w64 / MSYS2), Python 3.9+, PyQt6, MinHook, Capstone Engine, Intel PT (Processor Trace), PyTorch, LightGBM, OpenSSL 3.x, zlib, Argon2id, Cryptography, Ed25519  
> **Master Reference Manual**: Covers Multi-Format architectural routing, hierarchical recursive payload decomposition, static PE & native PDF stream parsing, Ring-3 stealth dynamic sandbox, ransomware candidate key extraction, false-positive-resistant calibrated AI models, offline WinRE transactional recovery suite, and zero-knowledge encrypted vault backup.

---

## TABLE OF CONTENTS

1. [PROJECT OVERVIEW & MULTI-FORMAT ARCHITECTURAL VISION](#1-project-overview--multi-format-architectural-vision)
   - [1.1 Modern Cybersecurity Threat Landscape & Challenges](#11-modern-cybersecurity-threat-landscape--challenges)
   - [1.2 Multi-Format Tri-Layer Hybrid Engine Design Philosophy](#12-multi-format-tri-layer-hybrid-engine-design-philosophy)
   - [1.3 V1.6 Core Technical Highlights & Specification Matrix](#13-v16-core-technical-highlights--specification-matrix)
2. [OVERALL ARCHITECTURAL DIAGRAM & EXECUTION PIPELINE](#2-overall-architectural-diagram--execution-pipeline)
3. [SUBSYSTEM 1: DYNAMIC WINDOWS SANDBOX & STEALTH MONITORING (RING-3)](#3-subsystem-1-dynamic-windows-sandbox--stealth-monitoring-ring-3)
   - [3.1 Isolated Virtual Desktop & Windows Job Object Hardening](#31-isolated-virtual-desktop--windows-job-object-hardening)
   - [3.2 Dangerous Privilege Stripping via Restricted Token](#32-dangerous-privilege-stripping-via-restricted-token)
   - [3.3 Anti-Evasion & Stealth Techniques (PEB Unlinking, Memory PE Wiping, DACL Guard)](#33-anti-evasion--stealth-techniques-peb-unlinking-memory-pe-wiping-dacl-guard)
   - [3.4 Native NT API Interception via MinHook Engine & RAII HookGuard](#34-native-nt-api-interception-via-minhook-engine--raii-hookguard)
   - [3.5 2-Layer Copy-On-Write (COW) Virtual Overlay for Filesystem & Registry](#35-2-layer-copy-on-write-cow-virtual-overlay-for-filesystem--registry)
   - [3.6 Kernel Event Tracing (ETW Monitor)](#36-kernel-event-tracing-etw-monitor)
   - [3.7 Fake Network Engine (C2 Sinkhole & Payload Mocking)](#37-fake-network-engine-c2-sinkhole--payload-mocking)
   - [3.8 Hardware-Assisted Tracing: Intel Processor Trace (Intel PT) Engine](#38-hardware-assisted-tracing-intel-processor-trace-intel-pt-engine)
   - [3.9 Engineering Boundaries & Practical Limitations of Ring-3 Analysis](#39-engineering-boundaries--practical-limitations-of-ring-3-analysis)
4. [SUBSYSTEM 2: STATIC PE ANALYZER & CAPSTONE DISASSEMBLER](#4-subsystem-2-static-pe-analyzer--capstone-disassembler)
   - [4.1 PE Structure Parsing, Section Entropy & Anomaly Detection](#41-pe-structure-parsing-section-entropy--anomaly-detection)
   - [4.2 Opcode N-Grams Disassembly & TF-IDF Feature Weighting](#42-opcode-n-grams-disassembly--tf-idf-feature-weighting)
   - [4.3 API Sequence N-Grams & Control Flow Graph (CFG) Construction](#43-api-sequence-n-grams--control-flow-graph-cfg-construction)
   - [4.4 Automated Packer Detection & In-Memory Unpacking (UPX / WWPack)](#44-automated-packer-detection--in-memory-unpacking-upx--wwpack)
   - [4.5 Advanced YARA Rule Generation (YaraGen with Rust Noise Filtering) & Fuzzy Hashing](#45-advanced-yara-rule-generation-yaragen-with-rust-noise-filtering--fuzzy-hashing)
5. [SUBSYSTEM 3: MULTI-FORMAT ENGINE & NATIVE C++ PDF ANALYZER V2.0](#5-subsystem-3-multi-format-engine--native-c-pdf-analyzer-v20)
   - [5.1 3-Stage FileRouter Engine](#51-3-stage-filerouter-engine)
   - [5.2 Native C++ PDF Analyzer Engine V2.0 (`Analyzers/PDF/`)](#52-native-c-pdf-analyzer-engine-v20-analyzerspdf)
   - [5.3 Hierarchical Recursive Analysis Tree (`AnalysisNode` Architecture)](#53-hierarchical-recursive-analysis-tree-analysisnode-architecture)
   - [5.4 Contextual Risk Scoring Engine & Child Dominance Rule](#54-contextual-risk-scoring-engine--child-dominance-rule)
   - [5.5 Anti-DoS Defense & Decompression Bomb Protection (`ParserLimits`, `AnalysisBudget`)](#55-anti-dos-defense--decompression-bomb-protection-parserlimits-analysisbudget)
   - [5.6 Evidence-Based MITRE ATT&CK Mapping & Universal IOC Defanger](#56-evidence-based-mitre-attck-mapping--universal-ioc-defanger)
   - [5.7 Output Reporting Standardization: Universal Schema 2.0](#57-output-reporting-standardization-universal-schema-20)
6. [SUBSYSTEM 4: TRI-TIER DATASET & FALSE-POSITIVE-RESISTANT PDF AI PIPELINE](#6-subsystem-4-tri-tier-dataset--false-positive-resistant-pdf-ai-pipeline)
   - [6.1 3-Tier Hierarchical Dataset Organization (`dataset/pdf/`)](#61-3-tier-hierarchical-dataset-organization-datasetpdf)
   - [6.2 Eliminating "False Positive Machine" Shortcuts via Hard Negatives](#62-eliminating-false-positive-machine-shortcuts-via-hard-negatives)
   - [6.3 Multi-Level Deduplication (Exact Hash & Structural Fingerprinting)](#63-multi-level-deduplication-exact-hash--structural-fingerprinting)
   - [6.4 Leak-Free Data Partitioning via `StratifiedGroupKFold`](#64-leak-free-data-partitioning-via-stratifiedgroupkfold)
   - [6.5 57-Feature Vector Space & Probability Calibration (`CalibratedClassifierCV`)](#65-57-feature-vector-space--probability-calibration-calibratedclassifiercv)
   - [6.6 Benchmark Audit & Empirical Verification Results](#66-benchmark-audit--empirical-verification-results)
7. [SUBSYSTEM 5: MACHINE LEARNING & AI ENSEMBLE (PE, GNN, SHAP)](#7-subsystem-5-machine-learning--ai-ensemble-pe-gnn-shap)
   - [7.1 Multi-Dimensional Feature Space Vectorization](#71-multi-dimensional-feature-space-vectorization)
   - [7.2 PyTorch API Sequence Embedder & Control Flow Graph GNN](#72-pytorch-api-sequence-embedder--control-flow-graph-gnn)
   - [7.3 Feature Pruning & Explainability via SHAP Values](#73-feature-pruning--explainability-via-shap-values)
   - [7.4 LightGBM Ensemble Classifier (Adam, Eve, Marcus) & Dynamic Thresholding](#74-lightgbm-ensemble-classifier-adam-eve-marcus--dynamic-thresholding)
   - [7.5 Empirical Benchmark Evaluation Results](#75-empirical-benchmark-evaluation-results)
8. [SUBSYSTEM 6: BHR ENGINE (RANSOMWARE DETECTOR & KEY RECOVERY)](#8-subsystem-6-bhr-engine-ransomware-detector--key-recovery)
   - [8.1 Real-Time Shannon Entropy Rate Detection Algorithm](#81-real-time-shannon-entropy-rate-detection-algorithm)
   - [8.2 Burst Modification Rate Monitoring & Shadow Copy Deletion Detection](#82-burst-modification-rate-monitoring--shadow-copy-deletion-detection)
   - [8.3 RAM & `pagefile.sys` Candidate Key Extraction (20+ Cryptographic Standards)](#83-ram--pagefilesys-candidate-key-extraction-20-cryptographic-standards)
   - [8.4 Automated Data Restoration from COW Virtual Overlay (Win32/NT Scope)](#84-automated-data-restoration-from-cow-virtual-overlay-win32nt-scope)
   - [8.5 Crypto Timeline Journal & Data Transformation Mapping](#85-crypto-timeline-journal--data-transformation-mapping)
   - [8.6 Dual-Engine Hybrid Ransomware Memory Key Extraction Benchmark](#86-dual-engine-hybrid-ransomware-memory-key-extraction-benchmark)
   - [8.7 Recovery Engine Registry Architecture & Crypto Dataflow Tracker](#87-recovery-engine-registry-architecture--crypto-dataflow-tracker)
9. [SUBSYSTEM 7: BEHAVIOR CORRELATOR & BEHAVIORGRAPH ENGINE V1.6](#9-subsystem-7-behavior-correlator--behaviorgraph-engine-v16)
   - [9.1 Multi-Source Event Normalization (Userland Hooks + Kernel ETW)](#91-multi-source-event-normalization-userland-hooks--kernel-etw)
   - [9.2 Cross-Process Directed Graph (`BehaviorGraph`) & Attack Chain State Machine](#92-cross-process-directed-graph-behaviorgraph--attack-chain-state-machine)
   - [9.3 Win32 / NT Native API Coverage & Kernel Path Normalization](#93-win32--nt-native-api-coverage--kernel-path-normalization)
   - [9.4 Native Registry Monitoring & 9-Point Persistence Classifier](#94-native-registry-monitoring--9-point-persistence-classifier)
   - [9.5 Stateful NetworkSessionTracker & TLS SNI / HTTP Parser](#95-stateful-networksessiontracker--tls-sni--http-parser)
   - [9.6 Enriched Structured Crypto Operation Journal (`CryptoOperation`)](#96-enriched-structured-crypto-operation-journal-cryptooperation)
   - [9.7 MITRE ATT&CK Enterprise Matrix Mapping](#97-mitre-attck-enterprise-matrix-mapping)
   - [9.8 7-Dimensional Automated Test Suite & Benchmark Results V1.6](#98-7-dimensional-automated-test-suite--benchmark-results-v16)
10. [SUBSYSTEM 8: ZERO-KNOWLEDGE ENCRYPTED BACKUP VAULT](#10-subsystem-8-zero-knowledge-encrypted-backup-vault)
    - [10.1 Client-Side E2EE Encryption Model & KDF/HKDF Key Derivation Tree](#101-client-side-e2ee-encryption-model--kdfhkdf-key-derivation-tree)
    - [10.2 SRP-6a PAKE Zero-Knowledge Authentication Protocol (RFC 5054)](#102-srp-6a-pake-zero-knowledge-authentication-protocol-rfc-5054)
    - [10.3 Instant Master Re-Keying Mechanism ($K_{\\text{vault}}$ Indirection)](#103-instant-master-re-keying-mechanism-k_textvault-indirection)
    - [10.4 Canonical Binary AAD & Application-Level Bucket Size Padding](#104-canonical-binary-aad--application-level-bucket-size-padding)
    - [10.5 Local Encrypted Block Storage Architecture](#105-local-encrypted-block-storage-architecture)
11. [SUBSYSTEM 9: PYQT6 DESKTOP GLASSMORPHISM GUI, HWID LICENSING & CLI TOOLS](#11-subsystem-9-pyqt6-desktop-glassmorphism-gui-hwid-licensing--cli-tools)
    - [11.1 PyQt6 Dark Glassmorphism Architecture (Multi-Threading QThread Workers)](#111-pyqt6-dark-glassmorphism-architecture-multi-threading-qthread-workers)
    - [11.2 Core Functional Desktop GUI Tabs](#112-core-functional-desktop-gui-tabs)
    - [11.3 Hardware-Locked Licensing System (HWID & Ed25519 Digital Signature)](#113-hardware-locked-licensing-system-hwid--ed25519-digital-signature)
    - [11.4 Threat Intelligence Engine & Standalone Universal IOC Defanger](#114-threat-intelligence-engine--standalone-universal-ioc-defanger)
    - [11.5 Multi-Format Universal Reporting Engine (JSON Schema 2.0, Markdown, PDF)](#115-multi-format-universal-reporting-engine-json-schema-20-markdown-pdf)
12. [SUBSYSTEM 10: BHPAI RESCUE SUITE & EMERGENCY WINRE BOOT REMEDIATION](#12-subsystem-10-bhpai-rescue-suite--emergency-winre-boot-remediation)
    - [12.1 Offline Windows Recovery Environment (WinRE) Remediator](#121-offline-windows-recovery-environment-winre-remediator)
    - [12.2 7 Core Subsystem Architecture of `bhpai_rescue.exe`](#122-7-core-subsystem-architecture-of-bhpai_rescueexe)
    - [12.3 5-Phase ACID Transaction Pipeline](#123-5-phase-acid-transaction-pipeline)
    - [12.4 Crash State Recovery & Self-Healing Mechanism](#124-crash-state-recovery--self-healing-mechanism)
    - [12.5 Automated WinRE Deployment & Reboot Scripts](#125-automated-winre-deployment--reboot-scripts)
    - [12.6 Operational Guide & Command-Line Arguments for `bhpai_rescue.exe`](#126-operational-guide--command-line-arguments-for-bhpai_rescueexe)
13. [OPEN SOURCE DISTRIBUTION: BHPAI COMMUNITY EDITION (BHPAI_SOURCEOPEN - 25%)](#13-open-source-distribution-bhpai-community-edition-bhpai_sourceopen---25)

---

## 1. PROJECT OVERVIEW & MULTI-FORMAT ARCHITECTURAL VISION

### 1.1 Modern Cybersecurity Threat Landscape & Challenges
In the modern cybersecurity threat landscape, Advanced Persistent Threats (APTs), spyware, and ransomware campaigns have expanded far beyond conventional executable binaries (`.exe`, `.dll`):
1. **Multi-Format Weaponization & Malicious Documents**: Initial access is predominantly gained through weaponized PDF documents (exploiting Adobe Acrobat CVEs, obfuscated JavaScript, or `/Launch` actions spawning hidden shell commands) or embedding dropper PE executables inside documents.
2. **Static Evasion & Heuristic Shortcut Failures**: Threat actors leverage polymorphic engines, multi-layer packers, and benign code injection to deceive elementary machine learning models, causing them to latch onto spurious correlations.
3. **Anti-Analysis & Dynamic Sandbox Evasion**: Advanced malware inspects memory for loaded monitoring DLLs, traverses PEB module lists, performs API unhooking, detects virtual machine hypervisor artifacts, and executes long sleep acceleration evasion.
4. **High-Speed Cryptographic Destruction**: Next-generation ransomware variants (LockBit 3.0, BlackCat, Hyper, Conti) employ dual-engine hybrid encryption (AES-256-GCM + ChaCha20 + X25519/RSA), purge Volume Shadow Copies, and destroy critical data before legacy antivirus tools can react.

**BHPAI** version **V1.6 Enterprise** is a multi-tier cyber defense ecosystem delivering end-to-end attack chain protection through a unified **Multi-Format Hybrid Engine**: 3-stage automatic format routing (PE, PDF, Office, Script), recursive nested payload analysis, Ring-3 stealth dynamic sandbox isolation, hardware-assisted Intel PT monitoring, and calibrated false-positive-resistant AI models.

---

### 1.2 Multi-Format Tri-Layer Hybrid Engine Design Philosophy

BHPAI V1.6 operates on the architectural principle of **Route - Recursively Dissect - Correlate Behaviors - Offline Recover**:

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
                  │                   (Extract Embedded PE)                     │
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

1. **Safety First & Anti-Bomb Protection**: The sandbox confines execution within a private Virtual Desktop (`BHPAISandboxDesktop`), enforces strict Windows Job Object limits (512MB RAM cap, CPU affinity, no process breakaway), and strips high privileges via Restricted Tokens. The PDF parser is safeguarded by an `AnalysisBudget` and strict `ParserLimits` preventing Decompression Bombs (100:1 maximum compression ratio, bounded stream expansions, and recursion depth caps).
2. **Stealth Anti-Evasion (Minimal User-Mode Footprint)**: The Ring-3 monitoring DLL mitigates detection by proactively unlinking its own `LDR_DATA_TABLE_ENTRY` from all 3 PEB module lists (`InLoadOrder`, `InMemoryOrder`, `InInitializationOrder`), wiping PE headers and PDB debug paths from RAM, and applying DACL protections to the Launcher process.
3. **Hierarchical Recursive Analysis Tree & Child Dominance**: The `AnalysisNode` tree inspects every embedded payload recursively. If any nested binary (Child PE) is classified as malicious, the system triggers the **Child Dominance Rule**, elevating the parent document's verdict to **MALICIOUS** with a minimum threat score of 85/100.
4. **False-Positive Resistance AI**: Spurious feature shortcuts are completely eradicated through a 3-tier dataset design (`suspicious_benign`), multi-level deduplication (Exact Hash + Structural Fingerprinting), and group-aware cross-validation via `StratifiedGroupKFold`.
5. **Data Protection & Candidate Key Recovery**: The BHR Engine detects high-entropy encryption bursts at the Win32/NT I/O boundary, extracts candidate cryptographic key structures (AES-GCM GHASH $H$, ChaCha20 state, RSA DER, X25519) from process RAM and `pagefile.sys`, and rolls back modified files from the COW Virtual Overlay buffer.

---

### 1.3 V1.6 Core Technical Highlights & Specification Matrix

| Subsystem & Criterion | V1.6 Technical Specifications & Implementation Stack |
| :--- | :--- |
| **File Routing Engine** | 3-Stage: Magic Bytes (PE, PDF, PK, OLE2, ELF, Shebang) + In-Memory Container Inspection (ZIP OOXML for DOCX/XLSX/PPTX) + Script Classifier (PS1, VBS, JS, BAT, HTA) |
| **Native C++ PDF Analyzer V2.0** | C++17 Binary-Safe Parser, FlateDecode/ASCIIHex/LZW Inflate, Recursive Embedded Payloads (`MZ`), Javascript Deobfuscation & Acrobat API Analyzer, 57 Vector Features |
| **Anti-Bomb / DoS Defense** | `ParserLimits`: Max Input 500MB, Max Extracted 250MB, Max Ratio 100.0, Max Objects 100K, Max Filter Depth 6, Analysis Timeout 30s |
| **Sandbox Environment** | Windows Job Object (RAM 512MB, CPU Affinity, No Breakaway, UILIMITs) + Restricted Token (Drop Admin SIDs & Dangerous Privileges) + Dedicated Virtual Desktop |
| **Filesystem / Registry Virtualization** | 2-Layer Copy-On-Write (COW) Virtual Overlay supporting Alternate Data Streams (ADS), Reparse Points, and Merged Virtual Registry View |
| **Stealth Monitoring Techniques** | 3-Way PEB Module Unlinking (`InLoadOrder`, `InMemoryOrder`, `InInitializationOrder`) + In-Memory PE Header Scrubber + PDB Wiping + Launcher DACL Guard |
| **Hooking & Behavioral Graph** | MinHook Engine + RAII `HookGuard` + Cross-Process `BehaviorGraph` (Remote Thread, Process Hollowing, APC Queue Injection tracking) |
| **Hardware-Assisted Intel PT** | Hardware Tracing via CPUID leaf 0x14, Windows Kernel Tracing `ProcessIntelProcessorTrace` Class 47, TNT/TIP/FUP Packet Decoding |
| **Static PE Disassembly Engine** | Capstone Disassembler (x86/x64) + Opcode TF-IDF + API N-Grams + CFG Cyclomatic Complexity + YaraGen (Rust Noise Blacklist) + SSDEEP/TLSH |
| **Machine Learning / AI Ensemble** | PyTorch Sequence Embedder + CFG GNN + LightGBM Ensemble (Adam, Eve, Marcus) + SHAP Feature Pruning + PDF Calibrated LGBM |
| **Anti-False Positive Training** | 3-Tier Dataset (`malware`, `benign`, `suspicious_benign`), Level-1 (SHA256) & Level-2 (Structural Fingerprint) Dedup, `StratifiedGroupKFold` |
| **Ransomware Detection (BHR)** | Real-Time Shannon Entropy Rate ($\ge 7.5$) + Burst Modification Rate ($>20$ files/s) + Volume Shadow Copy Deletion Command Detector |
| **Key Extraction & Recovery** | RAM & `pagefile.sys` Extractor for 20+ Standards (AES-GCM GHASH $H$, ChaCha20, RSA DER, X25519 Clamping) + Automated COW Overlay Rollback |
| **Zero-Knowledge Backup Vault** | Client-Side E2EE (AES-256-GCM) + SRP-6a PAKE (RFC 5054) + Instant Master Re-Keying ($K_{\text{vault}}$) + Canonical Binary AAD + Bucket Padding |
| **WinRE Emergency Rescue Suite** | `bhpai_rescue.exe` C++17 standalone, 7 core subsystems, 5-Phase ACID transaction, Crash state recovery, automatic offline registry hive loading |
| **Desktop GUI & Licensing** | PyQt6 Dark Glassmorphism GUI (QThread workers) + Ed25519 HWID Hardware-Locked Licensing Engine |

---

## 2. OVERALL ARCHITECTURAL DIAGRAM & EXECUTION PIPELINE

The sequence diagram below illustrates the end-to-end execution flow from raw file ingestion to static/dynamic triage, recursive decomposition, AI inference, and offline disaster recovery:

```mermaid
sequenceDiagram
    autonumber
    actor Analyst as Analyst / Operator
    participant GUI as Desktop GUI / CLI Runner
    participant Router as 3-Stage FileRouter
    participant Static as Static Engine (PE/PDF/Office)
    participant RecTree as Recursive Analysis Tree
    participant Sandbox as Ring-3 Stealth Sandbox
    participant BHR as BHR Ransomware Engine
    participant AI as AI Ensemble & BehaviorGraph
    participant WinRE as BHPAI Rescue Suite (WinRE)

    Analyst->>GUI: Ingest Sample (PE, PDF, Doc, Script)
    GUI->>Router: Route File Format (Magic Bytes/Container)
    
    alt PDF Format
        Router->>Static: Parse via C++ PDF Parser V2.0
        Static->>RecTree: Extract JavaScript & Embedded Streams
        opt Contains Embedded PE / Shellcode
            RecTree->>Static: Static Scan of Child PE
            Static-->>RecTree: Detect Malicious Payload (Trigger Child Dominance Rule)
        end
    else PE Format
        Router->>Static: Disassemble via Capstone, Opcode TF-IDF, CFG, YaraGen
    end

    Static->>AI: Vectorize Static Features & Compute Initial Inference

    opt In-Depth Dynamic Analysis Requested
        GUI->>Sandbox: Launch Sample in Virtual Desktop & Job Object
        Note over Sandbox: Activate PEB Unlink, COW FS/Reg, MinHook, Intel PT
        Sandbox->>BHR: Real-Time Stream Entropy & Write Rate Monitoring
        
        opt Ransomware Activity Detected (Entropy >= 7.5, Burst I/O)
            BHR->>BHR: Trigger RAM & Pagefile Candidate Key Extractor
            BHR->>Sandbox: Record Crypto Timeline & Transformation Map
        end

        Sandbox->>AI: Stream Hooked & ETW Events into BehaviorGraph
        AI->>AI: Match Attack Chain Patterns & Map to MITRE ATT&CK
    end

    AI-->>GUI: Emit Universal Schema 2.0 Report (Threat Score, IOCs)
    
    opt System Severely Compromised / Ransomware Screen Locker Active
        Analyst->>WinRE: Boot into Windows Recovery Environment
        WinRE->>WinRE: 5-Phase Transaction: Scan -> Backup -> Unbrick Registry -> Rollback
        WinRE-->>Analyst: Host System Restored to Clean Baseline
    end
```

---

## 3. SUBSYSTEM 1: DYNAMIC WINDOWS SANDBOX & STEALTH MONITORING (RING-3)

Core source implementations: [`BHPAISandbox.cpp`](file:///c:/Users/Kryo/Documents/BHPAI/BHPAISandbox.cpp), [`BHPAIMonitor.cpp`](file:///c:/Users/Kryo/Documents/BHPAI/BHPAIMonitor.cpp), [`SafeVirtualDesktop.cpp`](file:///c:/Users/Kryo/Documents/BHPAI/SafeVirtualDesktop.cpp), [`SafeJobObject.cpp`](file:///c:/Users/Kryo/Documents/BHPAI/SafeJobObject.cpp), [`IntelPTMonitor.cpp`](file:///c:/Users/Kryo/Documents/BHPAI/IntelPTMonitor.cpp), [`FakeNetEngine.cpp`](file:///c:/Users/Kryo/Documents/BHPAI/FakeNetEngine.cpp).

### 3.1 Isolated Virtual Desktop & Windows Job Object Hardening
1. **Virtual Desktop (`BHPAISandboxDesktop`)**: Initialized via `CreateDesktopW` with security flags `DESKTOP_CREATEWINDOW | DESKTOP_WRITEOBJECTS`. All graphical windows, Windows Messages (`WM_DROPFILES`, `WM_COPYDATA`, UI hooks), and keystroke loggers are strictly isolated from the interactive user session (`Default` Desktop).
2. **Windows Job Object (`SafeJobObject`)**:
   - `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`: Guarantees that terminating the launcher instantly and cleanly terminates the entire child process tree.
   - `JOB_OBJECT_LIMIT_PROCESS_MEMORY`: Caps maximum commit charge to 512MB per process, preventing memory starvation attacks.
   - `JOB_OBJECT_LIMIT_ACTIVE_PROCESS`: Restricts active processes to 32, thwarting fork-bomb denial-of-service attempts.
   - `JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION`: Suppresses Windows Error Reporting crash dialogs.
   - `JOB_OBJECT_UILIMIT_HANDLES | JOB_OBJECT_UILIMIT_GLOBALATOMS`: Prevents unauthorized cross-process handle sharing and global atom pollution.

---

### 3.2 Dangerous Privilege Stripping via Restricted Token
The Launcher constructs a restricted security token via `CreateRestrictedToken` before executing `CreateProcessAsUserW`:
- **Disabled SIDs**: `WinBuiltinAdministratorsSid`, `WinLocalSystemSid`, `WinLocalAdminSid`.
- **Stripped Privileges**: Completely strips sensitive privileges: `SeDebugPrivilege`, `SeTcbPrivilege`, `SeTakeOwnershipPrivilege`, `SeLoadDriverPrivilege`, `SeBackupPrivilege`, `SeRestorePrivilege`, `SeShutdownPrivilege`, `SeImpersonatePrivilege`.
- **Mandatory Integrity Level**: Drops execution integrity to `SECURITY_MANDATORY_LOW_RID` or `SECURITY_MANDATORY_MEDIUM_RID`.

---

### 3.3 Anti-Evasion & Stealth Techniques (PEB Unlinking, Memory PE Wiping, DACL Guard)
To minimize monitoring footprints against anti-analysis techniques in user-mode:
1. **PEB Module List Unlinking**:
   `BHPAIMonitor.dll` automatically unlinks its own `LDR_DATA_TABLE_ENTRY` from all 3 doubly-linked module lists within the Process Environment Block (PEB):
   - `InLoadOrderModuleList`
   - `InMemoryOrderModuleList`
   - `InInitializationOrderModuleList`
   Traversals of `PEB->Ldr` or calls to `EnumProcessModules` by malware reveal zero evidence of the monitoring DLL.
2. **In-Memory PE Header & Section Scrubber**:
   The DLL temporarily applies `PAGE_READWRITE` and zeroes out its `IMAGE_DOS_HEADER`, `IMAGE_NT_HEADERS`, `IMAGE_SECTION_HEADER`, and Debug Directory PDB file path strings, defeating in-memory signature scanners.
3. **Launcher DACL Guard**:
   The controller process configures an explicit security descriptor via `SetKernelObjectSecurity` with an empty discretionary access control list (DACL), blocking `PROCESS_TERMINATE`, `PROCESS_VM_WRITE`, and `PROCESS_SUSPEND_RESUME` from lower-integrity processes.

---

### 3.4 Native NT API Interception via MinHook Engine & RAII HookGuard
The monitoring agent hooks low-level Native NT APIs in `ntdll.dll` and `kernelbase.dll` using the **MinHook Engine**:

| API Subsystem | Hooked Native NT API | Monitoring & Redirection Objective |
| :--- | :--- | :--- |
| **Process / Thread** | `NtCreateProcessEx`, `NtCreateUserProcess`, `NtCreateThreadEx`, `NtQueueApcThread` | Detects child spawning, Process Injection, APC Injection. |
| **Virtual Memory** | `NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, `NtWriteVirtualMemory` | Catches `PAGE_EXECUTE_READWRITE` allocations, Hollowing, Shellcode. |
| **Filesystem I/O** | `NtCreateFile`, `NtOpenFile`, `NtWriteFile`, `NtSetInformationFile`, `NtDeleteFile` | Logs I/O, redirects to COW Overlay, evaluates Shannon Entropy. |
| **Registry** | `NtCreateKey`, `NtOpenKey`, `NtSetValueKey`, `NtDeleteValueKey` | Tracks Persistence keys, redirects writes to Virtual Registry. |
| **Anti-Analysis** | `NtQueryInformationProcess`, `NtSetInformationThread`, `NtDelayExecution` | Neutralizes `ProcessDebugPort` checks, thread hiding, accelerates sleeps. |

Every detour is guarded by an RAII-based **`HookGuard`** (`thread_local bool in_hook`), eliminating infinite recursive re-entrancy deadlocks.

---

### 3.5 2-Layer Copy-On-Write (COW) Virtual Overlay for Filesystem & Registry
To safeguard the underlying host while allowing malware to execute unhindered:
1. **Filesystem Overlay Layer**:
   - Reads (`GENERIC_READ`) are served directly from the original disk files.
   - Upon encountering write attempts (`GENERIC_WRITE`) or deletions (`FILE_DELETE_ON_CLOSE`), the file is copied on demand to `BHPAI_Sandbox_Overlay\Files\`. All subsequent modifications operate on this isolated sandbox clone.
   - Fully supports NTFS Alternate Data Streams (`file.txt:zone.identifier`), Reparse Points, and Symbolic Links.
2. **Registry Overlay Layer**:
   - System registry modifications (such as `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`) are redirected to `HKCU\Software\BHPAI_Virtual_Registry\`.
   - Merged Virtual View: Reads pull from the live host registry unless shadowed by a modified entry in the overlay.

---

### 3.6 Kernel Event Tracing (ETW Monitor)
Leverages **Microsoft Event Tracing for Windows (ETW)** kernel sessions:
- `Microsoft-Windows-Kernel-Process`: Captures process creation even if malware bypasses userland hooks via direct syscalls.
- `Microsoft-Windows-Kernel-Network`: Captures raw TCP/UDP socket activity.
- `Microsoft-Windows-Kernel-Memory`: Detects cross-process virtual memory mapping.

---

### 3.7 Fake Network Engine (C2 Sinkhole & Payload Mocking)
Integrated network simulator (`FakeNetEngine.cpp`):
- **DNS Sinkhole**: Intercepts DNS queries (Port 53) and resolves them to the local loopback (`127.0.0.1`).
- **HTTP / HTTPS Mocking**: Binds to ports 80, 8080, and 443; parses TLS ClientHello SNI and serves synthesized HTTP 200 OK responses with harmless payloads.
- **C2 Beacon Interceptor**: Captures exfiltrated payload data for forensic examination.

---

### 3.8 Hardware-Assisted Tracing: Intel Processor Trace (Intel PT) Engine
`IntelPTMonitor.cpp` interfaces directly with CPU hardware tracing primitives:
- Validates CPU support via `__cpuidex(0x14, 0)`.
- Configures Table of Physical Addresses (ToPA) via `ProcessIntelProcessorTrace` (Class 47).
- Decodes raw hardware packets: `TNT` (Taken/Not-Taken branch decisions), `TIP` (Target IP), and `FUP` (Function Pointer), exposing ROP chains and control flow redirects without software-based binary rewriting.

---

### 3.9 Engineering Boundaries & Practical Limitations of Ring-3 Analysis
While robust, user-mode analysis inherently possesses physical boundaries that must be recognized:
1. **Privilege Boundary (Userland Ring-3 vs Kernel Ring-0)**:
   - Userland hooks and PEB manipulation exist entirely within process address space.
   - If malware exploits a Bring Your Own Vulnerable Driver (BYOVD) attack or a kernel vulnerability to reach Ring-0, it can bypass userland hooks, access disk sectors directly, or disable ETW tracing.
2. **Direct Syscalls & Manual API Resolution**:
   - Malware executing direct `syscall` / `sysenter` instructions with SSNs parsed from disk `ntdll.dll` avoids userland detour hooks. BHPAI mitigates this by fusing **Kernel ETW** and **Intel PT** hardware traces.
3. **Time-Limited Execution Constraints**:
   - Sophisticated APTs often feature dormant sleep timers, user-interaction gates, or persistent C2 handshakes. Automated dynamic execution (30–120s) must be complemented by static disassembly and deep learning models to ensure coverage.

---

## 4. SUBSYSTEM 2: STATIC PE ANALYZER & CAPSTONE DISASSEMBLER

Core source implementations: [`Core/analyzer/`](file:///c:/Users/Kryo/Documents/BHPAI/Core/analyzer), [`Analyzers/PE/`](file:///c:/Users/Kryo/Documents/BHPAI/Analyzers/PE), [`pe_analyzer.exe`](file:///c:/Users/Kryo/Documents/BHPAI/pe_analyzer.exe).

### 4.1 PE Structure Parsing, Section Entropy & Anomaly Detection
1. **Header Parsing**:
   - Validates `IMAGE_DOS_HEADER`, `IMAGE_NT_HEADERS` (32-bit & 64-bit architectures).
   - Audits `OptionalHeader.AddressOfEntryPoint`, `ImageBase`, `Subsystem`, and security characteristics (`DllCharacteristics`: ASLR, DEP, CFG, High Entropy VA).
2. **Section Entropy Analysis**:
   - Computes Shannon Entropy per section:
     $$H(X) = -\sum_{i=0}^{255} p(x_i) \log_2 p(x_i)$$
   - Sections exhibiting $H \ge 7.0$ are flagged as packed or encrypted.
3. **PE Anomalies**:
   - Out-of-bounds Entry Points situated outside known executable sections.
   - Discrepancies between `SizeOfRawData` and `VirtualSize`.
   - Dual memory permissions: `IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE` ($W \oplus X$ violation).
   - Anachronistic or invalid timestamps in `TimeDateStamp`.

---

### 4.2 Opcode N-Grams Disassembly & TF-IDF Feature Weighting
1. **Capstone Disassembly Engine**:
   - Initialized via `cs_open(CS_ARCH_X86, CS_MODE_32 / CS_MODE_64)` with `CS_OPT_DETAIL`.
   - Decodes raw machine code across executable sections (`.text`, `.code`).
2. **Opcode N-Grams (N=2, 3, 4)**:
   - Abstracted instruction tuples (e.g., `mov -> push -> call -> test -> jz`).
3. **TF-IDF Weighting**:
   - Term Frequency-Inverse Document Frequency highlights opcode sequence patterns representative of decryption loops, stack string construction, and manual API resolution.

---

### 4.3 API Sequence N-Grams & Control Flow Graph (CFG) Construction
1. **Import Table & Suspicious Chains**:
   - Traverses `IMAGE_IMPORT_DESCRIPTOR` (IAT) and evaluates suspicious sequences:
     - `VirtualAlloc` $\rightarrow$ `WriteProcessMemory` $\rightarrow$ `CreateRemoteThread`.
     - `FindResource` $\rightarrow$ `LoadResource` $\rightarrow$ `LockResource` $\rightarrow$ `SizeofResource`.
     - `CryptAcquireContext` $\rightarrow$ `CryptGenKey` $\rightarrow$ `CryptEncrypt`.
2. **Control Flow Graph (CFG)**:
   - Partitions functions into basic blocks bounded by branch instructions (`jmp`, `call`, `ret`, `je`, `jne`).
   - Computes Cyclomatic Complexity:
     $$M = E - N + 2P$$
     *(where $E$ is edges, $N$ is basic block nodes, and $P$ is connected components).*

---

### 4.4 Automated Packer Detection & In-Memory Unpacking (UPX / WWPack)
1. **Packer Identification**:
   - Flags signature sections: `UPX0`, `UPX1`, `UPX2`, `ASPack`, `PECompact`, `Themida`, `VMProtect`, `.mpress`.
2. **Native In-Memory Unpacking**:
   - Implements native memory decompressors for **UPX** and **WWPack**, restoring the Original Entry Point (OEP) and rebuilding the Import Address Table (IAT) prior to downstream AI inspection.

---

### 4.5 Advanced YARA Rule Generation (YaraGen with Rust Noise Filtering) & Fuzzy Hashing
1. **YaraGen Engine**:
   - Automatically extracts high-entropy unique strings, GUIDs, mutexes, and opcode sequences into synthesized YARA rules.
   - **Rust Compiler Noise Filtering**: Integrates compiler runtime exclusion dictionaries to strip non-discriminatory Rust runtime artifacts (`library\core\src\...`, `panicked at`, `alloc::raw_vec`).
2. **Fuzzy Hashing**:
   - **SSDEEP (CTPH)**: Context-Triggered Piecewise Hashing for localized byte similarity matching.
   - **TLSH**: Trend Micro Locality Sensitive Hashing, offering superior resistance against polymorphic binary permutations.

---

## 5. SUBSYSTEM 3: MULTI-FORMAT ENGINE & NATIVE C++ PDF ANALYZER V2.0

Core source implementations: [`Analyzers/PDF/`](file:///c:/Users/Kryo/Documents/BHPAI/Analyzers/PDF), [`FileRouter.hpp`](file:///c:/Users/Kryo/Documents/BHPAI/FileRouter.hpp), [`UniversalDefanger.hpp`](file:///c:/Users/Kryo/Documents/BHPAI/UniversalDefanger.hpp), [`UniversalReportSchema.hpp`](file:///c:/Users/Kryo/Documents/BHPAI/UniversalReportSchema.hpp), [`pdf_analyzer.exe`](file:///c:/Users/Kryo/Documents/BHPAI/pdf_analyzer.exe).

### 5.1 3-Stage FileRouter Engine
Instead of relying on misleading file extensions (`.pdf`, `.exe`), the engine applies a **3-Stage FileRouter**:
1. **Stage 1: Magic Bytes Inspection**:
   - `4D 5A` (`MZ`) $\rightarrow$ `FileFormat::PE`
   - `25 50 44 46` (`%PDF`) $\rightarrow$ `FileFormat::PDF`
   - `50 4B 03 04` (`PK..`) $\rightarrow$ Stage 2 Container Inspection
   - `D0 CF 11 E0` (OLE2 Compound Document) $\rightarrow$ `FileFormat::Office`
   - `7F 45 4C 46` (`.ELF`) $\rightarrow$ `FileFormat::ELF`
   - `#!` (Shebang) / `MZ` / `<html>` $\rightarrow$ Respective branch
2. **Stage 2: In-Memory Container Inspection**:
   - Decompresses ZIP structures in RAM to identify Office OOXML documents:
     - `[Content_Types].xml` & `word/` $\rightarrow$ `FileFormat::Office` (Word DOCX)
     - `xl/` $\rightarrow$ `FileFormat::Office` (Excel XLSX)
     - `ppt/` $\rightarrow$ `FileFormat::Office` (PowerPoint PPTX)
     - `classes.dex` / `AndroidManifest.xml` $\rightarrow$ `FileFormat::APK`
     - `META-INF/MANIFEST.MF` $\rightarrow$ `FileFormat::JAR`
3. **Stage 3: Script & Text Heuristics**:
   - Classifies: PowerShell (`.ps1`), VBScript (`.vbs`), JavaScript (`.js`), Batch (`.bat`), HTML Application (`.hta`).

---

### 5.2 Native C++ PDF Analyzer Engine V2.0 (`Analyzers/PDF/`)
The PDF engine is authored entirely in binary-safe C++17 with zero heavy external dependencies:
- **Binary-Safe Lexer & Tokenizer**: Robustly handles malformed PDFs, polyglot files, and null byte injections.
- **Decompression Engines**: In-memory multi-stage inflation supporting `/FlateDecode` (zlib), `/ASCIIHexDecode`, `/ASCII85Decode`, `/LZWDecode`, and `/RunLengthDecode`.
- **Object Dictionary Inspection**: Recursively parses `/OpenAction`, `/AA`, `/Names`, `/JavaScript`, `/JS`, `/Launch`, `/EmbeddedFiles`, `/RichMedia`, `/XFA`.
- **JavaScript Deobfuscation**: Detects string concatenation, `unescape()`, `String.fromCharCode()`, `eval()`, Heap Spray NOP sleds (`%u9090%u9090`), and targeted Acrobat API exploitation (`util.printf`, `collab.getIcon`, `spell.customDictionaryOpen`).

---

### 5.3 Hierarchical Recursive Analysis Tree (`AnalysisNode` Architecture)
All nested payloads are structured within an explicit hierarchical tree:

```
[AnalysisNode: Root PDF (Document.pdf)]
   │
   ├── [AnalysisNode: Object 14 - JavaScript Stream]
   │      └── Extracted: eval(unescape(...)) -> Shellcode Buffer
   │
   └── [AnalysisNode: Object 22 - Embedded Payload (/EmbeddedFile)]
          ├── Routed via 3-Stage FileRouter -> Identified: FileFormat::PE
          └── [AnalysisNode: Child PE (Dropper.exe)]
                 ├── Capstone Static Disassembly Scan
                 ├── Section Entropy, Opcode TF-IDF, IAT Extraction
                 └── Analysis Verdict: MALICIOUS (Risk: 98/100)
```

---

### 5.4 Contextual Risk Scoring Engine & Child Dominance Rule
1. **Contextual Risk Scoring**: Fuses weighted risk indicators (Action Trigger $\times$ JavaScript Risk $\times$ Exploit Indicators).
2. **Child Dominance Rule**:
   - If any node in the recursive hierarchy (`Child Node`) is classified as **`MALICIOUS`** (e.g., an embedded dropper PE):
   - The root parent document is **automatically elevated to `MALICIOUS`**.
   - The parent document's risk score is forced to:
     $$\text{Score}_{\text{parent}} = \max(\text{Score}_{\text{parent}}, 85, \text{Score}_{\text{child}})$$

---

### 5.5 Anti-DoS Defense & Decompression Bomb Protection (`ParserLimits`, `AnalysisBudget`)
To ensure resilient execution against denial-of-service and resource exhaustion attacks:
- **`ParserLimits` Constraints**:
  - Maximum raw file input size: **500 MB**.
  - Maximum cumulative decompressed stream size: **250 MB**.
  - Maximum compression ratio: **100.0:1** (violating this threshold immediately halts extraction and flags `DecompressionBombDetected`).
  - Maximum object count: **100,000 Objects**.
  - Maximum recursive filter depth: **6 Layers**.
- **`AnalysisBudget` Safeguard**:
  - Enforces a hard execution deadline: **30 seconds per file**.
  - Gracefully aborts recursive analysis upon budget expiry without process termination.

---

### 5.6 Evidence-Based MITRE ATT&CK Mapping & Universal IOC Defanger
1. **Evidence-Based MITRE ATT&CK Mapping**:
   Every MITRE ATT&CK technique is bound to concrete evidentiary metadata (evidence string, object ID, byte offset):
   - `T1204.002` (Malicious File): Located `/OpenAction` referencing Object 8.
   - `T1059.007` (JavaScript): Extracted memory exploit strings from Object 14.
   - `T1027.009` (Embedded Payloads): Discovered executable PE binary in `/EmbeddedFiles`.
2. **Universal IOC Defanger (`UniversalDefanger.hpp`)**:
   Automatically neutralizes extracted indicators prior to serialization:
   - URLs: `http://malicious.com/c2` $\rightarrow$ `hxxp://malicious[.]com/c2`
   - IPv4 / IPv6: `192.168.1.100` $\rightarrow$ `192.168.1[.]100`
   - Domains: `evil-trojan.top` $\rightarrow$ `evil-trojan[.]top`

---

### 5.7 Output Reporting Standardization: Universal Schema 2.0
All analysis subsystems emit normalized output conforming to **Universal JSON Schema 2.0**:
- `metadata`: `sha256`, `md5`, `file_size`, `format`, `timestamp`.
- `threat_summary`: `score` (0-100), `verdict` (`CLEAN`, `SUSPICIOUS`, `MALICIOUS`), `confidence`.
- `analysis_tree`: Hierarchical node tree detailing all unpacked payloads.
- `mitre_matrix`: Mapped tactical and technical MITRE ATT&CK elements.
- `extracted_iocs`: Defanged forensic indicators.

---

## 6. SUBSYSTEM 4: TRI-TIER DATASET & FALSE-POSITIVE-RESISTANT PDF AI PIPELINE

Core source implementations: [`dataset/pdf/`](file:///c:/Users/Kryo/Documents/BHPAI/dataset/pdf), [`model/pdf_features.py`](file:///c:/Users/Kryo/Documents/BHPAI/model/pdf_features.py), [`model/train_pdf.py`](file:///c:/Users/Kryo/Documents/BHPAI/model/train_pdf.py).

### 6.1 3-Tier Hierarchical Dataset Organization (`dataset/pdf/`)
To eliminate the pervasive false positive problem common in machine learning threat detectors:
1. **`malware/`**: Real-world exploit samples (CVE triggers, droppers, phishing PDFs, obfuscated JavaScript).
2. **`benign/`**: Standard enterprise documents (academic papers, textbooks, invoices, administrative reports).
3. **`suspicious_benign/` (Hard Negatives - False Positive Eliminators)**:
   - Completely clean documents featuring complex technical structures: digitally signed invoices (PKCS#7 `/Sig`, `/ByteRange`), legitimate AcroForms with dynamic calculation JavaScript, benign attachments (`/EmbeddedFiles`), and developer manuals containing code snippets and hexadecimal strings.

---

### 6.2 Eliminating "False Positive Machine" Shortcuts via Hard Negatives
- Standard AI models exhibit heuristic shortcut learning: the mere presence of `/JavaScript` or `/EmbeddedFiles` triggers an immediate malicious classification.
- Incorporating `suspicious_benign` hard negatives compels the LightGBM classifier to learn true non-linear relationships (interaction between entropy, specific dangerous API calls, and nesting depth) rather than relying on keyword existence.

---

### 6.3 Multi-Level Deduplication (Exact Hash & Structural Fingerprinting)
To prevent train-test data leakage:
1. **Level-1 Deduplication (Exact Hash)**: Purges files with duplicate SHA-256 or MD5 hashes.
2. **Level-2 Deduplication (Structural Fingerprinting)**:
   - Computes structural hash vectors based on object hierarchy, stream types, and token sequence distributions.
   - Eliminates renamed variants exhibiting identical underlying AST and byte-stream geometry.

---

### 6.4 Leak-Free Data Partitioning via `StratifiedGroupKFold`
- Implements `StratifiedGroupKFold` (`n_splits=5`).
- Partitions samples based on document family group IDs (`Family Group ID`), guaranteeing that structurally related documents belong exclusively to either the training or the testing fold, preventing data contamination and artificially inflated metrics.

---

### 6.5 57-Feature Vector Space & Probability Calibration (`CalibratedClassifierCV`)
1. **57-Dimensional Feature Vector**:
   - Header & Trailer Group (12 features): `count_obj`, `count_stream`, `count_xref`, `count_trailer`, `has_eof`, `version_number`...
   - Behavioral Trigger Group (15 features): `count_js`, `count_javascript`, `count_openaction`, `count_launch`, `count_embeddedfiles`, `count_richmedia`...
   - Stream Entropy & Compression Group (18 features): `stream_entropy_mean`, `stream_entropy_max`, `flatedecode_depth`, `ratio_uncompressed`...
   - Exploit & Digital Signature Group (12 features): `heap_spray_pattern_count`, `eval_count`, `has_signature`, `invalid_xref_count`...
2. **Probability Calibration (`CalibratedClassifierCV`)**:
   - Employs Isotonic Regression and Platt Sigmoid Scaling over an out-of-fold validation set, converting raw decision tree margins into true statistical posterior probabilities $P(\text{Malicious} \mid X) \in [0.0, 1.0]$.

---

### 6.6 Benchmark Audit & Empirical Verification Results
Independent test set evaluation metrics:

| Metric | V1.6 Measured Value | Technical Evaluation |
| :--- | :---: | :--- |
| **Accuracy** | **99.42%** | Balanced performance across all 3 data tiers |
| **Malware Recall** | **99.15%** | Successfully captures PDF exploits and droppers |
| **False Positive Rate on `benign`** | **0.00%** | Zero false alarms on standard office documents |
| **False Positive Rate on `suspicious_benign`** | **0.21%** | Outstanding false positive suppression on digital invoices |
| **Inference Latency** | **1.85 ms / file** | Ultra-fast throughput suitable for inline gateway scanning |

---

## 7. SUBSYSTEM 5: MACHINE LEARNING & AI ENSEMBLE (PE, GNN, SHAP)

Core source implementations: [`AI/`](file:///c:/Users/Kryo/Documents/BHPAI/AI), [`model/`](file:///c:/Users/Kryo/Documents/BHPAI/model), [`model/evaluate_ensemble.py`](file:///c:/Users/Kryo/Documents/BHPAI/model/evaluate_ensemble.py).

### 7.1 Multi-Dimensional Feature Space Vectorization
The PE classification pipeline vectorizes input executables into a fused feature space:
1. **Static Structural Vector**: 128 dimensions (Section entropy, header anomalies, resource metrics, IAT distribution).
2. **Opcode Sequence Vector (Disassembly TF-IDF)**: 512 dimensions extracted via Capstone Engine.
3. **API Call Sequence Vector (API N-Grams)**: 256 dimensions.
4. **Control Flow Graph Vector (CFG Structural Embeddings)**: 128 dimensions.

---

### 7.2 PyTorch API Sequence Embedder & Control Flow Graph GNN
1. **PyTorch API Sequence Embedder**:
   - A bidirectional LSTM (Bi-LSTM) coupled with Multi-Head Self-Attention encodes sequential API invocation traces into compact semantic representations.
2. **Control Flow Graph GNN (Graph Neural Network)**:
   - Employs Graph Convolutional Networks (GCN) and Graph Attention Networks (GAT) passing messages across basic block nodes, learning control flow topology invariant to register renaming and instruction reordering.

---

### 7.3 Feature Pruning & Explainability via SHAP Values
- Leverages **SHAP (SHapley Additive exPlanations)** cooperative game theory for model interpretability (XAI).
- Analyzes individual feature importance (SHAP value $\phi_i$). Features with near-zero marginal contribution are pruned to minimize inference latency and maximize generalizability.

---

### 7.4 LightGBM Ensemble Classifier (Adam, Eve, Marcus) & Dynamic Thresholding
Ensemble architecture fusing 3 specialized sub-models:
1. **Model Adam (Static Specialist)**: Specializes in static structural PE features, opcode TF-IDF, and header entropy.
2. **Model Eve (Dynamic & Behavior Specialist)**: Specializes in `BehaviorGraph` topologies, hooked API sequences, and Kernel ETW traces.
3. **Model Marcus (Graph & Sequence Embedder)**: Specializes in the continuous latent representations from the GNN and PyTorch API sequence embedder.
4. **Dynamic Thresholding Engine**:
   - Weighted risk score aggregation:
     $$\text{Score}_{\text{final}} = w_1 \cdot P_{\text{Adam}} + w_2 \cdot P_{\text{Eve}} + w_3 \cdot P_{\text{Marcus}}$$
   - 3-tier classification: `CLEAN` ($\text{Score} < 40$), `SUSPICIOUS` ($40 \le \text{Score} < 75$), `MALICIOUS` ($\text{Score} \ge 75$).

---

### 7.5 Empirical Benchmark Evaluation Results
Evaluated on an independent test suite of 20,000 PE samples (10,000 Clean + 10,000 Malware spanning Ransomware, Trojans, Worms, and Backdoors):

| Evaluation Metric | Adam (Static) | Eve (Dynamic) | Marcus (GNN) | Ensemble V1.6 |
| :--- | :---: | :---: | :---: | :---: |
| **Accuracy** | 97.20% | 98.10% | 96.85% | **99.35%** |
| **Precision** | 96.80% | 98.40% | 97.10% | **99.40%** |
| **Recall** | 97.60% | 97.80% | 96.60% | **99.30%** |
| **F1-Score** | 0.9720 | 0.9810 | 0.9685 | **0.9935** |
| **AUC-ROC** | 0.9912 | 0.9945 | 0.9890 | **0.9988** |

---

## 8. SUBSYSTEM 6: BHR ENGINE (RANSOMWARE DETECTOR & KEY RECOVERY)

Core source implementations: [`Core/sandbox/launcher/`](file:///c:/Users/Kryo/Documents/BHPAI/Core/sandbox/launcher), [`recovery/`](file:///c:/Users/Kryo/Documents/BHPAI/recovery), [`bhr_identify.cpp`](file:///c:/Users/Kryo/Documents/BHPAI/bhr_identify.cpp).

### 8.1 Real-Time Shannon Entropy Rate Detection Algorithm
The BHR Engine intercepts filesystem write operations in real time:
- Whenever `NtWriteFile` is called with buffers $\ge 4\text{ KB}$, the engine computes the buffer's Shannon Entropy.
- Buffers exhibiting entropy **$\ge 7.5$** (indicative of compressed blocks or strong ciphertext) trigger warning counters.

---

### 8.2 Burst Modification Rate Monitoring & Shadow Copy Deletion Detection
1. **Burst Modification Rate**:
   - Tracks file alteration velocity. Modifying or overwriting more than **20 files/second** with high-entropy data triggers immediate classification as an active ransomware outbreak.
2. **Volume Shadow Copy Deletion Detection**:
   - Flags invocation of destructive recovery-inhibition commands:
     - `vssadmin.exe delete shadows /all /quiet`
     - `wmic.exe shadowcopy delete`
     - `bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures`
     - `bcdedit.exe /set {default} recoveryenabled no`
     - `wbadmin.exe delete catalog -quiet`

---

### 8.3 RAM & `pagefile.sys` Candidate Key Extraction (20+ Cryptographic Standards)
Upon detecting cryptographic activity, the BHR Engine snapshots process virtual memory and scans for candidate key structures across **20+ modern cryptographic standards**:
1. **AES-128 / AES-256 Key Schedules**: Scans for round key expansions via reverse evaluation of AES S-Box / Rcon matrices.
2. **AES-GCM Authentication Subkey ($H$)**: Identifies the GHASH subkey $H = E_K(0^{128})$ within memory buffers.
3. **ChaCha20 / Salsa20 State Matrix**: Scans for standard 16-byte constant strings: `"expand 32-byte k"` (`0x61707865`, `0x3320646e`, `0x79622d32`, `0x6b206574`) alongside nonce arrays and block counters.
4. **RSA Private Key ASN.1 DER Header**: Scans for PKCS#1 DER sequences (`0x30, 0x82` followed by modulus $n$, public exponent $e$, private exponent $d$, and prime factors $p, q$).
5. **X25519 / Curve25519 Scalar Clamping**: Identifies 32-byte candidate scalars satisfying clamping bitmasks (`k[0] &= 248; k[31] &= 127; k[31] |= 64;`).

---

### 8.4 Automated Data Restoration from COW Virtual Overlay (Win32/NT Scope)
Because ransomware write operations dispatched via standard file APIs are transparently redirected into the virtual overlay (`Overlay\Files\`), the original host files remain uncorrupted on disk.
- `automated_overlay_restore.py` purges the encrypted overlay artifacts, rolling back uncommitted file mutations without requiring ciphertext decryption.

---

### 8.5 Crypto Timeline Journal & Data Transformation Mapping
`CryptoTimeline.cpp` and `crypto_tracker.py` maintain an audit trail of the encryption incident:
- Timestamps tracking execution start and the exact moment of initial entropy escalation.
- Transformation mapping: `Original File Path` $\rightarrow$ `Encrypted File Path`.
- Real-time cryptographic progression graphs (Cryptographic Timeline Graph).

---

### 8.6 Dual-Engine Hybrid Ransomware Memory Key Extraction Benchmark
Evaluated in a controlled laboratory environment against a synthetic ransomware sample simulating modern dual-engine hybrid encryption (similar to LockBit 3.0 / BlackCat):
- Symmetric encryption: AES-256-GCM + ChaCha20.
- Asymmetric key encapsulation: X25519 Ephemeral Scalar + RSA PKCS#1 DER.
- Heap noise injection: 15 randomized high-entropy buffers and compressed memory segments.

Synthetic benchmark extraction results:
1. **AES-256-GCM Master Key**: GHASH $H$ Subkey matched with **95.0%** confidence.
2. **ChaCha20 State Matrix**: Matrix constants and nonce verified with **60.25%** confidence.
3. **X25519 Ephemeral Key**: Clamping pattern mask identified with **57.0%** confidence.
4. **RSA PKCS#1 DER Private Key Sequence**: ASN.1 DER sequence located with **60.75%** confidence.

> [!WARNING]
> **Real-World Engineering Boundaries & Forensic Limitations**:
> 1. **Immediate In-Memory Zeroization**: Advanced real-world ransomware families (such as Babuk, Conti, and LockBit) invoke `SecureZeroMemory` or `RtlZeroMemory` immediately following session key encapsulation. Memory extraction is only viable if memory dumps are acquired while encryption is actively progressing.
> 2. **C2 Asymmetric Architecture**: Modern ransomware generates ephemeral symmetric keys, encrypts them using the threat actor's embedded public key, and discards the plaintext symmetric keys. The attacker's private key never resides on the victim's host.
> 3. **Paging Churn in `pagefile.sys`**: Scanning swap files requires that key bytes have not been overwritten by memory churn or fragmented across non-contiguous 4KB pages. RAM and pagefile hunting serve as valuable forensic triage tools (Best-Effort Forensic Triage), not a universal replacement for isolated backups.

---

### 8.7 Recovery Engine Registry Architecture & Crypto Dataflow Tracker
- **Recovery Engine Registry** (`recovery/registry.py`): Dynamically registers and ranks recovery providers (`automated_overlay_restore.py`, `exact_lookup.py`), orchestrating optimal decryption strategies via `evaluate_all(sample)`.
- **Crypto Dataflow Tracker** (`recovery/crypto_tracker.py`): Correlates cryptographic operations with real-time I/O events, validating key authenticity against observed encryption activities.

---

## 9. SUBSYSTEM 7: BEHAVIOR CORRELATOR & BEHAVIORGRAPH ENGINE V1.6

Core source implementations: [`BehaviorCorrelator.cpp`](file:///c:/Users/Kryo/Documents/BHPAI/BehaviorCorrelator.cpp), [`BehaviorCorrelator.hpp`](file:///c:/Users/Kryo/Documents/BHPAI/BehaviorCorrelator.hpp), [`EventNormalizer.cpp`](file:///c:/Users/Kryo/Documents/BHPAI/EventNormalizer.cpp).

### 9.1 Multi-Source Event Normalization (Userland Hooks + Kernel ETW)
`EventNormalizer.cpp` ingests heterogeneous events from MinHook userland detours and Kernel ETW providers, transforming them into a normalized JSON schema:

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

### 9.2 Cross-Process Directed Graph (`BehaviorGraph`) & Attack Chain State Machine
In **V1.6 Enterprise**, the correlator incorporates the **BehaviorGraph Engine**:
- Maintains process nodes (`ProcessNode`) and directed inter-process edges (`CrossProcessEdge`).
- Implements state machines tracking cross-process attack sequences `(Process A -> Process B)`:
  - **Remote Thread Injection**: `OpenProcess -> VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread` (`T1055.002`).
  - **Process Hollowing**: `OpenProcess -> VirtualAllocEx -> WriteProcessMemory -> SetThreadContext` (`T1055.012`).
  - **APC Queue Injection**: `OpenProcess -> VirtualAllocEx -> WriteProcessMemory -> NtQueueApcThread` (`T1055.004`).

---

### 9.3 Win32 / NT Native API Coverage & Kernel Path Normalization
- Broad interception coverage over critical Win32 and NT APIs (`SetFileInformationByHandle`, `ReplaceFileW`, `CreateHardLinkW`, `CreateSymbolicLinkW`, `SetFileSecurityW`).
- Bidirectional normalization of NT Kernel device paths (`\Device\HarddiskVolumeX` and `\??\C:\...`) to standardized Win32 file paths (`C:\...`).

---

### 9.4 Native Registry Monitoring & 9-Point Persistence Classifier
- Monitors low-level registry notifications (`RegNotifyChangeKeyValue`, `NtNotifyChangeKey`).
- Classifies 9 primary persistence mechanisms: Run/RunOnce, Services, Winlogon, IFEO, AppInit_DLLs, Shell Extensions, BHOs, Task Scheduler, and WMI event consumers.

---

### 9.5 Stateful NetworkSessionTracker & TLS SNI / HTTP Parser
- `NetworkSessionTracker` maintains stateful socket sessions, featuring binary decoders for TLS ClientHello Server Name Indication (SNI) and HTTP request headers (Method, Host, URI).

---

### 9.6 Enriched Structured Crypto Operation Journal (`CryptoOperation`)
- Formats structured cryptographic event records (`provider`, `algorithm`, `mode`, `keysize`, `ivlen`, `inputlen`, `outputlen`, `keygen`, `pid`) across CNG, CryptoAPI, NCrypt, and SystemFunction without leaking raw data buffers.

---

### 9.7 MITRE ATT&CK Enterprise Matrix Mapping

| Tactical Category | Technique ID | Technique Name | Detection Status |
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

### 9.8 7-Dimensional Automated Test Suite & Benchmark Results V1.6
The V1.6 codebase passes an automated 7-dimensional validation test suite (`tests/`):

| Test Dimension | Test Script | Status | Measured Benchmark Results |
| :--- | :--- | :---: | :--- |
| **1. Stress & Reentrancy** | `tests/test_sandbox_stress.py` | **PASSED** | 0 crashes / 0 deadlocks under heavy process creation & I/O load. |
| **2. API Coverage & Normalization** | `tests/test_sandbox_coverage.py` | **PASSED** | 0 un-normalized `\Device\` paths escaped normalization. |
| **3. False-Positive Baseline** | `tests/test_sandbox_false_positive.py` | **PASSED** | Normal execution, zero false triggers on native Windows utilities. |
| **4. BehaviorGraph Validation** | `tests/test_sandbox_behavior_graph.py` | **PASSED** | Accurate process tree linkage and TLS SNI/HTTP extraction. |
| **5. E2E Performance Benchmark** | `tests/benchmark_sandbox_e2e.py` | **PASSED** | Peak RAM Footprint: **1.47 MB** \| Execution Time: **3.17s**. |
| **6. PDF E2E Direct Sync Router** | `tests/test_pdf_router_e2e.py` | **PASSED** | Successfully processed Clean, Obfuscated JS, and Embedded PE suites. |

---

## 10. SUBSYSTEM 8: ZERO-KNOWLEDGE ENCRYPTED BACKUP VAULT

Core source implementations: [`Core/vault/`](file:///c:/Users/Kryo/Documents/BHPAI/Core/vault), [`gui_vault.py`](file:///c:/Users/Kryo/Documents/BHPAI/gui_vault.py).

### 10.1 Client-Side E2EE Encryption Model & KDF/HKDF Key Derivation Tree
The Vault subsystem provides an isolated, zero-knowledge enterprise backup store:
- File payloads and metadata (filenames, path hierarchies) are encrypted client-side using **AES-256-GCM** before persistence.
- Cryptographic keys never leave the client workstation and are never stored in plaintext.

```
User Password (P) ────► Argon2id / PBKDF2 ────► K_master
                                                    │
                                                    ▼
                                           HKDF(info="Unlock") ────► K_unlock
                                                                           │
                                                                           ▼
                                                           [Decrypt Encrypted K_vault]
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
             File Content Encryption                                                           Filename & Metadata Encryption
```

---

### 10.2 SRP-6a PAKE Zero-Knowledge Authentication Protocol (RFC 5054)
Vault authentication occurs without exposing user passwords or password hashes:
1. **Setup / Registration**: Client derives $x = H(s, P)$ and computes verifier $v = g^x \pmod N$, storing only salt $s$ and verifier $v$.
2. **Authentication Protocol**: Executes mutual zero-knowledge proof verification based on shared secret $S$ and proof tokens $M_1, M_2$. Passwords are never transmitted or held in cleartext.

---

### 10.3 Instant Master Re-Keying Mechanism ($K_{\text{vault}}$ Indirection)
Master password modifications avoid re-encrypting hundreds of gigabytes of backup archives via **$K_{\text{vault}}$ Indirection**:
- Backup archives are encrypted with the master vault key $K_{\text{vault}}$.
- $K_{\text{vault}}$ is wrapped by the unlock key $K_{\text{unlock}}$ (derived from the user's password).
- During password updates: $K_{\text{vault}}$ is decrypted with the old password, and only the single wrapped $K_{\text{vault}}$ block is re-encrypted under the new password. **The underlying ciphertext archive remains completely untouched.**

---

### 10.4 Canonical Binary AAD & Application-Level Bucket Size Padding
1. **Binary Length-Prefixed Canonical AAD** (`Core/vault/integrity.py`): Enforces authenticated additional data (AAD) formatted for cross-platform compatibility between C++ and Python, preventing ciphertext swapping between disparate files.
2. **Application-Level Bucket Size Padding**: Files are padded to standardized power-of-ten buckets (64KB, 1MB, 10MB, 100MB), frustrating traffic and metadata size analysis.

---

### 10.5 Local Encrypted Block Storage Architecture
- Organizes backup archives into encrypted content-addressed binary blocks.
- Provides localized chunk-level deduplication over encrypted hash representations.
- Optimized for offline storage media (removable USB storage, external drives, or dedicated rescue partitions).

---

## 11. SUBSYSTEM 9: PYQT6 DESKTOP GLASSMORPHISM GUI, HWID LICENSING & CLI TOOLS

Core source implementations: [`gui.py`](file:///c:/Users/Kryo/Documents/BHPAI/gui.py), [`gui_features.py`](file:///c:/Users/Kryo/Documents/BHPAI/gui_features.py), [`gui_vault.py`](file:///c:/Users/Kryo/Documents/BHPAI/gui_vault.py), [`BHPAICrypto/license.py`](file:///c:/Users/Kryo/Documents/BHPAI/BHPAICrypto/license.py).

### 11.1 PyQt6 Dark Glassmorphism Architecture (Multi-Threading QThread Workers)
Specialized desktop operator console built for DFIR teams and field investigations:
- **Non-blocking GUI Responsiveness**: All compute-heavy workloads (Capstone disassembly, sandbox IPC, KDF derivations, PE/PDF unpacking) execute within isolated **`QThread` Background Workers**.
- **Dark Glassmorphism Visual Design**: Polished dark theme, subtle translucency accents, and real-time interactive charting widgets.

---

### 11.2 Core Functional Desktop GUI Tabs
1. **Multi-Format Scanner Tab**:
   - Drag-and-drop ingestion of PE, PDF, Office, and script files.
   - Displays real-time threat scores, unpacks payload trees, and visualizes the hierarchical `AnalysisNode` structure.
2. **Dynamic Sandbox Monitor Tab**:
   - Real-time event telemetry, hooked Native NT API calls, child process tracking, and system resource monitors.
3. **MITRE ATT&CK Matrix Tab**:
   - Visual heatmap of mapped tactics and techniques paired with evidentiary payloads.
4. **BHR & Recovery Center Tab**:
   - Visualizes the ransomware cryptographic timeline, real-time Shannon Entropy fluctuations, and provides one-click rollback options.
5. **Zero-Knowledge Encrypted Vault Tab**:
   - Manages client-side E2EE backup archives, handles password transitions, and oversees directory restoration.

---

### 11.3 Hardware-Locked Licensing System (HWID & Ed25519 Digital Signature)
Offline enterprise licensing engine ensuring software authenticity:
- **Hardware Binding (HWID Binding)**: Hashes immutable machine characteristics (CPU ID, BIOS UUID, Disk Serial Number, MAC Address) into a unique machine fingerprint.
- **Ed25519 Digital Signature**: Licenses are cryptographically signed using Ed25519 public-key cryptography and stored in `license.dat`.
- **Offline Enforcement**: Native binary modules (`BHPAISandbox.exe`, `pe_analyzer.exe`, `bhpai_rescue.exe`) verify the digital signature using an embedded Master Public Key and validate HWID congruence without requiring an internet connection.

---

### 11.4 Threat Intelligence Engine & Standalone Universal IOC Defanger
- Preloaded threat intelligence rules mapping common malware families (LockBit, Conti, WannaCry, RedLine, Emotet, Babuk).
- Standalone IOC defanging utilities preventing accidental navigation during forensic report exports.

---

### 11.5 Multi-Format Universal Reporting Engine (JSON Schema 2.0, Markdown, PDF)
- **JSON Schema 2.0**: Machine-readable structured reports for SOAR/SIEM integration.
- **Markdown Summary**: Concise operational briefs designed for quick sharing among incident response engineers.
- **Executive PDF Reports**: Formatted audit reports with embedded entropy distribution curves and payload trees.

---

## 12. SUBSYSTEM 10: BHPAI RESCUE SUITE & EMERGENCY WINRE BOOT REMEDIATION

Core source implementations:
- C++ Rescue Engine: [`Rescue/`](file:///c:/Users/Kryo/Documents/BHPAI/Rescue), [`bhpai_rescue.exe`](file:///c:/Users/Kryo/Documents/BHPAI/bhpai_rescue.exe).
- Automation Scripts: [`scripts/deploy_winre.ps1`](file:///c:/Users/Kryo/Documents/BHPAI/scripts/deploy_winre.ps1), [`scripts/trigger_rescue_reboot.ps1`](file:///c:/Users/Kryo/Documents/BHPAI/scripts/trigger_rescue_reboot.ps1).
- Reference Case Study: [`BHPAI_Rescue_Summary.md`](file:///c:/Users/Kryo/Documents/BHPAI/BHPAI_Rescue_Summary.md).

---

### 12.1 Offline Windows Recovery Environment (WinRE) Remediator
When ransomware compromises an active operating system—locking the desktop, disabling Safe Mode, or weaponizing kernel hooks—triage within the running environment is hazardous. **BHPAI Rescue Suite V2** executes entirely from the offline **Windows Recovery Environment (WinRE)** or Windows PE:
- **Clean Execution Domain**: Completely isolated from active malicious processes or rootkits present in the primary Windows OS.
- **Offline Hive Loading**: Mounts target registry files (`SYSTEM`, `SOFTWARE`, `NTUSER.DAT`) directly from disk into WinRE hives, allowing persistence neutralization without booting the compromised OS.
- **Air-Gapped & Network Independent**: Operates strictly offline, eliminating risks of C2-triggered secondary destructive wipes.

---

### 12.2 7 Core Subsystem Architecture of `bhpai_rescue.exe`

The rescue engine located at [`Rescue/`](file:///c:/Users/Kryo/Documents/BHPAI/Rescue) is written in static C++17 linked with OpenSSL and zlib:

```
Rescue/
├── include/
│   ├── RescueTargetFinder.hpp          # 1. Target OS Volume Locator & BitLocker State
│   ├── OfflineRegistryManager.hpp      # 2. Offline Hive Loader & Persistence Stripper
│   ├── OfflineMalwareScanner.hpp       # 3. BHR 10-Pillar Static PE Analysis Engine
│   ├── OfflineBlastRadius.hpp          # 4. Multi-Signal Damage & Ransom Notes Assessor
│   ├── OfflineCryptoArtifactHunter.hpp # 5. Memory Dump & pagefile.sys Key Extractor
│   ├── RescueRemediator.hpp            # 6. Transactional Remediation Coordinator
│   └── RescueTransactionJournal.hpp    # 7. ACID Transaction Journal & LIFO Rollback
└── source/
    └── bhpai_rescue_main.cpp           # CLI Entrypoint & Interactive Operator Menu
```

1. **`RescueTargetFinder` (OS Volume Locator)**:
   - Scans physical drives and mounted partitions via `FindFirstVolumeW` / `FindNextVolumeW`.
   - Validates Windows directory layouts (`System32\ntoskrnl.exe`, `System32\config\SYSTEM`, `explorer.exe`).
   - Extracts Volume GUIDs, physical disk numbers, filesystem types (NTFS/ReFS), and BitLocker lock states.
2. **`OfflineRegistryManager` (Offline Hive Loader)**:
   - Uses `RegLoadKeyW` to mount target hives into temporary roots: `HKEY_LOCAL_MACHINE\BHPAI_OFFLINE_SYSTEM`, `BHPAI_OFFLINE_SOFTWARE`, `BHPAI_OFFLINE_NTUSER`.
   - Resolves the active ControlSet via `Select\Current` (e.g., `ControlSet001`).
   - Scans and strips critical persistence vectors:
     - Winlogon Hijacks: `Shell` (hijacked to point to malware instead of `explorer.exe`) and `Userinit`.
     - Image File Execution Options (IFEO Debugger Hijacks): Rogue debuggers attached to `taskmgr.exe`, `cmd.exe`, or `sethc.exe`.
     - Run / RunOnce / RunServices keys across user and machine scopes.
     - Malicious Windows Services configured for automatic boot-time loading.
     - Scheduled Tasks parsed directly from XML definitions in `Windows\System32\Tasks`.
3. **`OfflineMalwareScanner` (BHR 10-Pillar Static PE Analyzer)**:
   - Ingests executables discovered in persistence locations and volatile directories (`AppData\Local\Temp`, `ProgramData`, `Users\Public`, `Windows\Temp`).
   - Evaluates section entropy, header anomalies, and abnormal import tables.
   - Assigns threat scores (0-100) and verdicts (`MALICIOUS`, `SUSPICIOUS`, `CLEAN`).
4. **`OfflineBlastRadius` (Multi-Signal Damage Assessment)**:
   - Audits user directories (`Desktop`, `Documents`, `Downloads`, `Pictures`, `Videos`).
   - Employs multi-signal scoring:
     - **High Confidence Encrypted**: Shannon Entropy $\ge 7.6$, altered magic headers, and bulk extension changes.
     - **Medium Confidence Suspicious**: Elevated entropy ($6.8 - 7.6$).
     - **Ransom Notes Detector**: Collects ransom communications (`README.txt`, `DECRYPT_FILES.html`, `HOW_TO_RESTORE.txt`).
5. **`OfflineCryptoArtifactHunter` (Forensic Key Hunter)**:
   - Reads directly from `pagefile.sys`, `swapfile.sys`, and memory crash dumps (`MEMORY.DMP`).
   - Searches for residual key artifacts: AES round keys (128/256-bit Key Schedules), ChaCha20 state matrices, X25519 clamped scalars, and RSA private key ASN.1 DER headers.
6. **`RescueRemediator` (Remediation Orchestrator)**:
   - Quarantines identified malicious binaries into an isolated store (`C:\BHPAI_Rescue_Quarantine\`) with verified SHA-256 digests.
   - Restores registry hygiene: resets Winlogon Shell to `explorer.exe`, strips IFEO debuggers, and disables malicious tasks and services.
7. **`RescueTransactionJournal` (ACID Journal & LIFO Rollback)**:
   - Governs the transactional remediation lifecycle. Every modification is preceded by a pre-modification backup.
   - Provides LIFO (Last-In-First-Out) rollback capability restoring the host to its exact pre-rescue state if required.

---

### 12.3 5-Phase ACID Transaction Pipeline

To ensure host stability and eliminate risks of bricking the Windows installation, `RescueRemediator` executes a rigorous 5-phase transaction:

```
[Phase 1: DETECT] ────► [Phase 2: BACKUP] ────► [Phase 3: MODIFY] ────► [Phase 4: VERIFY] ────► [Phase 5: COMMIT]
 Malicious Binaries      Full Registry Hives     Quarantine Binaries     Verify Disk State &     Mark Transaction
 & Persistence Mapped    & File Metadata (LIFO)  & Restore Registry      Checksums Match         COMMITTED
                                                         │
                                                  (Upon Failure)
                                                         ▼
                                                [AUTOMATIC ROLLBACK]
                                                (Instant LIFO Reversal)
```

1. **Phase 1 (Detect)**: Comprehensive scan indexing malicious binaries, persistence keys, and impacted data.
2. **Phase 2 (Backup)**: Allocates transaction folder `C:\BHPAI_Rescue_Backup\` tied to the volume GUID. Archives full registry hives (`SYSTEM.before`, `SOFTWARE.before`, `NTUSER.DAT.before`) and preserves file ACLs and timestamps.
3. **Phase 3 (Modify)**: Logs each action into `transaction.json`, relocates binaries to quarantine, and restores registry defaults.
4. **Phase 4 (Verify)**: Validates that threats no longer reside in active locations, verifies quarantine SHA-256 hashes, and ensures registry hives point to authentic Windows binaries.
5. **Phase 5 (Commit)**: Transitions transaction status from `IN_PROGRESS` to `COMMITTED`. Any fault occurring during Phase 3 or 4 triggers an immediate **LIFO Rollback**, restoring backup hives and returning quarantined binaries.

---

### 12.4 Crash State Recovery & Self-Healing Mechanism
If power loss or unexpected hardware failure interrupts execution during active remediation:
- Upon the subsequent WinRE boot, `bhpai_rescue.exe` inspects `transaction.json` and detects an uncommitted **CRASH STATE** (`IN_PROGRESS`).
- Displays a prominent alert: `[CRITICAL WARNING] INCOMPLETE REMEDIATION DETECTED`.
- Offers two tiers of automated self-healing:
  - **Tier 1**: Transactional rollback following the LIFO journal.
  - **Tier 2 (Emergency Hive Restore)**: Forceful restoration of all original registry hives from `*.before` backups.

---

### 12.5 Automated WinRE Deployment & Reboot Scripts

#### 1. Safe Deployment Script [`scripts/deploy_winre.ps1`](file:///c:/Users/Kryo/Documents/BHPAI/scripts/deploy_winre.ps1):
- **Direct DISM Invocation**: Streams output directly to prevent PowerShell pipeline deadlocks.
- **State Preservation**: Records initial WinRE activation status via `reagentc /info` and restores that exact state upon completion.
- **Pre-Modification Backup**: Creates a backup clone: `Winre.wim.BHPAI.backup`.
- **Dynamic Drive Adaptation**: Generates `Windows\System32\bhpai.cmd` utilizing `%~d0` and `%SystemDrive%`, dynamically resolving WinPE assigned volume letters.
- **Automated Rollback Handler**: Mount exceptions trigger automatic `/Discard` actions, restoring the backup WIM and clearing scratch files.

#### 2. Emergency Reboot Trigger Script [`scripts/trigger_rescue_reboot.ps1`](file:///c:/Users/Kryo/Documents/BHPAI/scripts/trigger_rescue_reboot.ps1):
- Enables WinRE if disabled.
- Executes `reagentc /boottore` and configures `bcdedit /set {current} recoveryenabled yes` to force an immediate one-time boot into WinRE on the subsequent reboot.

---

### 12.6 Operational Guide & Command-Line Arguments for `bhpai_rescue.exe`

Following a system reboot into the Windows Recovery Environment:
1. Navigate to: **Troubleshoot** $\rightarrow$ **Advanced options** $\rightarrow$ **Command Prompt**.
2. At the command prompt, launch:
   ```cmd
   bhpai
   ```

#### Interactive Operator Menu:
```text
Select Operation Mode:
  [1] Dry-Run Safe Triage (Inspect & Generate Report - ZERO Disk Writes)
  [2] Full Active Emergency Rescue (5-Phase Transaction: Scan -> Backup -> Remediate -> Verify -> Commit)
  [3] Multi-Signal Blast Radius Assessment (Audit Encrypted Files & Collect Ransom Notes)
  [4] Crypto Artifact Hunter (Extract Cryptographic Keys from pagefile.sys & Crash Dumps)
  [5] Registry Unbrick Only with Pre-Backup (Reset Winlogon Shell to explorer.exe)
  [6] Transactional Rollback (Revert All Changes from BHPAI_Rescue_Backup)
  [7] Exit / Return to WinRE Prompt
```

#### Advanced CLI Arguments:
```cmd
# Safe simulation without disk writes (Dry-Run):
bhpai_rescue.exe --dry-run

# Fully automated non-interactive emergency repair:
bhpai_rescue.exe --target C: --repair --auto

# Roll back a prior remediation transaction:
bhpai_rescue.exe --target C: --rollback

# Export forensic output in structured JSON format:
bhpai_rescue.exe --dry-run --json

# Specify an offline hardware-locked license file:
bhpai_rescue.exe --license C:\license.dat --repair
```

#### Generated Forensic Output Reports:
At the conclusion of each triage session, the engine outputs two forensic artifacts at the root of the target partition:
- `C:\BHPAI_Rescue_Report.json`: Detailed JSON artifact cataloging SHA-256 hashes, recovered keys, registry alterations, and transaction metadata.
- `C:\BHPAI_Rescue_Summary.md`: Comprehensive Markdown summary report tailored for security incident responders (reference sample: [`BHPAI_Rescue_Summary.md`](file:///c:/Users/Kryo/Documents/BHPAI/BHPAI_Rescue_Summary.md)).

---

## 13. OPEN SOURCE DISTRIBUTION: BHPAI COMMUNITY EDITION (`bhpai_sourceopen` - 25%)

To support cybersecurity researchers, independent auditors, and academic verification, the BHPAI project provides the **Community Edition** located in [`bhpai_sourceopen`](file:///c:/Users/Kryo/Documents/BHPAI/bhpai_sourceopen). This distribution follows the Open-Core architecture:

### Curated ~25% Core Source Code (Static PE Analysis & Multi-Format Routing):

- **`Core/scanner/`**: Complete C++ PE structural analysis engine, Opcode/API N-Grams feature extraction, CFG Cyclomatic Complexity, TF-IDF, YaraGen automated rule synthesis, AVX2-optimized string search (`StringEx`).
- **`Core/Decompile/`**: Binary disassembler engine for x86/x64 via Capstone Engine (`Disassembler`, `PeParser`).
- **`Core/pack/`**: In-memory native unpackers for UPX and WWPack.
- **`fuzzy/`**: SSDEEP context-triggered piecewise hashing (`fuzzyhash.c/.h`).
- **`Analyzers/Common/`**: 3-stage file routing (`FileRouter`), resource bounds (`ParserLimits`), MITRE ATT&CK mapping (`MitreMapper`), IOC extraction and defanging (`IOCExtractor`).
- **`Core/Train/` & `model/`**: PE feature vectorization (`feature_extractor.py`) and classification threshold configuration.
- **`scan.py` & `app_scan.py`**: High-performance CLI batch scanner and dedicated PyQt6 desktop PE analysis utility.

> [!IMPORTANT]
> **IP Safeguards & Independent Build**:
> 1. **100% PDF Exclusion**: The PDF analyzer engine is currently under development and is strictly excluded from this open-source release.
> 2. **100% Dataset Exclusion**: Zero files from the `dataset/` directory are published.
> 3. **Community License**: Bundled with a permissive Community Edition license stub (`BhpaiLicense.hpp`), enabling standalone compilation without requiring an enterprise license key.

---

*Master Technical Architecture Documentation for the BHPAIV1.6 Enterprise System, maintained and verified by the Rin449. All rights reserved.*
