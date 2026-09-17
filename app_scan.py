#!/usr/bin/env python3
"""
BHPAI Dedicated PE Scanner (app_scan.py)
========================================
Standalone, high-performance GUI application for PE Static Analysis,
visual section entropy breakdown, YARA signature inspection,
and batch directory/dataset scanning with AI Model Ensemble.
"""

from __future__ import annotations

import csv
import datetime
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure project root in sys.path
_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from gui_features import (
    AIMode,
    AIScannerEngine,
    PEInfo,
    PEMetadataExtractor,
    ScanResult,
    calculate_sha256,
    run_pe_analyzer,
)

try:
    from PyQt6.QtCore import QPointF, QRectF, QSize, Qt, QThread, QTimer, pyqtSignal
    from PyQt6.QtGui import (
        QAction,
        QBrush,
        QColor,
        QCursor,
        QFont,
        QIcon,
        QLinearGradient,
        QPainter,
        QPainterPath,
        QPen,
        QPixmap,
    )
    from PyQt6.QtWidgets import (
        QApplication,
        QButtonGroup,
        QCheckBox,
        QComboBox,
        QFileDialog,
        QFrame,
        QGridLayout,
        QGroupBox,
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QLineEdit,
        QMainWindow,
        QMessageBox,
        QProgressBar,
        QPushButton,
        QRadioButton,
        QScrollArea,
        QSizePolicy,
        QSplitter,
        QTabWidget,
        QTableWidget,
        QTableWidgetItem,
        QTextEdit,
        QVBoxLayout,
        QWidget,
    )
    QT_API = "PyQt6"
except ImportError:
    from PySide6.QtCore import QPointF, QRectF, QSize, Qt, QThread, QTimer, Signal as pyqtSignal
    from PySide6.QtGui import (
        QAction,
        QBrush,
        QColor,
        QCursor,
        QFont,
        QIcon,
        QLinearGradient,
        QPainter,
        QPainterPath,
        QPen,
        QPixmap,
    )
    from PySide6.QtWidgets import (
        QApplication,
        QButtonGroup,
        QCheckBox,
        QComboBox,
        QFileDialog,
        QFrame,
        QGridLayout,
        QGroupBox,
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QLineEdit,
        QMainWindow,
        QMessageBox,
        QProgressBar,
        QPushButton,
        QRadioButton,
        QScrollArea,
        QSizePolicy,
        QSplitter,
        QTabWidget,
        QTableWidget,
        QTableWidgetItem,
        QTextEdit,
        QVBoxLayout,
        QWidget,
    )
    QT_API = "PySide6"


# ── Color Palette (Modern Cyber Dark Theme matching Web Dashboard) ─────────────
BG_DARK       = "#0B0F14"   # Canvas background
BG_PANEL      = "#111820"   # Sidebar / Panel container
BG_CARD       = "#151D27"   # Elevated Cyber Card
BG_HOVER      = "#1E293B"   # Card Hover
BORDER_COLOR  = "#263341"   # Subtle tech border
BORDER_ACTIVE = "#00A8FF"   # Neon Cyan Focus

CYAN_NEON     = "#00A8FF"   # Primary Cyan Accent
EMERALD_GREEN = "#00D084"   # Clean / High confidence
ROSE_RED      = "#FF4D5E"   # Threat / Malicious
AMBER_WARN    = "#FFB020"   # Warning / Suspicious
PURPLE_ACCENT = "#A855F7"   # Forensics / Deep AI

TEXT_PRIMARY   = "#F1F5F9"  # High-contrast readable title
TEXT_SECONDARY = "#94A3B8"  # Body text
TEXT_MUTED     = "#64748B"  # Subtitles and table headers


SCANNER_STYLESHEET = f"""
QMainWindow, QWidget {{
    background-color: {BG_DARK};
    color: {TEXT_PRIMARY};
    font-family: 'Segoe UI', 'Consolas', monospace;
    font-size: 9.5pt;
}}

QFrame#cyberCard {{
    background-color: {BG_CARD};
    border: 1px solid {BORDER_COLOR};
    border-radius: 10px;
}}
QFrame#cyberCard:hover {{
    border: 1px solid {CYAN_NEON};
}}

QLineEdit, QComboBox {{
    background-color: {BG_PANEL};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER_COLOR};
    border-radius: 6px;
    padding: 6px 10px;
    font-family: 'Consolas', monospace;
}}
QLineEdit:focus, QComboBox:focus {{
    border: 1px solid {CYAN_NEON};
}}

QPushButton {{
    background-color: {BG_CARD};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER_COLOR};
    border-radius: 6px;
    padding: 7px 14px;
    font-weight: bold;
}}
QPushButton:hover {{
    background-color: {BG_HOVER};
    border-color: {CYAN_NEON};
    color: {CYAN_NEON};
}}

QProgressBar {{
    background-color: {BG_PANEL};
    border: 1px solid {BORDER_COLOR};
    border-radius: 4px;
    text-align: center;
    color: {TEXT_PRIMARY};
    font-weight: bold;
}}
QProgressBar::chunk {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 {EMERALD_GREEN}, stop:1 {CYAN_NEON});
    border-radius: 3px;
}}

QTableWidget {{
    background-color: {BG_CARD};
    border: 1px solid {BORDER_COLOR};
    border-radius: 8px;
    gridline-color: {BORDER_COLOR};
    color: {TEXT_PRIMARY};
    font-family: 'Consolas', monospace;
}}
QHeaderView::section {{
    background-color: {BG_PANEL};
    color: {TEXT_MUTED};
    padding: 5px;
    border: 1px solid {BORDER_COLOR};
    font-weight: bold;
}}
QTableWidget::item:selected {{
    background-color: {BG_HOVER};
    color: {EMERALD_GREEN};
}}

QTabWidget::pane {{
    border: 1px solid {BORDER_COLOR};
    background-color: {BG_CARD};
    border-radius: 8px;
}}
QTabBar::tab {{
    background-color: {BG_PANEL};
    color: {TEXT_SECONDARY};
    border: 1px solid {BORDER_COLOR};
    padding: 7px 16px;
    margin-right: 4px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    font-weight: bold;
}}
QTabBar::tab:selected {{
    background-color: {BG_CARD};
    color: {EMERALD_GREEN};
    border-bottom: 2px solid {EMERALD_GREEN};
}}
"""


# ── Threat Radial Gauge Widget ───────────────────────────────────────────────
class ThreatGauge(QWidget):
    """Futuristic circular gauge displaying Threat Risk Score (0-100)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._score = 0.0
        self.setFixedSize(140, 140)

    def set_score(self, score: float):
        self._score = max(0.0, min(100.0, float(score)))
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w, h = self.width(), self.height()
        side = min(w, h)
        rect = QRectF((w - side) / 2 + 10, (h - side) / 2 + 10, side - 20, side - 20)

        # Background track
        pen_bg = QPen(QColor(BORDER_COLOR), 8)
        pen_bg.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen_bg)
        painter.drawArc(rect, -90 * 16, 360 * 16)

        # Dynamic color
        if self._score >= 70:
            c = QColor(ROSE_RED)
        elif self._score >= 40:
            c = QColor(AMBER_WARN)
        elif self._score > 0:
            c = QColor(CYAN_NEON)
        else:
            c = QColor(EMERALD_GREEN)

        # Progress Arc
        if self._score > 0:
            pen_fg = QPen(c, 8)
            pen_fg.setCapStyle(Qt.PenCapStyle.RoundCap)
            painter.setPen(pen_fg)
            span_angle = int(-(self._score / 100.0) * 360 * 16)
            painter.drawArc(rect, 90 * 16, span_angle)

        # Central text
        painter.setPen(c)
        f = QFont("Consolas", 18, QFont.Weight.Bold)
        painter.setFont(f)
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, f"{int(self._score)}")

        # Label
        painter.setPen(QColor(TEXT_MUTED))
        f_sub = QFont("Segoe UI", 7, QFont.Weight.Bold)
        painter.setFont(f_sub)
        sub_rect = QRectF(rect.x(), rect.y() + 26, rect.width(), rect.height())
        label = "MALICIOUS" if self._score >= 70 else "SUSPICIOUS" if self._score >= 40 else "BENIGN"
        painter.drawText(sub_rect, Qt.AlignmentFlag.AlignCenter, label)


# ── Interactive Dropzone Frame ───────────────────────────────────────────────
class DropZone(QFrame):
    file_dropped = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("cyberCard")
        self.setAcceptDrops(True)
        self.setMinimumHeight(140)
        self._is_hovered = False

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.icon_lbl = QLabel("⚡")
        self.icon_lbl.setFont(QFont("Segoe UI", 24))
        self.icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.icon_lbl.setStyleSheet(f"color: {CYAN_NEON};")

        self.title_lbl = QLabel("KÉO THẢ TỆP TIN THỰC THI (PE) VÀO ĐÂY HOẶC CHỌN TỆP")
        self.title_lbl.setFont(QFont("Consolas", 10, QFont.Weight.Bold))
        self.title_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.title_lbl.setStyleSheet(f"color: {EMERALD_GREEN};")

        self.sub_lbl = QLabel("Hỗ trợ: .exe, .dll, .sys, .bin (Phân tích tĩnh cấu trúc PE, Entropy & AI Ensemble)")
        self.sub_lbl.setFont(QFont("Segoe UI", 8))
        self.sub_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.sub_lbl.setStyleSheet(f"color: {TEXT_MUTED};")

        layout.addWidget(self.icon_lbl)
        layout.addWidget(self.title_lbl)
        layout.addWidget(self.sub_lbl)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self.setStyleSheet(f"background-color: {BG_HOVER}; border: 2px dashed {EMERALD_GREEN}; border-radius: 10px;")

    def dragLeaveEvent(self, event):
        self.setStyleSheet("")

    def dropEvent(self, event):
        self.setStyleSheet("")
        urls = event.mimeData().urls()
        if urls:
            path = urls[0].toLocalFile()
            if path:
                self.file_dropped.emit(path)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            fn, _ = QFileDialog.getOpenFileName(
                self,
                "Chọn tệp thực thi phân tích tĩnh",
                "",
                "PE Files (*.exe *.dll *.sys *.bin);;All Files (*.*)"
            )
            if fn:
                self.file_dropped.emit(fn)


def extract_section_details(filepath: str) -> List[Dict[str, Any]]:
    details: List[Dict[str, Any]] = []
    try:
        import pefile
        pe = pefile.PE(filepath, fast_load=True)
        for sec in pe.sections:
            name = sec.Name.decode("utf-8", "ignore").strip("\x00")
            vsize = getattr(sec, "Misc_VirtualSize", 0)
            rsize = getattr(sec, "SizeOfRawData", 0)
            ent = round(sec.get_entropy(), 3)
            details.append({
                "name": name,
                "virtual_size": vsize,
                "raw_size": rsize,
                "entropy": ent
            })
    except Exception:
        pass
    return details


def extract_import_details(filepath: str) -> List[Tuple[str, str, bool]]:
    details: List[Tuple[str, str, bool]] = []
    suspicious_apis = {
        "virtualalloc", "virtualprotect", "writeprocessmemory", "createremotethread",
        "openprocess", "ntunmapviewofsection", "isdebuggerpresent", "checkremotedebuggerpresent",
        "urldownloadtofile", "winhttpopen", "internetopen", "regsetvalue", "regcreatekey",
        "setwindowshook", "getasynckeystate", "cryptencrypt"
    }
    try:
        import pefile
        pe = pefile.PE(filepath)
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", "ignore") if entry.dll else "Unknown.dll"
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode("utf-8", "ignore")
                        is_sus = any(s in func_name.lower() for s in suspicious_apis)
                        details.append((dll_name, func_name, is_sus))
    except Exception:
        pass
    return details


# ── Background Scan Worker Thread ───────────────────────────────────────────
class ScanWorker(QThread):
    progress = pyqtSignal(int, str)
    single_done = pyqtSignal(object)  # ScanResult
    batch_item_done = pyqtSignal(dict)
    batch_all_done = pyqtSignal(int, int)  # total, malicious

    def __init__(self, mode: str, target_path: str, ai_mode: str = "HYBRID", parent=None):
        super().__init__(parent)
        self.mode = mode  # "single" or "batch"
        self.target_path = target_path
        self.ai_mode = ai_mode
        self._is_cancelled = False

    def cancel(self):
        self._is_cancelled = True

    def run(self):
        if self.mode == "single":
            self._run_single()
        else:
            self._run_batch()

    def _run_single(self):
        p = Path(self.target_path)
        if not p.exists():
            return

        self.progress.emit(10, f"Đang tính toán mã băm SHA256 cho {p.name}...")
        sha = calculate_sha256(str(p))

        self.progress.emit(35, "Đang giải mã PE Headers, Section Table & Entropy...")
        meta = PEMetadataExtractor.extract(str(p))

        self.progress.emit(65, "Đang đối soát quy tắc mẫu độc hại YARA & Byte Opcode...")
        temp_dir = _PROJECT_ROOT / "gui_temp"
        temp_dir.mkdir(exist_ok=True)
        try:
            raw_pe = run_pe_analyzer(str(p), temp_dir)
        except Exception:
            pass

        self.progress.emit(85, "Đang nạp đặc trưng vào mô hình AI Ensemble...")
        res = AIScannerEngine.analyze(str(p), mode=AIMode.ONLY_STATIC)

        self.progress.emit(100, "Hoàn thành phân tích tĩnh PE!")
        self.single_done.emit(res)

    def _run_batch(self):
        root = Path(self.target_path)
        if not root.exists():
            return

        targets = []
        for curr, _, files in os.walk(root):
            if self._is_cancelled:
                break
            for f in files:
                ext = os.path.splitext(f)[1].lower()
                if ext in (".exe", ".dll", ".sys", ""):
                    targets.append(Path(curr) / f)

        total = len(targets)
        malicious_count = 0

        for idx, file_path in enumerate(targets):
            if self._is_cancelled:
                break

            pct = int(((idx + 1) / max(total, 1)) * 100)
            self.progress.emit(pct, f"Đang quét ({idx + 1}/{total}): {file_path.name}")

            try:
                res = AIScannerEngine.analyze(str(file_path), mode=AIMode.ONLY_STATIC)
                is_mal = res.threat_score >= 50
                if is_mal:
                    malicious_count += 1

                self.batch_item_done.emit({
                    "filename": res.filename,
                    "filepath": res.filepath,
                    "sha256": res.pe_info.sha256,
                    "score": res.threat_score,
                    "label": res.risk_label,
                    "color": res.risk_color,
                    "arch": res.pe_info.architecture or "x86/x64",
                    "time": f"{res.execution_time_sec:.2f}s"
                })
            except Exception as e:
                self.batch_item_done.emit({
                    "filename": file_path.name,
                    "filepath": str(file_path),
                    "sha256": "N/A",
                    "score": 0,
                    "label": "ERROR",
                    "color": TEXT_MUTED,
                    "arch": "Unknown",
                    "time": "0.0s"
                })

        self.batch_all_done.emit(total, malicious_count)


# ── Main Scanner Window ──────────────────────────────────────────────────────
class BHPAIScannerWindow(QMainWindow):
    """Dedicated Standalone PE Scanner Window for BHPAI."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("BHPAI Dedicated PE Scanner & Dataset Analyzer v2.0")
        self.resize(1180, 820)
        self.setMinimumSize(950, 650)
        self.setStyleSheet(SCANNER_STYLESHEET)

        self._current_result: Optional[ScanResult] = None
        self._batch_results: List[dict] = []
        self._worker: Optional[ScanWorker] = None

        self._build_ui()

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(16, 16, 16, 16)
        main_layout.setSpacing(12)

        # ── Top Header ───────────────────────────────────────────────
        header = QFrame()
        header.setObjectName("cyberCard")
        h_layout = QHBoxLayout(header)
        h_layout.setContentsMargins(14, 10, 14, 10)

        title_box = QVBoxLayout()
        title_lbl = QLabel("BHPAI PE STATIC ANALYZER")
        title_lbl.setFont(QFont("Consolas", 13, QFont.Weight.Bold))
        title_lbl.setStyleSheet(f"color: {CYAN_NEON};")
        sub_lbl = QLabel("Zero-Execution PE Header Forensics • Section Entropy • YARA Signatures • AI Ensemble")
        sub_lbl.setFont(QFont("Segoe UI", 9))
        sub_lbl.setStyleSheet(f"color: {TEXT_MUTED};")
        title_box.addWidget(title_lbl)
        title_box.addWidget(sub_lbl)
        h_layout.addLayout(title_box)
        h_layout.addStretch()

        # Engine Badge
        engine_badge = QLabel("● ENGINE STANDALONE READY")
        engine_badge.setFont(QFont("Consolas", 9, QFont.Weight.Bold))
        engine_badge.setStyleSheet(f"color: {EMERALD_GREEN}; background: #00D08415; border: 1px solid #00D08440; border-radius: 6px; padding: 4px 10px;")
        h_layout.addWidget(engine_badge)

        main_layout.addWidget(header)

        # ── Drop Zone ────────────────────────────────────────────────
        self.drop_zone = DropZone()
        self.drop_zone.file_dropped.connect(self._on_file_selected)
        main_layout.addWidget(self.drop_zone)

        # ── Controls Bar ─────────────────────────────────────────────
        controls = QFrame()
        controls.setObjectName("cyberCard")
        c_layout = QHBoxLayout(controls)
        c_layout.setContentsMargins(12, 8, 12, 8)

        c_layout.addWidget(QLabel("Mục tiêu:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Đường dẫn tệp .exe / .dll hoặc thư mục dataset...")
        c_layout.addWidget(self.target_input, stretch=1)

        self.btn_browse_file = QPushButton("📁 Chọn File")
        self.btn_browse_file.clicked.connect(self._browse_file)
        c_layout.addWidget(self.btn_browse_file)

        self.btn_browse_folder = QPushButton("📂 Chọn Thư Mục")
        self.btn_browse_folder.clicked.connect(self._browse_folder)
        c_layout.addWidget(self.btn_browse_folder)

        c_layout.addWidget(QLabel("Mô hình AI:"))
        self.ai_combo = QComboBox()
        self.ai_combo.addItems(["HYBRID (LightGBM + PE Analyzer)", "STATIC_ONLY (YARA + Opcode)", "FAST_HEURISTIC (Quick Hash + Headers)"])
        c_layout.addWidget(self.ai_combo)

        self.btn_start = QPushButton("⚡ QUÉT NGAY")
        self.btn_start.setStyleSheet(f"background-color: {EMERALD_GREEN}; color: #0B0F14; font-weight: bold; border-radius: 6px;")
        self.btn_start.clicked.connect(self._start_scan)
        c_layout.addWidget(self.btn_start)

        main_layout.addWidget(controls)

        # ── Progress Bar ─────────────────────────────────────────────
        self.progress_frame = QFrame()
        p_layout = QHBoxLayout(self.progress_frame)
        p_layout.setContentsMargins(0, 0, 0, 0)
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_lbl = QLabel("Sẵn sàng")
        self.progress_lbl.setFont(QFont("Consolas", 9))
        self.progress_lbl.setStyleSheet(f"color: {TEXT_MUTED};")
        p_layout.addWidget(self.progress_bar, stretch=1)
        p_layout.addWidget(self.progress_lbl)
        main_layout.addWidget(self.progress_frame)

        # ── Result Tabs ──────────────────────────────────────────────
        self.tabs = QTabWidget()

        # Tab 1: Single File Overview & Headers
        self.tab_single = QWidget()
        self._build_single_tab()
        self.tabs.addTab(self.tab_single, "📊 Kết Quả Tệp Đơn Lẻ")

        # Tab 2: Section Entropy Visualizer
        self.tab_sections = QWidget()
        self._build_sections_tab()
        self.tabs.addTab(self.tab_sections, "📈 Cấu Trúc PE & Entropy")

        # Tab 3: Imports & API Forensics
        self.tab_imports = QWidget()
        self._build_imports_tab()
        self.tabs.addTab(self.tab_imports, "🧩 Windows API Imports")

        # Tab 4: Batch Dataset Scan Table
        self.tab_batch = QWidget()
        self._build_batch_tab()
        self.tabs.addTab(self.tab_batch, "📁 Quét Thư Mục Hàng Loạt")

        main_layout.addWidget(self.tabs, stretch=1)

        # ── Footer Actions ───────────────────────────────────────────
        footer = QHBoxLayout()
        self.btn_export_json = QPushButton("💾 Xuất Báo Cáo JSON")
        self.btn_export_json.clicked.connect(self._export_json)
        self.btn_export_csv = QPushButton("📑 Xuất Báo Cáo CSV")
        self.btn_export_csv.clicked.connect(self._export_csv)

        footer.addWidget(self.btn_export_json)
        footer.addWidget(self.btn_export_csv)
        footer.addStretch()

        self.btn_quarantine = QPushButton("🛡️ Cách Ly Tệp")
        self.btn_quarantine.setStyleSheet(f"color: {AMBER_WARN}; border-color: {AMBER_WARN};")
        self.btn_quarantine.clicked.connect(self._quarantine_current)
        footer.addWidget(self.btn_quarantine)

        main_layout.addLayout(footer)

    def _build_single_tab(self):
        layout = QHBoxLayout(self.tab_single)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(14)

        # Left gauge & verdict box
        verdict_box = QFrame()
        verdict_box.setObjectName("cyberCard")
        verdict_box.setFixedWidth(240)
        v_layout = QVBoxLayout(verdict_box)
        v_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        v_layout.setSpacing(8)

        self.gauge = ThreatGauge()
        v_layout.addWidget(self.gauge)

        self.verdict_badge = QLabel("CHƯA QUÉT")
        self.verdict_badge.setFont(QFont("Consolas", 10, QFont.Weight.Bold))
        self.verdict_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.verdict_badge.setStyleSheet(f"color: {TEXT_MUTED}; background: #263341; border-radius: 4px; padding: 4px 10px;")
        v_layout.addWidget(self.verdict_badge)

        self.meta_summary = QLabel("Chưa có dữ liệu phân tích")
        self.meta_summary.setFont(QFont("Segoe UI", 8))
        self.meta_summary.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.meta_summary.setStyleSheet(f"color: {TEXT_MUTED};")
        v_layout.addWidget(self.meta_summary)
        v_layout.addStretch()

        layout.addWidget(verdict_box)

        # Right details table
        self.table_single = QTableWidget(0, 2)
        self.table_single.setHorizontalHeaderLabels(["Thuộc Tính", "Giá Trị"])
        self.table_single.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table_single.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table_single, stretch=1)

    def _build_sections_tab(self):
        layout = QVBoxLayout(self.tab_sections)
        layout.setContentsMargins(14, 14, 14, 14)

        self.table_sections = QTableWidget(0, 5)
        self.table_sections.setHorizontalHeaderLabels(["Tên Section", "Virtual Size", "Raw Size", "Entropy (0-8)", "Đánh Giá An Ninh"])
        self.table_sections.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table_sections)

    def _build_imports_tab(self):
        layout = QVBoxLayout(self.tab_imports)
        layout.setContentsMargins(14, 14, 14, 14)

        self.table_imports = QTableWidget(0, 3)
        self.table_imports.setHorizontalHeaderLabels(["Thư Viện DLL", "Hàm Windows API Import", "Mức Độ Rủi Ro"])
        self.table_imports.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table_imports.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table_imports.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        layout.addWidget(self.table_imports)

    def _build_batch_tab(self):
        layout = QVBoxLayout(self.tab_batch)
        layout.setContentsMargins(14, 14, 14, 14)

        self.table_batch = QTableWidget(0, 6)
        self.table_batch.setHorizontalHeaderLabels(["Tên Tệp", "Điểm Nguy Cơ", "Đánh Giá", "Kiến Trúc", "Thời Gian", "SHA256"])
        self.table_batch.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table_batch.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table_batch.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table_batch.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table_batch.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table_batch.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table_batch)

    # ── Actions & Slots ──────────────────────────────────────────
    def _browse_file(self):
        fn, _ = QFileDialog.getOpenFileName(
            self, "Chọn file thực thi", "", "PE Files (*.exe *.dll *.sys);;All Files (*.*)"
        )
        if fn:
            self._on_file_selected(fn)

    def _browse_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Chọn thư mục quét PE hàng loạt")
        if folder:
            self.target_input.setText(folder)
            self.tabs.setCurrentWidget(self.tab_batch)

    def _on_file_selected(self, path: str):
        self.target_input.setText(path)
        if os.path.isfile(path):
            self.tabs.setCurrentWidget(self.tab_single)
            self._start_scan()
        elif os.path.isdir(path):
            self.tabs.setCurrentWidget(self.tab_batch)
            self._start_scan()

    def _start_scan(self):
        target = self.target_input.text().strip()
        if not target or not os.path.exists(target):
            QMessageBox.warning(self, "Thiếu Mục Tiêu", "Vui lòng chọn một tệp tin hoặc thư mục hợp lệ để quét.")
            return

        is_dir = os.path.isdir(target)
        mode = "batch" if is_dir else "single"

        self.btn_start.setEnabled(False)
        self.progress_bar.setValue(0)
        self.progress_lbl.setText("Đang khởi tạo bộ quét...")

        if is_dir:
            self._batch_results.clear()
            self.table_batch.setRowCount(0)

        ai_choice = "HYBRID"
        if "STATIC_ONLY" in self.ai_combo.currentText():
            ai_choice = "STATIC_ONLY"
        elif "FAST_HEURISTIC" in self.ai_combo.currentText():
            ai_choice = "FAST_HEURISTIC"

        self._worker = ScanWorker(mode, target, ai_mode=ai_choice, parent=self)
        self._worker.progress.connect(self._on_progress)
        if mode == "single":
            self._worker.single_done.connect(self._on_single_done)
        else:
            self._worker.batch_item_done.connect(self._on_batch_item_done)
            self._worker.batch_all_done.connect(self._on_batch_all_done)

        self._worker.start()

    def _on_progress(self, pct: int, msg: str):
        self.progress_bar.setValue(pct)
        self.progress_lbl.setText(msg)

    def _on_single_done(self, res: ScanResult):
        self.btn_start.setEnabled(True)
        self._current_result = res
        score = res.threat_score
        self.gauge.set_score(score)

        if score >= 70:
            badge_text = "MALICIOUS / ĐỘC HẠI"
            badge_color = ROSE_RED
        elif score >= 40:
            badge_text = "SUSPICIOUS / KHẢ NGHI"
            badge_color = AMBER_WARN
        else:
            badge_text = "BENIGN / AN TOÀN"
            badge_color = EMERALD_GREEN

        self.verdict_badge.setText(badge_text)
        self.verdict_badge.setStyleSheet(f"color: {badge_color}; background: {badge_color}20; border: 1px solid {badge_color}50; border-radius: 4px; padding: 4px 10px; font-weight: bold;")
        self.meta_summary.setText(f"Tệp: {res.filename}\nThời gian phân tích: {res.execution_time_sec:.2f}s")

        # Populate Single table
        props = [
            ("Tên tệp tin", res.filename),
            ("Đường dẫn tệp", res.filepath),
            ("Mã băm SHA256", res.pe_info.sha256),
            ("Mã băm MD5", res.pe_info.md5),
            ("Kích thước tệp", f"{res.pe_info.file_size_bytes:,} bytes"),
            ("Kiến trúc phần cứng", res.pe_info.architecture or "IMAGE_FILE_MACHINE_AMD64"),
            ("Thời điểm biên dịch", res.pe_info.compile_time or "N/A"),
            ("Chứng chỉ số (Signer)", res.pe_info.signer or "Unsigned"),
            ("Độ hỗn loạn Entropy", f"{res.pe_info.entropy:.3f} {'(Đóng gói/Nén UPX)' if res.pe_info.packed else '(Bình thường)'}"),
            ("Số lượng Sections", str(res.pe_info.sections)),
            ("Tổng số hàm Imports", str(res.pe_info.imports_count)),
            ("Imports khả nghi", ", ".join(res.pe_info.suspicious_imports) if res.pe_info.suspicious_imports else "Không"),
            ("Quy tắc YARA khớp", ", ".join(res.behavior_matched_rules) if res.behavior_matched_rules else "Không phát hiện YARA độc hại"),
            ("Giải thích AI (SHAP)", "; ".join([f"{r[0]} ({r[1]:+.2f})" for r in res.shap_reasons[:4]]) if res.shap_reasons else "Đặc trưng phân bố bình thường"),
        ]

        self.table_single.setRowCount(len(props))
        for row, (k, v) in enumerate(props):
            item_k = QTableWidgetItem(k)
            item_k.setForeground(QColor(TEXT_MUTED))
            item_v = QTableWidgetItem(str(v))
            self.table_single.setItem(row, 0, item_k)
            self.table_single.setItem(row, 1, item_v)

        # Populate Sections table with real section details
        sec_details = extract_section_details(res.filepath)
        if not sec_details and res.pe_info.section_names:
            sec_details = [{"name": name, "virtual_size": 0, "raw_size": 0, "entropy": res.pe_info.entropy} for name in res.pe_info.section_names]

        self.table_sections.setRowCount(len(sec_details))
        for row, s in enumerate(sec_details):
            name = s.get("name", "N/A")
            vsize = s.get("virtual_size", 0)
            rsize = s.get("raw_size", 0)
            ent = s.get("entropy", 0.0)

            ent_eval = "Bình thường"
            c = TEXT_PRIMARY
            if ent > 7.2:
                ent_eval = "RẤT CAO (Nén/Mã Hóa - Packed)"
                c = ROSE_RED
            elif ent > 6.4:
                ent_eval = "Hơi cao"
                c = AMBER_WARN

            self.table_sections.setItem(row, 0, QTableWidgetItem(name))
            self.table_sections.setItem(row, 1, QTableWidgetItem(f"{vsize:,} B"))
            self.table_sections.setItem(row, 2, QTableWidgetItem(f"{rsize:,} B"))

            ent_item = QTableWidgetItem(f"{ent:.3f}")
            ent_item.setForeground(QColor(c))
            self.table_sections.setItem(row, 3, ent_item)

            eval_item = QTableWidgetItem(ent_eval)
            eval_item.setForeground(QColor(c))
            self.table_sections.setItem(row, 4, eval_item)

        # Populate Imports table with real parsed DLL & functions
        import_details = extract_import_details(res.filepath)
        self.table_imports.setRowCount(len(import_details))
        for row, (dll, func, is_sus) in enumerate(import_details):
            self.table_imports.setItem(row, 0, QTableWidgetItem(dll))
            self.table_imports.setItem(row, 1, QTableWidgetItem(func))
            risk_item = QTableWidgetItem("Khả nghi (Suspicious API)" if is_sus else "Bình thường")
            risk_item.setForeground(QColor(ROSE_RED if is_sus else EMERALD_GREEN))
            self.table_imports.setItem(row, 2, risk_item)

    def _on_batch_item_done(self, item: dict):
        self._batch_results.append(item)
        row = self.table_batch.rowCount()
        self.table_batch.insertRow(row)

        self.table_batch.setItem(row, 0, QTableWidgetItem(item["filename"]))
        score_item = QTableWidgetItem(f"{item['score']}%")
        score_item.setForeground(QColor(item["color"]))
        self.table_batch.setItem(row, 1, score_item)

        lbl_item = QTableWidgetItem(item["label"])
        lbl_item.setForeground(QColor(item["color"]))
        self.table_batch.setItem(row, 2, lbl_item)

        self.table_batch.setItem(row, 3, QTableWidgetItem(item["arch"]))
        self.table_batch.setItem(row, 4, QTableWidgetItem(item["time"]))
        self.table_batch.setItem(row, 5, QTableWidgetItem(item["sha256"]))

    def _on_batch_all_done(self, total: int, malicious: int):
        self.btn_start.setEnabled(True)
        self.progress_bar.setValue(100)
        self.progress_lbl.setText(f"Hoàn thành quét hàng loạt: {total} tệp ({malicious} độc hại)")
        QMessageBox.information(
            self,
            "Quét Hàng Loạt Hoàn Tất",
            f"Đã quét thành công {total} tệp thực thi.\nPhát hiện: {malicious} tệp mã độc / khả nghi."
        )

    def _export_json(self):
        if not self._current_result and not self._batch_results:
            QMessageBox.warning(self, "Không có dữ liệu", "Vui lòng thực hiện quét trước khi xuất báo cáo.")
            return

        fn, _ = QFileDialog.getSaveFileName(self, "Lưu báo cáo JSON", "scan_report.json", "JSON Files (*.json)")
        if fn:
            out_data: Dict[str, Any] = {"timestamp": datetime.datetime.now().isoformat()}
            if self._current_result:
                out_data["single_scan"] = {
                    "filename": self._current_result.filename,
                    "sha256": self._current_result.pe_info.sha256,
                    "threat_score": self._current_result.threat_score,
                    "verdict": self._current_result.risk_label,
                    "execution_time_sec": self._current_result.execution_time_sec,
                }
            if self._batch_results:
                out_data["batch_scans"] = self._batch_results

            with open(fn, "w", encoding="utf-8") as f:
                json.dump(out_data, f, indent=2, ensure_ascii=False)
            QMessageBox.information(self, "Xuất thành công", f"Báo cáo JSON đã lưu tại:\n{fn}")

    def _export_csv(self):
        if not self._batch_results and not self._current_result:
            QMessageBox.warning(self, "Không có dữ liệu", "Vui lòng quét dữ liệu trước khi xuất CSV.")
            return

        fn, _ = QFileDialog.getSaveFileName(self, "Lưu báo cáo CSV", "scan_report.csv", "CSV Files (*.csv)")
        if fn:
            with open(fn, "w", encoding="utf-8-sig", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Filename", "Filepath", "ThreatScore", "Label", "Arch", "ExecutionTime", "SHA256"])
                if self._batch_results:
                    for b in self._batch_results:
                        writer.writerow([b["filename"], b["filepath"], b["score"], b["label"], b["arch"], b["time"], b["sha256"]])
                elif self._current_result:
                    r = self._current_result
                    writer.writerow([r.filename, r.filepath, r.threat_score, r.risk_label, r.pe_info.architecture, f"{r.execution_time_sec:.2f}s", r.pe_info.sha256])
            QMessageBox.information(self, "Xuất thành công", f"Báo cáo CSV đã lưu tại:\n{fn}")

    def _quarantine_current(self):
        if not self._current_result:
            QMessageBox.warning(self, "Chưa chọn tệp", "Vui lòng quét một tệp trước khi cách ly.")
            return

        target_path = self._current_result.filepath
        if not os.path.exists(target_path):
            QMessageBox.warning(self, "Lỗi", "Không tìm thấy tệp gốc trên ổ đĩa.")
            return

        quarantine_dir = _PROJECT_ROOT / "recovery" / "quarantine"
        quarantine_dir.mkdir(parents=True, exist_ok=True)
        dest = quarantine_dir / f"{Path(target_path).name}.bhpai_locked"

        try:
            os.rename(target_path, dest)
            QMessageBox.information(self, "Cách Ly Thành Công", f"Tệp tin đã được di chuyển an toàn vào trạm cách ly:\n{dest}")
        except Exception as e:
            QMessageBox.warning(self, "Lỗi Cách Ly", f"Không thể cách ly tệp: {e}")


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    win = BHPAIScannerWindow()
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
