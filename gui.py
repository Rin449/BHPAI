from __future__ import annotations
import datetime
import os
import sys
from pathlib import Path
from gui_features import (
    AIMode,
    AIScannerEngine,
    BenchmarkEngine,
    BHPAISandboxRunner,
    PEInfo,
    PEMetadataExtractor,
    RealtimeGuardEngine,
    ScanResult,
    SystemMonitor,
)
try:
    from gui_vault import EncryptedBackupVaultWidget
except Exception:
    EncryptedBackupVaultWidget = None

try:
    from PyQt6.QtCore import QFileSystemWatcher, QPointF, QRectF, QSize, Qt, QTimer, QThread, pyqtSignal
    from PyQt6.QtGui import (
        QAction,
        QBrush,
        QColor,
        QConicalGradient,
        QCursor,
        QFont,
        QFontMetrics,
        QIcon,
        QLinearGradient,
        QPainter,
        QPainterPath,
        QPen,
        QPixmap,
        QTextCursor,
    )
    from PyQt6.QtWidgets import (
        QApplication,
        QButtonGroup,
        QCheckBox,
        QDialog,
        QDoubleSpinBox,
        QFileDialog,
        QFrame,
        QGraphicsDropShadowEffect,
        QGridLayout,
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QLineEdit,
        QMainWindow,
        QMenu,
        QMessageBox,
        QProgressBar,
        QPushButton,
        QRadioButton,
        QScrollArea,
        QSizePolicy,
        QSlider,
        QSpinBox,
        QSplitter,
        QStackedWidget,
        QSystemTrayIcon,
        QTableWidget,
        QTableWidgetItem,
        QTextEdit,
        QVBoxLayout,
        QWidget,
    )
    QT_API = "PyQt6"
except ImportError:
    from PySide6.QtCore import QFileSystemWatcher, QPointF, QRectF, QSize, Qt, QTimer, QThread, Signal as pyqtSignal
    from PySide6.QtGui import (
        QAction,
        QBrush,
        QColor,
        QConicalGradient,
        QCursor,
        QFont,
        QFontMetrics,
        QIcon,
        QLinearGradient,
        QPainter,
        QPainterPath,
        QPen,
        QPixmap,
        QTextCursor,
    )
    from PySide6.QtWidgets import (
        QApplication,
        QButtonGroup,
        QCheckBox,
        QDialog,
        QDoubleSpinBox,
        QFileDialog,
        QFrame,
        QGraphicsDropShadowEffect,
        QGridLayout,
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QLineEdit,
        QMainWindow,
        QMenu,
        QMessageBox,
        QProgressBar,
        QPushButton,
        QRadioButton,
        QScrollArea,
        QSizePolicy,
        QSlider,
        QSpinBox,
        QSplitter,
        QStackedWidget,
        QSystemTrayIcon,
        QTableWidget,
        QTableWidgetItem,
        QTextEdit,
        QVBoxLayout,
        QWidget,
    )
    QT_API = "PySide6"


APP_VERSION = "V1.5 Enterprise"
APP_NAME = "BHPAI Security Suite"


BG_MAIN       = "#f8fafc"
BG_PANEL      = "#ffffff"
BG_CARD       = "#ffffff"
BG_CARD_ALT   = "#f1f5f9"
BG_HOVER      = "#e2e8f0"
BG_INPUT      = "#ffffff"
BG_TERMINAL   = "#0f172a"

ACCENT_BLUE   = "#2563eb"
ACCENT_LIGHT  = "#3b82f6"
CYAN_ACCENT   = "#0284c7"
EMERALD_GREEN = "#059669"
ROSE_RED      = "#dc2626"
AMBER_WARN    = "#d97706"

BORDER_LIGHT  = "#cbd5e1"
BORDER_DARK   = "#94a3b8"
BORDER_ACTIVE = "#2563eb"

FG_PRIMARY    = "#0f172a"
FG_SECONDARY  = "#334155"
FG_MUTED      = "#475569"
FG_DIM        = "#64748b"

SIDEBAR_W = 270
IMAGE_DIR = Path(__file__).parent / "image"
LOGO_PATH = IMAGE_DIR / "BHPA.png"

def load_logo_scaled(width: int) -> QPixmap | None:
    if LOGO_PATH.exists():
        pm = QPixmap(str(LOGO_PATH))
        if not pm.isNull():
            return pm.scaledToWidth(
                width,
                Qt.TransformationMode.SmoothTransformation,
            )
    return None


def get_font(family: str = "Segoe UI", size: float = 10.0, bold: bool = False) -> QFont:
    f = QFont(family, int(round(size)))
    f.setBold(bold)
    return f


APP_STYLESHEET = f"""
QMainWindow, QWidget {{
    background-color: {BG_MAIN};
    color: {FG_PRIMARY};
    font-family: 'Segoe UI', 'Inter', -apple-system, sans-serif;
    font-size: 10pt;
}}

/* Custom Scrollbars */
QScrollBar:vertical {{
    border: none;
    background: {BG_MAIN};
    width: 8px;
    margin: 0px;
}}
QScrollBar::handle:vertical {{
    background: {BORDER_LIGHT};
    border-radius: 4px;
    min-height: 35px;
}}
QScrollBar::handle:vertical:hover {{
    background: {ACCENT_BLUE};
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}

QFrame#cardFrame {{
    background-color: {BG_CARD};
    border: 1px solid {BORDER_LIGHT};
    border-radius: 12px;
}}
QFrame#cardFrame:hover {{
    border: 1px solid {ACCENT_LIGHT};
}}

QLineEdit, QSpinBox, QDoubleSpinBox {{
    background-color: {BG_INPUT};
    color: {FG_PRIMARY};
    border: 2px solid {BORDER_LIGHT};
    border-radius: 8px;
    padding: 7px 12px;
    font-weight: bold;
    font-size: 10pt;
    selection-background-color: {ACCENT_BLUE};
}}
QLineEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus {{
    border: 2px solid {ACCENT_BLUE};
    background-color: #ffffff;
}}

QSpinBox::up-button, QDoubleSpinBox::up-button {{
    subcontrol-origin: border;
    subcontrol-position: top right;
    width: 24px;
    height: 14px;
    background-color: #e2e8f0;
    border-left: 1px solid {BORDER_LIGHT};
    border-bottom: 1px solid {BORDER_LIGHT};
    border-top-right-radius: 6px;
}}
QSpinBox::down-button, QDoubleSpinBox::down-button {{
    subcontrol-origin: border;
    subcontrol-position: bottom right;
    width: 24px;
    height: 14px;
    background-color: #e2e8f0;
    border-left: 1px solid {BORDER_LIGHT};
    border-bottom-right-radius: 6px;
}}
QSpinBox::up-button:hover, QDoubleSpinBox::up-button:hover,
QSpinBox::down-button:hover, QDoubleSpinBox::down-button:hover {{
    background-color: {ACCENT_BLUE};
}}

/* Arrow graphics */
QSpinBox::up-arrow, QDoubleSpinBox::up-arrow {{
    image: none;
    width: 0px; height: 0px;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-bottom: 6px solid #0f172a;
}}
QSpinBox::up-button:hover QSpinBox::up-arrow, QDoubleSpinBox::up-button:hover QDoubleSpinBox::up-arrow {{
    border-bottom-color: #ffffff;
}}

QSpinBox::down-arrow, QDoubleSpinBox::down-arrow {{
    image: none;
    width: 0px; height: 0px;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 6px solid #0f172a;
}}
QSpinBox::down-button:hover QSpinBox::down-arrow, QDoubleSpinBox::down-button:hover QDoubleSpinBox::down-arrow {{
    border-top-color: #ffffff;
}}

/* Mode Cards */
QFrame#modeCard {{
    background-color: {BG_CARD_ALT};
    border: 2px solid {BORDER_LIGHT};
    border-radius: 12px;
    padding: 12px;
}}
QFrame#modeCard:hover {{
    border-color: {ACCENT_LIGHT};
    background-color: #e2e8f0;
}}
QFrame#modeCard[active="true"] {{
    border: 2px solid {ACCENT_BLUE};
    background-color: #eff6ff;
}}

/* Drop Zone Frame */
QFrame#dropZoneFrame {{
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #ffffff, stop:1 #eff6ff);
    border: 2px dashed {ACCENT_BLUE};
    border-radius: 16px;
}}
QFrame#dropZoneFrame:hover {{
    border-color: {CYAN_ACCENT};
    background-color: #e0f2fe;
}}

/* Console Terminal Log */
QTextEdit#terminalLog {{
    background-color: {BG_TERMINAL};
    color: #38bdf8;
    border: 1px solid {BORDER_LIGHT};
    border-radius: 12px;
    font-family: 'Cascadia Code', 'Consolas', 'Courier New', monospace;
    font-size: 9.5pt;
    padding: 14px;
    line-height: 1.5;
}}

/* Progress Bar */
QProgressBar {{
    background-color: #e2e8f0;
    border: 1px solid {BORDER_LIGHT};
    border-radius: 8px;
    text-align: center;
    color: {FG_PRIMARY};
    font-weight: bold;
    font-size: 9pt;
}}
QProgressBar::chunk {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 {ACCENT_BLUE}, stop:1 {CYAN_ACCENT});
    border-radius: 7px;
}}

QPushButton {{
    background-color: #ffffff;
    color: #0f172a !important;
    border: 2px solid {BORDER_LIGHT};
    border-radius: 8px;
    padding: 9px 18px;
    font-weight: bold;
    font-size: 10pt;
}}
QPushButton:hover {{
    border: 2px solid {ACCENT_BLUE};
    background-color: #f8fafc;
    color: {ACCENT_BLUE} !important;
}}
QPushButton:pressed {{
    background-color: #f1f5f9;
}}

QPushButton#btnPrimary {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #2563eb, stop:1 #1d4ed8);
    color: #ffffff !important;
    border: 2px solid #1d4ed8;
}}
QPushButton#btnPrimary:hover {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #3b82f6, stop:1 #2563eb);
    border: 2px solid #60a5fa;
    color: #ffffff !important;
}}
QPushButton#btnPrimary:pressed {{
    background: #1e40af;
    border: 2px solid #1e3a8a;
}}

QPushButton#btnSecondary {{
    background-color: #ffffff;
    color: #0f172a !important;
    border: 2px solid #cbd5e1;
}}
QPushButton#btnSecondary:hover {{
    background-color: #eff6ff;
    color: #1d4ed8 !important;
    border: 2px solid #3b82f6;
}}
QPushButton#btnSecondary:pressed {{
    background-color: #dbeafe;
}}

QPushButton:disabled,
QPushButton#btnPrimary:disabled,
QPushButton#btnSecondary:disabled {{
    background-color: #f1f5f9 !important;
    color: #64748b !important;
    border: 2px solid #e2e8f0 !important;
}}

/* Radio Buttons */
QRadioButton {{
    color: {FG_PRIMARY};
    font-weight: bold;
    font-size: 10.5pt;
    spacing: 10px;
}}
QRadioButton::indicator {{
    width: 20px;
    height: 20px;
    border-radius: 10px;
    border: 2px solid {BORDER_DARK};
    background: #ffffff;
}}
QRadioButton::indicator:checked {{
    border: 2px solid {ACCENT_BLUE};
    background: {ACCENT_BLUE};
}}
"""


def apply_drop_shadow(widget: QWidget, blur: int = 16, y_offset: int = 4, alpha: int = 35) -> None:
    shadow = QGraphicsDropShadowEffect(widget)
    shadow.setBlurRadius(blur)
    shadow.setYOffset(y_offset)
    shadow.setXOffset(0)
    shadow.setColor(QColor(0, 0, 0, alpha))
    widget.setGraphicsEffect(shadow)

class ScanWorker(QThread):
    progress_log = pyqtSignal(str, str)
    finished = pyqtSignal(object)

    def __init__(self, filepath: str, mode: AIMode, threshold: float, parent: QWidget | None = None):
        super().__init__(parent)
        self.filepath = filepath
        self.mode = mode
        self.threshold = threshold

    def run(self) -> None:
        try:
            res = AIScannerEngine.analyze(
                filepath=self.filepath,
                mode=self.mode,
                threshold=self.threshold,
                log_callback=lambda msg, lvl="info": self.progress_log.emit(msg, lvl)
            )
            self.finished.emit(res)
        except Exception as exc:
            self.progress_log.emit(f"Lỗi phân tích Engine: {exc}", "danger")

class SandboxWorker(QThread):
    progress_log = pyqtSignal(str, str)
    finished = pyqtSignal(dict)

    def __init__(self, filepath: str, timeout_sec: int, parent: QWidget | None = None):
        super().__init__(parent)
        self.filepath = filepath
        self.timeout_sec = timeout_sec

    def run(self) -> None:
        try:
            res = BHPAISandboxRunner.run_sandbox(
                filepath=self.filepath,
                timeout_sec=self.timeout_sec,
                log_callback=lambda msg, lvl="info": self.progress_log.emit(msg, lvl)
            )
            self.finished.emit(res)
        except Exception as exc:
            self.progress_log.emit(f"Lỗi thực thi Sandbox Container: {exc}", "danger")


class RealtimeGuardWorkerThread(QThread):
    """Background worker thread for watching directories & real-time file scanning.
    Ultra-lightweight event & poll cycle to avoid CPU spikes.
    """
    threat_detected = pyqtSignal(dict)
    guard_status = pyqtSignal(str)

    def __init__(self, engine: RealtimeGuardEngine, parent: QWidget | None = None):
        super().__init__(parent)
        self.engine = engine
        self._running = True
        self._watcher = QFileSystemWatcher(self)
        self._watcher.directoryChanged.connect(self._on_dir_changed)
        self._watcher.fileChanged.connect(self._on_file_changed)
        self._pending_files: set[str] = set()
        self._seen_files: dict[str, tuple[float, int]] = {}

    def update_watched_dirs(self):
        existing = set(self._watcher.directories())
        for path in self.engine.watched_paths:
            if os.path.exists(path) and path not in existing:
                try:
                    self._watcher.addPath(path)
                except Exception:
                    pass

    def _on_dir_changed(self, path: str):
        if self.engine.enabled:
            self._scan_directory(path)

    def _on_file_changed(self, path: str):
        if self.engine.enabled and os.path.exists(path):
            self._pending_files.add(path)

    def _scan_directory(self, dir_path: str):
        if not self.engine.enabled:
            return
        try:
            for entry in os.scandir(dir_path):
                if entry.is_file():
                    name_lower = entry.name.lower()
                    if any(name_lower.endswith(ext) for ext in RealtimeGuardEngine.TEMP_EXTENSIONS):
                        continue
                    ext = Path(entry.name).suffix.lower()
                    if ext in RealtimeGuardEngine.TARGET_PE_EXTENSIONS:
                        try:
                            stat = entry.stat()
                            key = (stat.st_mtime, stat.st_size)
                            if self._seen_files.get(entry.path) == key:
                                continue
                            self._seen_files[entry.path] = key
                            self._pending_files.add(entry.path)
                        except Exception:
                            pass
        except Exception:
            pass

    def run(self) -> None:
        self.update_watched_dirs()
        for watched in list(self.engine.watched_paths):
            self._scan_directory(watched)

        while self._running:
            self.update_watched_dirs()
            if self.engine.enabled:
                for watched in list(self.engine.watched_paths):
                    self._scan_directory(watched)

                to_process = list(self._pending_files)
                self._pending_files.clear()

                for filepath in to_process:
                    if not self._running or not self.engine.enabled:
                        break
                    if os.path.exists(filepath):
                        res = self.engine.scan_file_quick(filepath)
                        if res is not None:
                            sha256 = RealtimeGuardEngine.calculate_sha256(filepath)
                            threat_info = {
                                "filepath": filepath,
                                "filename": os.path.basename(filepath),
                                "scan_result": res,
                                "sha256": sha256,
                                "threat_score": res.threat_score,
                                "risk_label": res.risk_label,
                                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            }
                            self.threat_detected.emit(threat_info)

            self.msleep(2000)

    def stop(self):
        self._running = False
        self.wait(1000)


class RealtimeThreatDialog(QDialog):
    """Modern safety alert modal popped up when Real-time Guard catches a threat.
    STRICT USER CONSENT REQUIRED: Absolutely NO file deletion without user explicit click!
    """
    ACTION_QUARANTINE = 1
    ACTION_DELETE = 2
    ACTION_SANDBOX = 3
    ACTION_TRUST = 4
    ACTION_IGNORE = 0

    def __init__(self, threat_info: dict, parent: QWidget | None = None):
        super().__init__(parent)
        self.threat_info = threat_info
        self.selected_action = self.ACTION_IGNORE
        self.setWindowTitle("⚠️ BHPAI REAL-TIME PROTECTION - PHÁT HIỆN MÃ ĐỘC!")
        self.setFixedWidth(540)
        self.setWindowFlags(self.windowFlags() | Qt.WindowType.WindowStaysOnTopHint)
        self.setStyleSheet(f"background-color: {BG_MAIN}; color: {FG_PRIMARY};")
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        banner = QFrame()
        banner.setStyleSheet(f"background-color: #fef2f2; border: 2px solid {ROSE_RED}; border-radius: 10px; padding: 12px;")
        b_layout = QHBoxLayout(banner)
        b_layout.setContentsMargins(12, 8, 12, 8)

        warn_icon = QLabel("⚠️")
        warn_icon.setFont(get_font("Segoe UI", 24))
        b_layout.addWidget(warn_icon)

        b_text = QVBoxLayout()
        b_title = QLabel("CẢNH BÁO MÃ ĐỘC THỜI GIAN THỰC")
        b_title.setFont(get_font("Segoe UI", 12, bold=True))
        b_title.setStyleSheet(f"color: {ROSE_RED};")
        b_desc = QLabel("Phát hiện tệp tin nghi vấn có hành vi hoặc cấu trúc độc hại.")
        b_desc.setFont(get_font("Segoe UI", 9))
        b_desc.setStyleSheet(f"color: {FG_SECONDARY};")
        b_text.addWidget(b_title)
        b_text.addWidget(b_desc)
        b_layout.addLayout(b_text)
        layout.addWidget(banner)

        info_card = QFrame()
        info_card.setObjectName("cardFrame")
        ic_layout = QVBoxLayout(info_card)
        ic_layout.setContentsMargins(16, 14, 16, 14)
        ic_layout.setSpacing(8)

        fn = self.threat_info.get("filename", "N/A")
        fp = self.threat_info.get("filepath", "N/A")
        score = self.threat_info.get("threat_score", 0)
        label = self.threat_info.get("risk_label", "SUSPICIOUS")
        sha = self.threat_info.get("sha256", "N/A")

        row1 = QLabel(f"<b>Tên tệp:</b> {fn}")
        row1.setFont(get_font("Segoe UI", 10))
        row2 = QLabel(f"<b>Đường dẫn:</b> {fp}")
        row2.setFont(get_font("Segoe UI", 9))
        row2.setWordWrap(True)
        row2.setStyleSheet(f"color: {FG_MUTED};")

        score_lbl = QLabel(f"<b>Điểm Nguy Cơ AI:</b> <span style='color:{ROSE_RED}; font-size:12pt; font-weight:bold;'>{score}% ({label})</span>")
        score_lbl.setFont(get_font("Segoe UI", 10))

        sha_lbl = QLabel(f"<b>SHA256:</b> {sha[:16]}...{sha[-8:]}" if len(sha) >= 24 else f"<b>SHA256:</b> {sha}")
        sha_lbl.setFont(get_font("Segoe UI", 8.5))
        sha_lbl.setStyleSheet(f"color: {FG_DIM};")

        ic_layout.addWidget(row1)
        ic_layout.addWidget(row2)
        ic_layout.addWidget(score_lbl)
        ic_layout.addWidget(sha_lbl)

        layout.addWidget(info_card)

        safety_note = QLabel("🔒 <b>Chính sách bảo vệ:</b> BHPAI KHÔNG tự động xóa file nếu chưa được sự đồng ý của bạn.")
        safety_note.setFont(get_font("Segoe UI", 8.5))
        safety_note.setStyleSheet(f"color: {EMERALD_GREEN}; background: #ecfdf5; border: 1px solid #a7f3d0; border-radius: 6px; padding: 6px 10px;")
        layout.addWidget(safety_note)

        btn_layout = QGridLayout()
        btn_layout.setSpacing(10)

        btn_quarantine = QPushButton("🛡️ Cách ly File")
        btn_quarantine.setFont(get_font("Segoe UI", 9.5, bold=True))
        btn_quarantine.setStyleSheet(f"background-color: {ACCENT_BLUE}; color: white; border-radius: 8px; padding: 10px;")
        btn_quarantine.clicked.connect(self._on_quarantine)

        btn_delete = QPushButton("🗑️ Xóa Vĩnh Viễn")
        btn_delete.setFont(get_font("Segoe UI", 9.5, bold=True))
        btn_delete.setStyleSheet(f"background-color: {ROSE_RED}; color: white; border-radius: 8px; padding: 10px;")
        btn_delete.clicked.connect(self._on_delete)

        btn_sandbox = QPushButton("🔍 Mở trong Sandbox")
        btn_sandbox.setFont(get_font("Segoe UI", 9.5, bold=True))
        btn_sandbox.setStyleSheet(f"background-color: {CYAN_ACCENT}; color: white; border-radius: 8px; padding: 10px;")
        btn_sandbox.clicked.connect(self._on_sandbox)

        btn_trust = QPushButton("✅ Cho Phép & Tin Tưởng")
        btn_trust.setFont(get_font("Segoe UI", 9.5, bold=True))
        btn_trust.setStyleSheet("background-color: #f1f5f9; color: #334155; border: 1px solid #cbd5e1; border-radius: 8px; padding: 10px;")
        btn_trust.clicked.connect(self._on_trust)

        btn_layout.addWidget(btn_quarantine, 0, 0)
        btn_layout.addWidget(btn_delete, 0, 1)
        btn_layout.addWidget(btn_sandbox, 1, 0)
        btn_layout.addWidget(btn_trust, 1, 1)

        layout.addLayout(btn_layout)

    def _on_quarantine(self):
        self.selected_action = self.ACTION_QUARANTINE
        self.accept()

    def _on_delete(self):
        reply = QMessageBox.question(
            self,
            "Xác nhận xóa tệp tin",
            f"Bạn có chắc chắn muốn XÓA VĨNH VIỄN tệp tin này?\n\n{self.threat_info.get('filepath')}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.selected_action = self.ACTION_DELETE
            self.accept()

    def _on_sandbox(self):
        self.selected_action = self.ACTION_SANDBOX
        self.accept()

    def _on_trust(self):
        self.selected_action = self.ACTION_TRUST
        self.accept()


class Card(QFrame):
    def __init__(self, parent: QWidget | None = None, enable_shadow: bool = True):
        super().__init__(parent)
        self.setObjectName("cardFrame")
        if enable_shadow:
            apply_drop_shadow(self, blur=14, y_offset=3, alpha=30)

class StatusPill(QLabel):
    def __init__(self, text: str, bg_color: str, fg_color: str = "#ffffff", parent: QWidget | None = None):
        super().__init__(text, parent)
        self.setFont(get_font("Segoe UI", 8.5, bold=True))
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setStyleSheet(
            f"background-color: {bg_color}; color: {fg_color}; "
            f"border-radius: 6px; padding: 4px 10px; font-weight: bold;"
        )

class RadialThreatGauge(QWidget):
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setFixedSize(180, 180)
        self._score = 0
        self._risk_label = "CHƯA QUÉT"
        self._risk_color = QColor(FG_MUTED)

    def set_result(self, score: int, label: str, color_hex: str) -> None:
        self._score = max(0, min(100, score))
        self._risk_label = label.upper()
        self._risk_color = QColor(color_hex)
        self.update()

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        rect = QRectF(12, 12, 156, 156)

        pen_bg = QPen(QColor("#e2e8f0"), 14, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap)
        painter.setPen(pen_bg)
        painter.drawArc(rect, -210 * 16, 240 * 16)

        if self._score > 0:
            pen_fg = QPen(self._risk_color, 14, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap)
            painter.setPen(pen_fg)
            span_angle = int(-240 * 16 * (self._score / 100.0))
            painter.drawArc(rect, 210 * 16, span_angle)

        painter.setFont(get_font("Segoe UI", 24, bold=True))
        painter.setPen(QPen(QColor(FG_PRIMARY)))
        score_text = f"{self._score}%"
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, score_text)

        painter.setFont(get_font("Segoe UI", 8.5, bold=True))
        painter.setPen(QPen(self._risk_color))
        sub_rect = QRectF(rect.x(), rect.y() + 104, rect.width(), 30)
        painter.drawText(sub_rect, Qt.AlignmentFlag.AlignCenter, self._risk_label)

class EntropyVisualizer(QWidget):
    """Horizontal rating bar for PE entropy values (0.0 to 8.0)."""
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setFixedHeight(14)
        self._entropy = 0.0

    def set_entropy(self, entropy: float) -> None:
        self._entropy = max(0.0, min(8.0, entropy))
        self.update()

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w = self.width()
        h = self.height()

        painter.setBrush(QBrush(QColor("#e2e8f0")))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawRoundedRect(0, 0, w, h, 7, 7)

        fill_w = int(w * (self._entropy / 8.0))
        if fill_w > 0:
            if self._entropy > 7.2:
                bar_color = QColor(ROSE_RED)
            elif self._entropy > 6.5:
                bar_color = QColor(AMBER_WARN)
            else:
                bar_color = QColor(EMERALD_GREEN)

            painter.setBrush(QBrush(bar_color))
            painter.drawRoundedRect(0, 0, fill_w, h, 7, 7)

class MetricCardWidget(Card):
    def __init__(self, title: str, value: str, subtext: str = "", accent_color: str = ACCENT_BLUE, parent: QWidget | None = None):
        super().__init__(parent)
        self.setMinimumHeight(105)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 14, 18, 14)
        layout.setSpacing(4)

        header_row = QHBoxLayout()
        title_lbl = QLabel(title)
        title_lbl.setFont(get_font("Segoe UI", 8.5, bold=True))
        title_lbl.setStyleSheet(f"color: {FG_MUTED}; text-transform: uppercase; letter-spacing: 0.5px;")
        header_row.addWidget(title_lbl)
        header_row.addStretch()

        accent_dot = QWidget()
        accent_dot.setFixedSize(10, 10)
        accent_dot.setStyleSheet(f"background-color: {accent_color}; border-radius: 5px;")
        header_row.addWidget(accent_dot)
        layout.addLayout(header_row)

        self.val_lbl = QLabel(value)
        self.val_lbl.setFont(get_font("Segoe UI", 18, bold=True))
        self.val_lbl.setStyleSheet(f"color: {FG_PRIMARY};")
        layout.addWidget(self.val_lbl)

        if subtext:
            sub_lbl = QLabel(subtext)
            sub_lbl.setFont(get_font("Segoe UI", 8.5))
            sub_lbl.setStyleSheet(f"color: {CYAN_ACCENT}; font-weight: bold;")
            layout.addWidget(sub_lbl)

class PageHeader(QWidget):
    def __init__(self, title: str, subtitle: str, parent: QWidget | None = None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 2, 0, 10)
        layout.setSpacing(4)

        top_row = QHBoxLayout()
        title_lbl = QLabel(title)
        title_lbl.setFont(get_font("Segoe UI", 18, bold=True))
        title_lbl.setStyleSheet(f"color: {FG_PRIMARY};")
        top_row.addWidget(title_lbl)

        top_row.addStretch()

        badge = QLabel(f"EXCLUSIVE ENGINE • {APP_VERSION}")
        badge.setFont(get_font("Segoe UI", 8.5, bold=True))
        badge.setStyleSheet(
            f"color: {ACCENT_BLUE}; background-color: #dbeafe; "
            f"border: 1px solid #bfdbfe; border-radius: 6px; padding: 4px 12px;"
        )
        top_row.addWidget(badge)
        layout.addLayout(top_row)

        sub_lbl = QLabel(subtitle)
        sub_lbl.setFont(get_font("Segoe UI", 9.5))
        sub_lbl.setStyleSheet(f"color: {FG_MUTED}; font-weight: 600;")
        layout.addWidget(sub_lbl)

class DropZoneFrame(QFrame):
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("dropZoneFrame")
        self.setAcceptDrops(True)
        self.setMinimumHeight(210)
        self.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self._on_path_selected = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(10)

        pm = load_logo_scaled(150)
        if pm:
            self.logo_lbl = QLabel()
            self.logo_lbl.setPixmap(pm)
            self.logo_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(self.logo_lbl)

        self.main_lbl = QLabel("DRAG & DROP PE FILES (.EXE) HERE")
        self.main_lbl.setFont(get_font("Segoe UI", 12, bold=True))
        self.main_lbl.setStyleSheet(f"color: {FG_PRIMARY}; letter-spacing: 0.5px;")
        self.main_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.main_lbl)

        self.sub_lbl = QLabel("or double-click this area to select a file from your computer")
        self.sub_lbl.setFont(get_font("Segoe UI", 9.5))
        self.sub_lbl.setStyleSheet(f"color: {FG_MUTED}; font-weight: 600;")
        self.sub_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.sub_lbl)

        btn_browse = QPushButton("Browse Local File")
        btn_browse.setObjectName("btnSecondary")
        btn_browse.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        btn_browse.clicked.connect(self._browse_file)
        layout.addWidget(btn_browse, alignment=Qt.AlignmentFlag.AlignCenter)

    def set_on_path_selected(self, callback) -> None:
        self._on_path_selected = callback

    def mouseDoubleClickEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self._browse_file()
        super().mouseDoubleClickEvent(event)

    def dragEnterEvent(self, event) -> None:
        if event.mimeData() and event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dragMoveEvent(self, event) -> None:
        if event.mimeData() and event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event) -> None:
        if event.mimeData() and event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            if urls:
                path = urls[0].toLocalFile()
                if path:
                    self.set_file_path(path)
                    event.acceptProposedAction()

    def _browse_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select PE executable to inspect",
            "",
            "Executable Files (*.exe);;All Files (*)",
        )
        if path:
            self.set_file_path(path)

    def set_file_path(self, path: str) -> None:
        self.main_lbl.setText(f"📁 SELECTED FILE: {os.path.basename(path)}")
        self.main_lbl.setStyleSheet(f"color: {EMERALD_GREEN}; font-weight: bold;")
        self.sub_lbl.setText(path)
        if self._on_path_selected:
            self._on_path_selected(path)


class NavButton(QFrame):
    def __init__(self, label: str, subtitle: str, on_click, parent: QWidget | None = None):
        super().__init__(parent)
        self._active = False
        self._on_click = on_click
        self.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))

        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self._active_bar = QFrame()
        self._active_bar.setFixedWidth(5)
        self._active_bar.setStyleSheet("background-color: transparent;")
        root.addWidget(self._active_bar)

        content = QVBoxLayout()
        content.setContentsMargins(18, 12, 18, 12)
        content.setSpacing(2)

        self._title_lbl = QLabel(label)
        self._title_lbl.setFont(get_font("Segoe UI", 10.5, bold=True))
        content.addWidget(self._title_lbl)

        self._sub_lbl = QLabel(subtitle)
        self._sub_lbl.setFont(get_font("Segoe UI", 8.5))
        content.addWidget(self._sub_lbl)

        root.addLayout(content, stretch=1)
        self._render_state()

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton and self._on_click:
            self._on_click()
        super().mousePressEvent(event)

    def set_active(self, active: bool) -> None:
        self._active = active
        self._render_state()

    def _render_state(self) -> None:
        if self._active:
            self.setStyleSheet(
                f"background-color: #eff6ff; border-radius: 10px; margin: 3px 10px; border: 1px solid #bfdbfe;"
            )
            self._active_bar.setStyleSheet(
                f"background-color: {ACCENT_BLUE}; border-radius: 3px;"
            )
            self._title_lbl.setStyleSheet(f"color: {ACCENT_BLUE};")
            self._sub_lbl.setStyleSheet(f"color: {CYAN_ACCENT}; font-weight: bold;")
        else:
            self.setStyleSheet(
                "background-color: transparent; border-radius: 10px; margin: 3px 10px; border: 1px solid transparent;"
            )
            self._active_bar.setStyleSheet("background-color: transparent;")
            self._title_lbl.setStyleSheet(f"color: {FG_PRIMARY};")
            self._sub_lbl.setStyleSheet(f"color: {FG_MUTED};")

class DashboardPage(QWidget):
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 20, 28, 28)
        layout.setSpacing(18)

        layout.addWidget(PageHeader(
            "Security Operations Center (SOC)",
            "Trung tâm giám sát tổng quan hệ thống nhận diện & phân tích mã độc BHPAI V1.1",
        ))

        hero_card = Card(enable_shadow=True)
        hero_layout = QHBoxLayout(hero_card)
        hero_layout.setContentsMargins(24, 20, 24, 20)
        hero_layout.setSpacing(24)

        pm = load_logo_scaled(170)
        if pm:
            hero_logo = QLabel()
            hero_logo.setPixmap(pm)
            hero_layout.addWidget(hero_logo)

        hero_text_layout = QVBoxLayout()
        hero_text_layout.setSpacing(6)

        hero_title = QLabel("BHPAI Security Suite — AI Threat Engine Active")
        hero_title.setFont(get_font("Segoe UI", 15, bold=True))
        hero_title.setStyleSheet(f"color: {ACCENT_BLUE};")
        hero_text_layout.addWidget(hero_title)

        hero_desc = QLabel(
            "The system automatically extracts static PE metadata combined with a LightGBM machine learning model "
            "và môi trường Sandbox BHPAISandbox.exe để bảo vệ toàn diện hệ thống Windows."
        )
        hero_desc.setFont(get_font("Segoe UI", 9.5))
        hero_desc.setStyleSheet(f"color: {FG_SECONDARY};")
        hero_desc.setWordWrap(True)
        hero_text_layout.addWidget(hero_desc)

        hero_layout.addLayout(hero_text_layout, stretch=1)

        btn_quick_scan = QPushButton("Quét Tệp PE Ngay")
        btn_quick_scan.setObjectName("btnSecondary")
        btn_quick_scan.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        btn_quick_scan.clicked.connect(self._go_to_scan)
        hero_layout.addWidget(btn_quick_scan, alignment=Qt.AlignmentFlag.AlignCenter)

        layout.addWidget(hero_card)

        grid = QGridLayout()
        grid.setSpacing(14)
        self.cards: dict[str, MetricCardWidget] = {}

        metrics = [
            ("Total PE Samples Analyzed", "1,675", "Mẫu kiểm thử tích lũy", ACCENT_BLUE),
            ("Malware Neutralized", "1,652", "Tỷ lệ phát hiện chính xác", ROSE_RED),
            ("AI Model Accuracy", "98.63%", "LightGBM + TF-IDF", EMERALD_GREEN),
            ("Active AI Mode", "Only Static", "Chuyển đổi linh hoạt", ACCENT_LIGHT),
            ("Sandbox Engine", "BHPAISandbox.exe", "Container cách ly", AMBER_WARN),
            ("Avg Static Scan Speed", "0.38s", "Tối ưu hóa siêu tốc", CYAN_ACCENT),
        ]

        for idx, (title, val, sub, color) in enumerate(metrics):
            card = MetricCardWidget(title, val, sub, accent_color=color)
            grid.addWidget(card, idx // 3, idx % 3)
            self.cards[title] = card

        grid_wrap = QWidget()
        grid_wrap.setLayout(grid)
        layout.addWidget(grid_wrap)

        rt_card = Card(enable_shadow=True)
        rt_l = QHBoxLayout(rt_card)
        rt_l.setContentsMargins(22, 18, 22, 18)
        rt_l.setSpacing(20)

        rt_icon = QLabel("🛡️")
        rt_icon.setFont(get_font("Segoe UI", 26))
        rt_l.addWidget(rt_icon)

        rt_text_layout = QVBoxLayout()
        rt_text_layout.setSpacing(4)
        self.rt_status_title = QLabel("BẢO VỆ THỜI GIAN THỰC (REAL-TIME GUARD): ĐANG BẬT")
        self.rt_status_title.setFont(get_font("Segoe UI", 11.5, bold=True))
        self.rt_status_title.setStyleSheet(f"color: {EMERALD_GREEN};")

        self.rt_status_desc = QLabel("Tự động giám sát Downloads & Desktop. Cảnh báo ngay khi có file mã độc mới mà KHÔNG tự ý xóa file.")
        self.rt_status_desc.setFont(get_font("Segoe UI", 9))
        self.rt_status_desc.setStyleSheet(f"color: {FG_SECONDARY};")

        self.rt_stats_lbl = QLabel("Giám sát: Downloads, Desktop | Khay hệ thống: Active | Chạy dưới nền: Sẵn sàng")
        self.rt_stats_lbl.setFont(get_font("Segoe UI", 8.5, bold=True))
        self.rt_stats_lbl.setStyleSheet(f"color: {ACCENT_BLUE};")

        rt_text_layout.addWidget(self.rt_status_title)
        rt_text_layout.addWidget(self.rt_status_desc)
        rt_text_layout.addWidget(self.rt_stats_lbl)
        rt_l.addLayout(rt_text_layout, stretch=1)

        self.btn_toggle_rt = QPushButton("Tắt Bảo Vệ")
        self.btn_toggle_rt.setObjectName("btnSecondary")
        self.btn_toggle_rt.setStyleSheet(f"color: {ROSE_RED} !important; border-color: {ROSE_RED};")
        self.btn_toggle_rt.clicked.connect(self._toggle_realtime_guard)
        rt_l.addWidget(self.btn_toggle_rt, alignment=Qt.AlignmentFlag.AlignCenter)

        layout.addWidget(rt_card)

        sys_card = Card()
        sys_l = QVBoxLayout(sys_card)
        sys_l.setContentsMargins(22, 18, 22, 18)
        sys_l.setSpacing(12)

        sys_title_row = QHBoxLayout()
        sys_title = QLabel("System Hardware Metrics & Monitor")
        sys_title.setFont(get_font("Segoe UI", 11, bold=True))
        sys_title.setStyleSheet(f"color: {FG_PRIMARY};")
        sys_title_row.addWidget(sys_title)
        sys_title_row.addStretch()

        self.live_badge = StatusPill("● LIVE MONITORING", "#dcfce7", EMERALD_GREEN)
        sys_title_row.addWidget(self.live_badge)
        sys_l.addLayout(sys_title_row)

        sys_grid = QGridLayout()
        sys_grid.setSpacing(14)

        sys_grid.addWidget(QLabel("CPU Utilization:"), 0, 0)
        self.cpu_bar = QProgressBar()
        self.cpu_bar.setRange(0, 100)
        sys_grid.addWidget(self.cpu_bar, 0, 1)

        self.cpu_val_lbl = QLabel("0%")
        self.cpu_val_lbl.setFont(get_font("Segoe UI", 9.5, bold=True))
        self.cpu_val_lbl.setStyleSheet(f"color: {ACCENT_BLUE};")
        sys_grid.addWidget(self.cpu_val_lbl, 0, 2)

        sys_grid.addWidget(QLabel("RAM Memory Usage:"), 1, 0)
        self.ram_bar = QProgressBar()
        self.ram_bar.setRange(0, 100)
        sys_grid.addWidget(self.ram_bar, 1, 1)

        self.ram_val_lbl = QLabel("0 GB / 0 GB")
        self.ram_val_lbl.setFont(get_font("Segoe UI", 9.5, bold=True))
        self.ram_val_lbl.setStyleSheet(f"color: {CYAN_ACCENT};")
        sys_grid.addWidget(self.ram_val_lbl, 1, 2)

        sys_l.addLayout(sys_grid)

        self.proc_lbl = QLabel("Active System Processes: Calculating...")
        self.proc_lbl.setFont(get_font("Segoe UI", 9.5))
        self.proc_lbl.setStyleSheet(f"color: {FG_MUTED}; padding-top: 2px;")
        sys_l.addWidget(self.proc_lbl)

        layout.addWidget(sys_card)
        layout.addStretch()

        self.timer = QTimer(self)
        self.timer.timeout.connect(self._refresh_hardware_stats)
        self.timer.start(2000)
        self._refresh_hardware_stats()

    def _go_to_scan(self) -> None:
        if self.window() and hasattr(self.window(), "_switch"):
            self.window()._switch("Scan")

    def _refresh_hardware_stats(self) -> None:
        stats = SystemMonitor.get_stats()
        cpu = stats["cpu_percent"]
        ram = stats["ram_percent"]
        ram_used = stats["ram_used_gb"]
        ram_total = stats["ram_total_gb"]
        procs = stats["processes_count"]

        self.cpu_bar.setValue(int(cpu))
        self.cpu_val_lbl.setText(f"{cpu}%")

        self.ram_bar.setValue(int(ram))
        self.ram_val_lbl.setText(f"{ram}% ({ram_used} / {ram_total} GB)")

        self.proc_lbl.setText(f"Active System Processes Monitored: {procs}")

    def update_active_mode_display(self, mode_str: str) -> None:
        if "Active AI Mode" in self.cards:
            self.cards["Active AI Mode"].val_lbl.setText(mode_str)

    def _toggle_realtime_guard(self) -> None:
        win = self.window()
        if win and hasattr(win, "_toggle_realtime_from_tray"):
            win._toggle_realtime_from_tray()

    def update_realtime_guard_ui(self, enabled: bool, scanned_count: int = 0, threat_count: int = 0) -> None:
        if enabled:
            self.rt_status_title.setText("BẢO VỆ THỜI GIAN THỰC (REAL-TIME GUARD): ĐANG BẬT")
            self.rt_status_title.setStyleSheet(f"color: {EMERALD_GREEN};")
            self.btn_toggle_rt.setText("Tắt Bảo Vệ")
            self.btn_toggle_rt.setStyleSheet(f"color: {ROSE_RED} !important; border-color: {ROSE_RED};")
            self.rt_stats_lbl.setText(f"Đã quét: {scanned_count} file | Đã phát hiện: {threat_count} nguy cơ | Khay hệ thống: Active")
        else:
            self.rt_status_title.setText("BẢO VỆ THỜI GIAN THỰC (REAL-TIME GUARD): ĐÃ TẮT")
            self.rt_status_title.setStyleSheet(f"color: {ROSE_RED};")
            self.btn_toggle_rt.setText("Bật Bảo Vệ")
            self.btn_toggle_rt.setStyleSheet(f"color: {EMERALD_GREEN} !important; border-color: {EMERALD_GREEN};")
            self.rt_stats_lbl.setText("Bảo vệ thời gian thực tạm dừng. Nhấn nút để bật lại.")


class ScanPage(QWidget):
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self._selected_path: str | None = None
        self._current_mode: AIMode = AIMode.ONLY_STATIC

        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 20, 28, 28)
        layout.setSpacing(16)

        layout.addWidget(PageHeader(
            "PE Analysis & AI Scan Engine (V1.1)",
            "Select an AI analysis mode and choose a Windows executable (.exe) to inspect.",
        ))

        mode_box = Card()
        m_layout = QVBoxLayout(mode_box)
        m_layout.setContentsMargins(18, 16, 18, 16)
        m_layout.setSpacing(10)

        m_title = QLabel("AI Analysis Mode Configuration (BHPAI V1.1):")
        m_title.setFont(get_font("Segoe UI", 10.5, bold=True))
        m_title.setStyleSheet(f"color: {FG_PRIMARY};")
        m_layout.addWidget(m_title)

        cards_row = QHBoxLayout()
        cards_row.setSpacing(14)

        self.mode_group = QButtonGroup(self)

        self.mode1_frame = QFrame()
        self.mode1_frame.setObjectName("modeCard")
        self.mode1_frame.setProperty("active", "true")
        self.mode1_frame.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        m1_l = QVBoxLayout(self.mode1_frame)
        self.radio_mode1 = QRadioButton("Mode 1: Only Static (Static AI Analysis)")
        self.radio_mode1.setChecked(True)
        self.mode_group.addButton(self.radio_mode1, 1)
        self.radio_mode1.toggled.connect(self._on_mode_toggled)
        m1_l.addWidget(self.radio_mode1)

        m1_desc = QLabel("Optimized for speed. Inspects PE structure, entropy, API n-grams, and predicts via LightGBM .pkl.")
        m1_desc.setFont(get_font("Segoe UI", 9))
        m1_desc.setStyleSheet(f"color: {FG_MUTED};")
        m1_desc.setWordWrap(True)
        m1_l.addWidget(m1_desc)
        cards_row.addWidget(self.mode1_frame, stretch=1)

        self.mode2_frame = QFrame()
        self.mode2_frame.setObjectName("modeCard")
        self.mode2_frame.setProperty("active", "false")
        self.mode2_frame.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        m2_l = QVBoxLayout(self.mode2_frame)
        self.radio_mode2 = QRadioButton("Mode 2: Static + Dynamic (Combined Static & Dynamic)")
        self.mode_group.addButton(self.radio_mode2, 2)
        self.radio_mode2.toggled.connect(self._on_mode_toggled)
        m2_l.addWidget(self.radio_mode2)

        m2_desc = QLabel("Most comprehensive. Static analysis combined with BHPAISandbox.exe runtime risk measurement.")
        m2_desc.setFont(get_font("Segoe UI", 9))
        m2_desc.setStyleSheet(f"color: {FG_MUTED};")
        m2_desc.setWordWrap(True)
        m2_l.addWidget(m2_desc)
        cards_row.addWidget(self.mode2_frame, stretch=1)

        m_layout.addLayout(cards_row)
        layout.addWidget(mode_box)

        self.drop_zone = DropZoneFrame(self)
        self.drop_zone.set_on_path_selected(self._on_file_selected)
        layout.addWidget(self.drop_zone)

        ctrl_card = Card()
        c_layout = QHBoxLayout(ctrl_card)
        c_layout.setContentsMargins(18, 12, 18, 12)
        c_layout.setSpacing(14)

        c_layout.addWidget(QLabel("Ngưỡng cảnh báo Threat (Threshold):"))
        self.spin_thresh = QDoubleSpinBox()
        self.spin_thresh.setRange(0.05, 0.95)
        self.spin_thresh.setSingleStep(0.01)
        self.spin_thresh.setValue(0.49)
        c_layout.addWidget(self.spin_thresh)

        self.lbl_selected_file = QLabel("No PE file selected.")
        self.lbl_selected_file.setStyleSheet(f"color: {FG_MUTED}; font-style: italic;")
        c_layout.addWidget(self.lbl_selected_file, stretch=1)

        self.btn_run_scan = QPushButton("START AI SCAN")
        self.btn_run_scan.setObjectName("btnSecondary")
        self.btn_run_scan.setEnabled(False)
        self.btn_run_scan.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_run_scan.clicked.connect(self._execute_scan)
        c_layout.addWidget(self.btn_run_scan)

        layout.addWidget(ctrl_card)

        output_grid = QHBoxLayout()
        output_grid = QHBoxLayout()
        output_grid.setSpacing(14)

        gauge_card = Card()
        g_layout = QVBoxLayout(gauge_card)
        g_layout.setContentsMargins(18, 16, 18, 16)
        g_layout.setSpacing(10)
        g_layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        g_title_row = QHBoxLayout()
        g_title = QLabel("AI Threat Breakdown")
        g_title.setFont(get_font("Segoe UI", 11, bold=True))
        g_title.setStyleSheet(f"color: {FG_PRIMARY};")
        g_title_row.addWidget(g_title)
        g_title_row.addStretch()

        self.lbl_auto_badge = StatusPill("READY", "#f1f5f9", FG_MUTED)
        g_title_row.addWidget(self.lbl_auto_badge)
        g_layout.addLayout(g_title_row)

        self.threat_gauge = RadialThreatGauge()
        g_layout.addWidget(self.threat_gauge, alignment=Qt.AlignmentFlag.AlignCenter)

        scores_grid = QGridLayout()
        scores_grid.setVerticalSpacing(6)

        lbl_s_title = QLabel("Static Risk (Ensemble):")
        lbl_s_title.setFont(get_font("Segoe UI", 9, bold=True))
        lbl_s_title.setStyleSheet(f"color: {FG_SECONDARY};")
        scores_grid.addWidget(lbl_s_title, 0, 0)

        self.lbl_static_score = QLabel("0%")
        self.lbl_static_score.setFont(get_font("Segoe UI", 9.5, bold=True))
        self.lbl_static_score.setStyleSheet(f"color: {ACCENT_BLUE};")
        scores_grid.addWidget(self.lbl_static_score, 0, 1)

        lbl_d_title = QLabel("Behavior Risk (0.3x):")
        lbl_d_title.setFont(get_font("Segoe UI", 9, bold=True))
        lbl_d_title.setStyleSheet(f"color: {FG_SECONDARY};")
        scores_grid.addWidget(lbl_d_title, 1, 0)

        self.lbl_dynamic_score = QLabel("N/A")
        self.lbl_dynamic_score.setFont(get_font("Segoe UI", 9.5, bold=True))
        self.lbl_dynamic_score.setStyleSheet(f"color: {AMBER_WARN};")
        scores_grid.addWidget(self.lbl_dynamic_score, 1, 1)

        lbl_delta_title = QLabel("Confidence Delta (Δ):")
        lbl_delta_title.setFont(get_font("Segoe UI", 9, bold=True))
        lbl_delta_title.setStyleSheet(f"color: {FG_SECONDARY};")
        scores_grid.addWidget(lbl_delta_title, 2, 0)

        self.lbl_confidence_delta = QLabel("0.00")
        self.lbl_confidence_delta.setFont(get_font("Segoe UI", 9.5, bold=True))
        self.lbl_confidence_delta.setStyleSheet(f"color: {CYAN_ACCENT};")
        scores_grid.addWidget(self.lbl_confidence_delta, 2, 1)

        g_layout.addLayout(scores_grid)
        g_layout.addStretch()
        output_grid.addWidget(gauge_card, stretch=2)

        explain_card = Card()
        ex_layout = QVBoxLayout(explain_card)
        ex_layout.setContentsMargins(18, 16, 18, 16)
        ex_layout.setSpacing(10)

        ex_title = QLabel("AI Explanation & Verification")
        ex_title.setFont(get_font("Segoe UI", 11, bold=True))
        ex_title.setStyleSheet(f"color: {FG_PRIMARY};")
        ex_layout.addWidget(ex_title)

        lbl_shap_head = QLabel("Static AI Suspicion Reasons (SHAP):")
        lbl_shap_head.setFont(get_font("Segoe UI", 8.5, bold=True))
        lbl_shap_head.setStyleSheet(f"color: {CYAN_ACCENT}; text-transform: uppercase;")
        ex_layout.addWidget(lbl_shap_head)

        self.txt_shap_reasons = QTextEdit()
        self.txt_shap_reasons.setReadOnly(True)
        self.txt_shap_reasons.setFixedHeight(70)
        self.txt_shap_reasons.setStyleSheet(
            f"background-color: {BG_MAIN}; border: 1px solid {BORDER_LIGHT}; border-radius: 6px; font-size: 8.5pt; font-family: 'Segoe UI';"
        )
        self.txt_shap_reasons.setPlaceholderText("No SHAP analysis results available yet...")
        ex_layout.addWidget(self.txt_shap_reasons)

        lbl_ver_head = QLabel("Sandbox Verification (SHAP Cross-Ref):")
        lbl_ver_head.setFont(get_font("Segoe UI", 8.5, bold=True))
        lbl_ver_head.setStyleSheet(f"color: {ACCENT_BLUE}; text-transform: uppercase;")
        ex_layout.addWidget(lbl_ver_head)

        self.txt_shap_verify = QTextEdit()
        self.txt_shap_verify.setReadOnly(True)
        self.txt_shap_verify.setFixedHeight(70)
        self.txt_shap_verify.setStyleSheet(
            f"background-color: {BG_MAIN}; border: 1px solid {BORDER_LIGHT}; border-radius: 6px; font-size: 8.5pt; font-family: 'Segoe UI';"
        )
        self.txt_shap_verify.setPlaceholderText("Sandbox verification results...")
        ex_layout.addWidget(self.txt_shap_verify)

        lbl_rules_head = QLabel("Matched Behavior Rules:")
        lbl_rules_head.setFont(get_font("Segoe UI", 8.5, bold=True))
        lbl_rules_head.setStyleSheet(f"color: {ROSE_RED}; text-transform: uppercase;")
        ex_layout.addWidget(lbl_rules_head)

        self.txt_matched_rules = QTextEdit()
        self.txt_matched_rules.setReadOnly(True)
        self.txt_matched_rules.setFixedHeight(60)
        self.txt_matched_rules.setStyleSheet(
            f"background-color: {BG_MAIN}; border: 1px solid {BORDER_LIGHT}; border-radius: 6px; font-size: 8.5pt; font-family: 'Segoe UI';"
        )
        self.txt_matched_rules.setPlaceholderText("No behavior rules triggered...")
        ex_layout.addWidget(self.txt_matched_rules)

        self.btn_open_sandbox = QPushButton("🔬 Open Sandbox Detail Tab")
        self.btn_open_sandbox.setObjectName("btnSecondary")
        self.btn_open_sandbox.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_open_sandbox.setVisible(False)
        self.btn_open_sandbox.clicked.connect(self._open_sandbox_detail)
        ex_layout.addWidget(self.btn_open_sandbox)

        output_grid.addWidget(explain_card, stretch=3)

        pe_card = Card()
        pe_layout = QVBoxLayout(pe_card)
        pe_layout.setContentsMargins(20, 16, 20, 16)
        pe_layout.setSpacing(10)

        pe_title = QLabel("PE Executable Metadata Inspector")
        pe_title.setFont(get_font("Segoe UI", 11, bold=True))
        pe_title.setStyleSheet(f"color: {FG_PRIMARY};")
        pe_layout.addWidget(pe_title)

        pe_grid = QGridLayout()
        pe_grid.setVerticalSpacing(8)
        pe_grid.setHorizontalSpacing(14)

        self.pe_fields: dict[str, QLabel] = {}
        fields_list = [
            "Filename", "SHA256", "MD5", "Compile Time",
            "Architecture", "Sections", "Entropy", "Packed?", "Signer", "Imports"
        ]

        for idx, key in enumerate(fields_list):
            lbl_k = QLabel(f"{key}:")
            lbl_k.setFont(get_font("Segoe UI", 9, bold=True))
            lbl_k.setStyleSheet("color: #0284c7;")
            lbl_k.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
            lbl_k.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
            lbl_k.setFixedWidth(120)
            lbl_k.setFixedHeight(24)
            pe_grid.addWidget(lbl_k, idx, 0)

            if key == "Entropy":
                self.entropy_visualizer = EntropyVisualizer()
                self.lbl_entropy_val = QLabel("0.0 / 8.0")
                self.lbl_entropy_val.setFont(get_font("Segoe UI", 9, bold=True))
                self.lbl_entropy_val.setStyleSheet(f"color: {FG_PRIMARY};")
                self.lbl_entropy_val.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
                self.lbl_entropy_val.setFixedSize(80, 24)

                entropy_row = QHBoxLayout()
                entropy_row.setContentsMargins(0, 0, 0, 0)
                entropy_row.setSpacing(8)
                entropy_row.addWidget(self.entropy_visualizer, stretch=1)
                entropy_row.addWidget(self.lbl_entropy_val)

                entropy_wrap = QWidget()
                entropy_wrap.setLayout(entropy_row)
                entropy_wrap.setFixedHeight(26)
                pe_grid.addWidget(entropy_wrap, idx, 1)
            else:
                lbl_v = QLabel("N/A")
                lbl_v.setFont(get_font("Segoe UI", 9))
                lbl_v.setStyleSheet("color: #0f172a;")
                lbl_v.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
                lbl_v.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
                lbl_v.setWordWrap(True)
                lbl_v.setFixedHeight(24)
                pe_grid.addWidget(lbl_v, idx, 1)
                self.pe_fields[key] = lbl_v

        pe_grid_wrap = QWidget()
        pe_grid_wrap.setLayout(pe_grid)
        pe_layout.addWidget(pe_grid_wrap)
        pe_layout.addStretch()

        output_grid.addWidget(pe_card, stretch=4)
        layout.addLayout(output_grid)

        log_header = QLabel("Real-Time AI Inspection Console Log")
        log_header.setFont(get_font("Segoe UI", 10.5, bold=True))
        log_header.setStyleSheet(f"color: {FG_PRIMARY};")
        layout.addWidget(log_header)

        self.log_terminal = QTextEdit()
        self.log_terminal.setObjectName("terminalLog")
        self.log_terminal.setReadOnly(True)
        self.log_terminal.setPlaceholderText("Ready. Select a PE file and click START AI SCAN...")
        layout.addWidget(self.log_terminal, stretch=1)

    def _on_mode_toggled(self) -> None:
        if self.radio_mode1.isChecked():
            self._current_mode = AIMode.ONLY_STATIC
            self.mode1_frame.setProperty("active", "true")
            self.mode2_frame.setProperty("active", "false")
        else:
            self._current_mode = AIMode.STATIC_AND_DYNAMIC
            self.mode1_frame.setProperty("active", "false")
            self.mode2_frame.setProperty("active", "true")

        self.mode1_frame.style().unpolish(self.mode1_frame)
        self.mode1_frame.style().polish(self.mode1_frame)
        self.mode2_frame.style().unpolish(self.mode2_frame)
        self.mode2_frame.style().polish(self.mode2_frame)

        if self.window() and hasattr(self.window(), "dash_page"):
            self.window().dash_page.update_active_mode_display(self._current_mode.value)

    def _on_file_selected(self, path: str) -> None:
        self._selected_path = path
        self.lbl_selected_file.setText(f"📁 {os.path.basename(path)}")
        self.lbl_selected_file.setStyleSheet(f"color: {EMERALD_GREEN}; font-weight: bold;")
        self.btn_run_scan.setEnabled(True)
        self._log(f"[+] Loaded target executable: {path}", "info")

    def _execute_scan(self) -> None:
        if not self._selected_path:
            return

        self.btn_run_scan.setEnabled(False)
        self.btn_run_scan.setText("Đang phân tích...")

        self.worker = ScanWorker(
            filepath=self._selected_path,
            mode=self._current_mode,
            threshold=self.spin_thresh.value(),
            parent=self
        )
        self.worker.progress_log.connect(self._log)
        self.worker.finished.connect(self._on_scan_finished)
        self.worker.start()

    def _on_scan_finished(self, result: ScanResult) -> None:
        pe = result.pe_info
        self.pe_fields["Filename"].setText(pe.filename)
        self.pe_fields["SHA256"].setText(pe.sha256)
        self.pe_fields["MD5"].setText(pe.md5)
        self.pe_fields["Compile Time"].setText(pe.compile_time)
        self.pe_fields["Architecture"].setText(pe.architecture)
        self.pe_fields["Sections"].setText(str(pe.sections))
        self.pe_fields["Packed?"].setText("CÓ (UPX / Packer Detected)" if pe.packed else "KHÔNG")
        self.pe_fields["Signer"].setText(pe.signer)
        self.pe_fields["Imports"].setText(f"{pe.imports_count} APIs ({len(pe.suspicious_imports)} nhạy cảm)")

        self.entropy_visualizer.set_entropy(pe.entropy)
        self.lbl_entropy_val.setText(f"{pe.entropy:.2f} / 8.0")

        self.threat_gauge.set_result(result.threat_score, result.risk_label, result.risk_color)
        self.lbl_static_score.setText(f"{result.static_score}%")

        if result.auto_concluded:
            self.lbl_auto_badge.setText("⚡ AUTO-CONCLUDED")
            self.lbl_auto_badge.setStyleSheet(
                f"background-color: #dbeafe; color: {ACCENT_BLUE}; border-radius: 6px; padding: 4px 10px; font-weight: bold;"
            )
            self.lbl_dynamic_score.setText("Bỏ qua (Auto)")
        else:
            self.lbl_auto_badge.setText("🔍 SANDBOX VERIFIED")
            self.lbl_auto_badge.setStyleSheet(
                f"background-color: #fef3c7; color: {AMBER_WARN}; border-radius: 6px; padding: 4px 10px; font-weight: bold;"
            )
            self.lbl_dynamic_score.setText(f"{result.behavior_risk_raw}/100")

        self.lbl_confidence_delta.setText(f"{result.confidence_delta:+.2f}")

        if result.shap_reasons:
            shap_lines = [
                f"• <b>{feat}</b>: {'+' if val > 0 else ''}{val:.4f}"
                for feat, val in result.shap_reasons
            ]
            self.txt_shap_reasons.setHtml("<br>".join(shap_lines))
        else:
            self.txt_shap_reasons.setHtml("<span style='color:#64748b;'>Không có SHAP explanation</span>")

        if result.shap_verification_details:
            verify_html = "<br>".join(result.shap_verification_details)
            if not result.auto_concluded and result.mode.value == "Static + Dynamic":
                verify_html += "<br><br><b style='color:#0284c7;'>── Sandbox Ops Breakdown ──</b>"
            self.txt_shap_verify.setHtml(verify_html)
        else:
            msg = "Không thực hiện verification (Auto-Concluded)"
            self.txt_shap_verify.setHtml(f"<span style='color:#64748b;'>{msg}</span>")

        if result.behavior_matched_rules:
            rules_html = [
                f"<span style='color:#dc2626;'>✔ {rule}</span>"
                for rule in result.behavior_matched_rules
            ]
            self.txt_matched_rules.setHtml("<br>".join(rules_html))
        else:
            self.txt_matched_rules.setHtml(
                "<span style='color:#059669;'>✔ Không có rule nào bị vi phạm</span>"
            )

        show_sandbox_btn = (
            not result.auto_concluded
            and result.mode.value == "Static + Dynamic"
            and self._selected_path is not None
        )
        self.btn_open_sandbox.setVisible(show_sandbox_btn)

        self.btn_run_scan.setEnabled(True)
        self.btn_run_scan.setText("BẮT ĐẦU QUÉT AI")

    def _log(self, msg: str, level: str = "info") -> None:
        now = datetime.datetime.now().strftime("%H:%M:%S")
        color = "#38bdf8"
        if level == "danger":
            color = "#f87171"
        elif level == "warn":
            color = "#fbbf24"
        elif level == "success":
            color = "#34d399"

        html = f"<span style='color: #94a3b8;'>[{now}]</span> <span style='color: {color};'>{msg}</span>"
        self.log_terminal.append(html)
        self.log_terminal.ensureCursorVisible()

    def _open_sandbox_detail(self) -> None:
        """Navigate to SandboxPage and pre-fill the current scan target path."""
        if self._selected_path and self.window() and hasattr(self.window(), "sandbox_page"):
            self.window().sandbox_page.set_target_path(self._selected_path)
            if hasattr(self.window(), "_switch"):
                self.window()._switch("Sandbox")

class SandboxPage(QWidget):
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 20, 28, 28)
        layout.setSpacing(16)

        layout.addWidget(PageHeader(
            "BHPAISandbox Execution Environment",
            "Môi trường cách ly BHPAISandbox.exe theo dõi APIs, Registry Overlay & Process Activity",
        ))

        config_card = Card()
        c_grid = QGridLayout(config_card)
        c_grid.setContentsMargins(20, 18, 20, 18)
        c_grid.setSpacing(14)

        c_grid.addWidget(QLabel("Tệp PE nghi vấn:"), 0, 0)
        self.txt_sandbox_path = QLineEdit()
        self.txt_sandbox_path.setPlaceholderText("Đường dẫn tệp .exe...")
        c_grid.addWidget(self.txt_sandbox_path, 0, 1)

        btn_browse = QPushButton("Duyệt Tệp...")
        btn_browse.setObjectName("btnSecondary")
        btn_browse.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        btn_browse.clicked.connect(self._browse_pe)
        c_grid.addWidget(btn_browse, 0, 2)

        c_grid.addWidget(QLabel("Thời gian Giả lập (Giây):"), 1, 0)
        self.spin_timeout = QSpinBox()
        self.spin_timeout.setRange(5, 300)
        self.spin_timeout.setValue(30)
        c_grid.addWidget(self.spin_timeout, 1, 1, Qt.AlignmentFlag.AlignLeft)

        btn_launch = QPushButton("Kích hoạt BHPAISandbox.exe")
        btn_launch.setObjectName("btnSecondary")
        btn_launch.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        btn_launch.clicked.connect(self._start_sandbox)
        c_grid.addWidget(btn_launch, 1, 2)

        layout.addWidget(config_card)

        stats_row = QHBoxLayout()
        stats_row.setSpacing(14)

        self.stat_status     = MetricCardWidget("Sandbox Status",      "Sẵn sàng", "Isolation Active",   ACCENT_BLUE)
        self.stat_pid        = MetricCardWidget("Process PID",         "---",       "Subprocess Target",  ACCENT_LIGHT)
        self.stat_risk       = MetricCardWidget("Behavior Risk Score", "---",       "BehaviorCorrelator", ROSE_RED)
        self.stat_confidence = MetricCardWidget("Confidence Score",    "---",       "Verdict Confidence", EMERALD_GREEN)

        stats_row.addWidget(self.stat_status)
        stats_row.addWidget(self.stat_pid)
        stats_row.addWidget(self.stat_risk)
        stats_row.addWidget(self.stat_confidence)
        layout.addLayout(stats_row)

        counters_row = QHBoxLayout()
        counters_row.setSpacing(14)

        self.stat_injection = MetricCardWidget("Injection Events", "0", "RemoteThread / RWX",     ROSE_RED)
        self.stat_file_ops  = MetricCardWidget("File Operations",  "0", "Create/Write/Drop/Del",  AMBER_WARN)
        self.stat_reg_ops   = MetricCardWidget("Registry Ops",     "0", "Key/Value/Persistence",  CYAN_ACCENT)
        self.stat_network   = MetricCardWidget("Network Activity", "0", "Connections / Download", ACCENT_BLUE)

        counters_row.addWidget(self.stat_injection)
        counters_row.addWidget(self.stat_file_ops)
        counters_row.addWidget(self.stat_reg_ops)
        counters_row.addWidget(self.stat_network)
        layout.addLayout(counters_row)

        summary_card = Card()
        summary_layout = QHBoxLayout(summary_card)
        summary_layout.setContentsMargins(18, 14, 18, 14)
        summary_layout.setSpacing(18)

        bg_col = QVBoxLayout()
        bg_label = QLabel("Behavior Groups Summary")
        bg_label.setFont(get_font("Segoe UI", 9, bold=True))
        bg_label.setStyleSheet(f"color: {CYAN_ACCENT}; text-transform: uppercase;")
        bg_col.addWidget(bg_label)
        self.txt_behavior_groups = QTextEdit()
        self.txt_behavior_groups.setReadOnly(True)
        self.txt_behavior_groups.setFixedHeight(76)
        self.txt_behavior_groups.setStyleSheet(
            f"background-color: {BG_MAIN}; border: 1px solid {BORDER_LIGHT}; "
            f"border-radius: 6px; font-size: 8.5pt; font-family: 'Segoe UI';"
        )
        self.txt_behavior_groups.setPlaceholderText("Chưa có kết quả behavior groups...")
        bg_col.addWidget(self.txt_behavior_groups)
        summary_layout.addLayout(bg_col, stretch=3)

        md_col = QVBoxLayout()
        md_label = QLabel("Memory Dump Summary")
        md_label.setFont(get_font("Segoe UI", 9, bold=True))
        md_label.setStyleSheet(f"color: {AMBER_WARN}; text-transform: uppercase;")
        md_col.addWidget(md_label)
        self.txt_memory_dump = QTextEdit()
        self.txt_memory_dump.setReadOnly(True)
        self.txt_memory_dump.setFixedHeight(76)
        self.txt_memory_dump.setStyleSheet(
            f"background-color: {BG_MAIN}; border: 1px solid {BORDER_LIGHT}; "
            f"border-radius: 6px; font-size: 8.5pt; font-family: 'Segoe UI';"
        )
        self.txt_memory_dump.setPlaceholderText("Memory dump metadata...")
        md_col.addWidget(self.txt_memory_dump)
        summary_layout.addLayout(md_col, stretch=2)

        layout.addWidget(summary_card)

        events_hdr = QHBoxLayout()
        events_hdr_lbl = QLabel("Sandbox Runtime Events")
        events_hdr_lbl.setFont(get_font("Segoe UI", 10.5, bold=True))
        events_hdr_lbl.setStyleSheet(f"color: {FG_PRIMARY};")
        events_hdr.addWidget(events_hdr_lbl)
        events_hdr.addStretch()
        self.lbl_event_count = StatusPill("0 events", "#f1f5f9", FG_MUTED)
        events_hdr.addWidget(self.lbl_event_count)
        layout.addLayout(events_hdr)

        self.events_table = QTableWidget()
        self.events_table.setColumnCount(6)
        self.events_table.setHorizontalHeaderLabels(["Type", "API", "Target", "Risk", "PID", "OK"])
        self.events_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        for _col in [0, 1, 3, 4, 5]:
            self.events_table.horizontalHeader().setSectionResizeMode(_col, QHeaderView.ResizeMode.ResizeToContents)
        self.events_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.events_table.setAlternatingRowColors(True)
        self.events_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.events_table.setMaximumHeight(190)
        self.events_table.setStyleSheet(
            f"QTableWidget {{ background-color: {BG_CARD}; border: 1px solid {BORDER_LIGHT}; "
            f"border-radius: 8px; gridline-color: {BORDER_LIGHT}; }}"
            f"QTableWidget::item:alternate {{ background-color: {BG_CARD_ALT}; }}"
            f"QHeaderView::section {{ background-color: {BG_CARD_ALT}; color: {FG_PRIMARY}; "
            f"font-weight: bold; border: none; padding: 6px; "
            f"border-bottom: 1px solid {BORDER_LIGHT}; }}"
        )
        layout.addWidget(self.events_table)

        log_header = QLabel("BHPAISandbox Runtime Log Environment")
        log_header.setFont(get_font("Segoe UI", 10.5, bold=True))
        log_header.setStyleSheet(f"color: {FG_PRIMARY};")
        layout.addWidget(log_header)

        self.sandbox_terminal = QTextEdit()
        self.sandbox_terminal.setObjectName("terminalLog")
        self.sandbox_terminal.setReadOnly(True)
        self.sandbox_terminal.setPlaceholderText("Real-time event log from BHPAISandbox.exe...")
        layout.addWidget(self.sandbox_terminal, stretch=1)

    def _browse_pe(self) -> None:
        p, _ = QFileDialog.getOpenFileName(self, "Select executable file", "", "Executable Files (*.exe)")
        if p:
            self.txt_sandbox_path.setText(p)

    def set_target_path(self, path: str) -> None:
        """Pre-fill path from ScanPage navigation."""
        self.txt_sandbox_path.setText(path)

    def _start_sandbox(self) -> None:
        path = self.txt_sandbox_path.text()
        if not path:
            self._log("Vui lòng chọn một tệp PE trước khi kích hoạt Sandbox.", "warn")
            return

        self.stat_status.val_lbl.setText("Running...")
        self.stat_pid.val_lbl.setText("---")
        self.stat_risk.val_lbl.setText("---")
        self.stat_confidence.val_lbl.setText("---")
        self.stat_injection.val_lbl.setText("0")
        self.stat_file_ops.val_lbl.setText("0")
        self.stat_reg_ops.val_lbl.setText("0")
        self.stat_network.val_lbl.setText("0")
        self.txt_behavior_groups.clear()
        self.txt_memory_dump.clear()
        self.events_table.setRowCount(0)
        self.lbl_event_count.setText("0 events")

        self._log(f"[*] Initializing BHPAISandbox isolation container → {os.path.basename(path)}", "info")

        self.sb_worker = SandboxWorker(path, self.spin_timeout.value(), parent=self)
        self.sb_worker.progress_log.connect(self._log)
        self.sb_worker.finished.connect(self._on_sandbox_finished)
        self.sb_worker.start()

    def _on_sandbox_finished(self, res: dict) -> None:
        pid_val = res.get("pid")
        self.stat_pid.val_lbl.setText(str(pid_val) if pid_val else "N/A")

        report = res.get("sandbox_report", {})

        behavior_risk   = report.get("behavior_risk_score",       res.get("dynamic_risk_score", 0))
        behavior_conf   = report.get("behavior_confidence_score", 0)
        behavior_groups = report.get("behavior_groups", "")

        file_create = report.get("file_create_count",    0)
        file_write  = report.get("file_write_count",     0)
        file_delete = report.get("file_delete_count",    0)
        exec_drop   = report.get("executable_drop_count",0)
        file_total  = file_create + file_write + file_delete + exec_drop

        reg_create  = report.get("reg_key_create_count",   0)
        reg_set     = report.get("reg_value_set_count",    0)
        reg_delete  = report.get("reg_key_delete_count",   0)
        reg_persist = report.get("reg_persistence_detected", 0)
        reg_total   = reg_create + reg_set + reg_delete

        inj_detected = report.get("process_injection_detected",    0)
        remote_thr   = report.get("remote_thread_injection_count", 0)
        mem_rwx      = report.get("memory_rwx_count",              0)
        inj_total    = inj_detected + remote_thr + mem_rwx

        net_conn  = report.get("network_connection_count",  0)
        dl_exec   = report.get("download_execute_detected", 0)
        net_total = net_conn + dl_exec

        mem_dump    = report.get("memory_dump", {})
        events_list = report.get("events",      [])
        alerts_list = report.get("alerts",      [])

        self.stat_risk.val_lbl.setText(f"{behavior_risk}/100")
        self.stat_confidence.val_lbl.setText(f"{behavior_conf}/100")
        self.stat_injection.val_lbl.setText(str(inj_total))
        self.stat_file_ops.val_lbl.setText(str(file_total))
        self.stat_reg_ops.val_lbl.setText(str(reg_total))
        self.stat_network.val_lbl.setText(str(net_total))

        risk_color_str = ROSE_RED if behavior_risk >= 60 else (AMBER_WARN if behavior_risk >= 30 else EMERALD_GREEN)
        self.stat_risk.val_lbl.setStyleSheet(
            f"color: {risk_color_str}; font-size: 18pt; font-weight: bold;"
        )

        mitre_techs = report.get("mitre_techniques", [])
        bg_text = behavior_groups
        if mitre_techs:
            bg_text += f"\n[MITRE ATT&CK]: {', '.join(mitre_techs)}"

        if bg_text:
            self.txt_behavior_groups.setPlainText(bg_text)
        else:
            matched_rules = res.get("behavior_matched_rules", [])
            if matched_rules:
                self.txt_behavior_groups.setHtml(
                    "<br>".join(
                        f"<span style='color:{ROSE_RED};'>▸ {r}</span>" for r in matched_rules
                    )
                )
            else:
                self.txt_behavior_groups.setHtml(
                    f"<span style='color:{EMERALD_GREEN};'>✔ Không phát hiện hành vi đáng ngờ</span>"
                )

        if mem_dump:
            rwx_d    = mem_dump.get("rwx_regions_dumped",     0)
            priv_d   = mem_dump.get("private_regions_dumped", 0)
            pe_ex    = mem_dump.get("pe_extracted",           0)
            heap_d   = mem_dump.get("heap_regions_dumped",    0)
            trigger  = mem_dump.get("trigger_reason",         "")
            dump_dir = mem_dump.get("dump_directory",         "")
            lines = [f"RWX: {rwx_d}  |  Private: {priv_d}  |  PE Extracted: {pe_ex}  |  Heap: {heap_d}"]
            if trigger:
                lines.append(f"Trigger: {trigger}")
            if dump_dir:
                lines.append(f"Dir: {dump_dir}")
            self.txt_memory_dump.setPlainText("\n".join(lines))
        else:
            self.txt_memory_dump.setPlainText("Không có memory dump được tạo trong session này.")

        display_evs = events_list[:500]
        self.events_table.setRowCount(len(display_evs))
        self.lbl_event_count.setText(f"{len(events_list)} events")
        self.lbl_event_count.setStyleSheet(
            f"background-color: {'#fee2e2' if alerts_list else '#f1f5f9'}; "
            f"color: {ROSE_RED if alerts_list else FG_MUTED}; "
            f"border-radius: 6px; padding: 4px 10px; font-weight: bold;"
        )

        for row_i, ev in enumerate(display_evs):
            ev_type = ev.get("type",      "")
            ev_api  = ev.get("api",       "")
            ev_tgt  = ev.get("target",    "")
            ev_risk = ev.get("riskScore", 0)
            ev_pid  = ev.get("pid",       "")
            ev_ok   = ev.get("success",   True)

            items = [
                QTableWidgetItem(ev_type),
                QTableWidgetItem(ev_api),
                QTableWidgetItem(ev_tgt),
                QTableWidgetItem(str(ev_risk)),
                QTableWidgetItem(str(ev_pid)),
                QTableWidgetItem("✓" if ev_ok else "✗"),
            ]
            if ev_risk >= 70:
                items[3].setForeground(QColor(ROSE_RED))
            elif ev_risk >= 40:
                items[3].setForeground(QColor(AMBER_WARN))
            else:
                items[3].setForeground(QColor(EMERALD_GREEN))
            items[5].setForeground(QColor(EMERALD_GREEN) if ev_ok else QColor(ROSE_RED))

            for col_i, item in enumerate(items):
                self.events_table.setItem(row_i, col_i, item)

        if mitre_techs:
            self._log(f"[+] MITRE ATT&CK Techniques Mapped: {', '.join(mitre_techs)}", "warn")
        if alerts_list:
            self._log(f"[!] {len(alerts_list)} Behavioral Alert(s) Detected:", "warn")
            for alert in alerts_list:
                self._log(f"    ⚠ {alert}", "danger")
        else:
            self._log("✔ No behavioral alerts detected.", "success")


        if reg_persist:
            self._log(f"  ✘ Registry Persistence Detected (creates:{reg_create}, sets:{reg_set})", "danger")
        if report.get("self_delete_detected", 0):
            self._log("  ✘ Self-Delete detected — Anti-forensic behavior", "danger")
        if report.get("dropped_executable_executed", 0):
            self._log("  ✘ Dropped Executable Executed — Dropper pattern confirmed", "danger")
        if report.get("download_execute_detected", 0):
            self._log("  ✘ Download-and-Execute detected", "danger")
        if mem_rwx > 0:
            self._log(f"  ⚠ {mem_rwx} RWX memory region(s) allocated — possible shellcode", "warn")

        for line in res["logs"]:
            if "WARN" in line or "ALERT" in line or "Cảnh báo" in line:
                self._log(line, "warn")
            elif "MALWARE" in line or "CRITICAL" in line or "ERROR" in line:
                self._log(line, "danger")
            elif "OK" in line or "✓" in line:
                self._log(line, "success")
            else:
                self._log(line, "info")

        if behavior_risk >= 70:
            verdict = "CRITICAL THREAT"
        elif behavior_risk >= 50:
            verdict = "HIGH RISK"
        elif behavior_risk >= 30:
            verdict = "SUSPICIOUS"
        else:
            verdict = "LOW RISK / CLEAN"
        self.stat_status.val_lbl.setText(verdict)
        lvl = "success" if behavior_risk < 30 else ("warn" if behavior_risk < 60 else "danger")
        self._log(f"[=] Hoàn tất. Behavior Risk: {behavior_risk}/100 — {verdict}", lvl)

    def _log(self, msg: str, level: str = "info") -> None:
        now = datetime.datetime.now().strftime("%H:%M:%S")
        color = "#38bdf8"
        if level == "danger":
            color = "#f87171"
        elif level == "warn":
            color = "#fbbf24"
        elif level == "success":
            color = "#34d399"

        html = f"<span style='color: #94a3b8;'>[{now}]</span> <span style='color: {color};'>{msg}</span>"
        self.sandbox_terminal.append(html)
        doc = self.sandbox_terminal.document()
        while doc.blockCount() > 200:
            cursor = self.sandbox_terminal.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.Start)
            cursor.select(QTextCursor.SelectionType.BlockUnderCursor)
            cursor.removeSelectedText()
            cursor.deleteChar()


class BenchmarkWorker(QThread):
    progress_log = pyqtSignal(str, str)
    finished = pyqtSignal(dict)

    def __init__(self, malware_folder: str | None, benign_folder: str | None, parent: QWidget | None = None):
        super().__init__(parent)
        self.malware_folder = malware_folder
        self.benign_folder = benign_folder

    def run(self) -> None:
        try:
            metrics = BenchmarkEngine.run_benchmark(
                malware_folder=self.malware_folder,
                benign_folder=self.benign_folder,
                log_callback=lambda msg, level="info": self.progress_log.emit(msg, level)
            )
            self.finished.emit(metrics)
        except Exception as exc:
            self.progress_log.emit(f"Lỗi benchmark: {exc}", "danger")
            self.finished.emit({
                "accuracy": 0.0,
                "precision": 0.0,
                "recall": 0.0,
                "f1_score": 0.0,
                "roc_auc": 0.0,
                "samples_tested": 0,
                "tp": 0,
                "fp": 0,
                "tn": 0,
                "fn": 0,
            })


class BenchmarkPage(QWidget):
    """AI Dataset Benchmark Evaluation Page."""
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 20, 28, 28)
        layout.setSpacing(16)

        layout.addWidget(PageHeader(
            "Dataset Benchmark & AI Evaluation (V1.1)",
            "Đánh giá hiệu năng mô hình LightGBM AI trên tập mẫu malware và benign chuẩn hóa",
        ))

        m_row = QHBoxLayout()
        m_row.setSpacing(14)
        self.b_cards: dict[str, MetricCardWidget] = {}

        for name in ["Accuracy", "Precision", "Recall", "F1 Score", "ROC-AUC"]:
            card = MetricCardWidget(name, "--%", "Dataset Test", ACCENT_BLUE)
            m_row.addWidget(card)
            self.b_cards[name] = card

        layout.addLayout(m_row)

        ctrl_card = Card()
        c_l = QHBoxLayout(ctrl_card)
        c_l.setContentsMargins(20, 14, 20, 14)
        c_l.setSpacing(10)

        self.bm_malware_dir = QLineEdit()
        self.bm_malware_dir.setPlaceholderText("Chọn thư mục malware (tùy chọn)")
        self.bm_malware_dir.setReadOnly(True)
        c_l.addWidget(QLabel("Malware:"))
        c_l.addWidget(self.bm_malware_dir, stretch=1)

        btn_malware = QPushButton("Browse")
        btn_malware.setObjectName("btnSecondary")
        btn_malware.clicked.connect(lambda: self._pick_folder("malware"))
        c_l.addWidget(btn_malware)

        self.bm_benign_dir = QLineEdit()
        self.bm_benign_dir.setPlaceholderText("Chọn thư mục benign (tùy chọn)")
        self.bm_benign_dir.setReadOnly(True)
        c_l.addWidget(QLabel("Benign:"))
        c_l.addWidget(self.bm_benign_dir, stretch=1)

        btn_benign = QPushButton("Browse")
        btn_benign.setObjectName("btnSecondary")
        btn_benign.clicked.connect(lambda: self._pick_folder("benign"))
        c_l.addWidget(btn_benign)

        btn_run = QPushButton("Chạy Benchmark AI")
        btn_run.setObjectName("btnSecondary")
        btn_run.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        btn_run.clicked.connect(self._execute_benchmark)
        c_l.addWidget(btn_run)

        layout.addWidget(ctrl_card)

        self.bm_terminal = QTextEdit()
        self.bm_terminal.setObjectName("terminalLog")
        self.bm_terminal.setReadOnly(True)
        self.bm_terminal.setPlaceholderText("Click 'Run AI Benchmark' to perform a simulated confusion matrix evaluation...")
        layout.addWidget(self.bm_terminal, stretch=1)

        self._benchmark_worker: BenchmarkWorker | None = None

    def _pick_folder(self, kind: str) -> None:
        folder = QFileDialog.getExistingDirectory(self, f"Chọn thư mục {kind}")
        if folder:
            if kind == "malware":
                self.bm_malware_dir.setText(folder)
            else:
                self.bm_benign_dir.setText(folder)

    def _execute_benchmark(self) -> None:
        if self._benchmark_worker is not None and self._benchmark_worker.isRunning():
            return

        self.bm_terminal.clear()
        malware_folder = self.bm_malware_dir.text().strip() or None
        benign_folder = self.bm_benign_dir.text().strip() or None

        now = datetime.datetime.now().strftime("%H:%M:%S")
        self.bm_terminal.append(f"<span style='color: #38bdf8;'>[{now}] Executing AI Benchmark on selected folders...</span>")
        if malware_folder:
            self.bm_terminal.append(f"<span style='color: #38bdf8;'>  • Malware folder: {malware_folder}</span>")
        if benign_folder:
            self.bm_terminal.append(f"<span style='color: #38bdf8;'>  • Benign folder: {benign_folder}</span>")
        self.bm_terminal.append("<span style='color: #fde047;'>  • Scanning all .exe files and evaluating them with the AI scanner engine...</span>")

        self._benchmark_worker = BenchmarkWorker(malware_folder, benign_folder, self)
        self._benchmark_worker.progress_log.connect(self._append_benchmark_log)
        self._benchmark_worker.finished.connect(self._on_benchmark_finished)
        self._benchmark_worker.start()

    def _append_benchmark_log(self, msg: str, level: str = "info") -> None:
        color = "#38bdf8"
        if level == "danger":
            color = "#f87171"
        elif level == "warn":
            color = "#fbbf24"
        elif level == "success":
            color = "#34d399"
        self.bm_terminal.append(f"<span style='color: {color};'>{msg}</span>")

    def _on_benchmark_finished(self, metrics: dict) -> None:
        self.b_cards["Accuracy"].val_lbl.setText(f"{metrics['accuracy']}%")
        self.b_cards["Precision"].val_lbl.setText(f"{metrics['precision']}%")
        self.b_cards["Recall"].val_lbl.setText(f"{metrics['recall']}%")
        self.b_cards["F1 Score"].val_lbl.setText(f"{metrics['f1_score']}%")
        self.b_cards["ROC-AUC"].val_lbl.setText(str(metrics['roc_auc']))

        self.bm_terminal.append(f"<span style='color: #34d399;'>  • Samples tested: {metrics['samples_tested']}</span>")
        self.bm_terminal.append(f"<span style='color: #34d399;'>  • TP: {metrics['tp']} | FP: {metrics['fp']} | TN: {metrics['tn']} | FN: {metrics['fn']}</span>")
        self.bm_terminal.append(f"<span style='color: #34d399; font-weight: bold;'>  • Overall AI Accuracy: {metrics['accuracy']}% | ROC-AUC Area: {metrics['roc_auc']}</span>")
        self.bm_terminal.append("<span style='color: #38bdf8;'>  • Benchmark completed successfully!</span>")

class AboutPage(QWidget):
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 24, 32, 32)
        layout.setSpacing(18)

        splash_card = Card(enable_shadow=True)
        s_layout = QHBoxLayout(splash_card)
        s_layout.setContentsMargins(28, 24, 28, 24)
        s_layout.setSpacing(24)

        pm = load_logo_scaled(220)
        if pm:
            logo_img = QLabel()
            logo_img.setPixmap(pm)
            s_layout.addWidget(logo_img)

        text_box = QVBoxLayout()
        text_box.setSpacing(6)

        title_lbl = QLabel(f"{APP_NAME}")
        title_lbl.setFont(get_font("Segoe UI", 24, bold=True))
        title_lbl.setStyleSheet(f"color: {ACCENT_BLUE};")
        text_box.addWidget(title_lbl)

        ver_lbl = QLabel(f"Behavioural Heuristic PE AI — Edition {APP_VERSION}")
        ver_lbl.setFont(get_font("Segoe UI", 11, bold=True))
        ver_lbl.setStyleSheet(f"color: {CYAN_ACCENT};")
        text_box.addWidget(ver_lbl)

        desc = QLabel(
            "BHPAI V1.5 Enterprise Security Edition is an advanced next-gen Windows threat hunting platform for detecting and mitigating malware & ransomware. "
            "It integrates static PE structure extraction, Capstone disassembler n-grams, GNN/LightGBM machine learning, runtime virtualization sandbox simulation, "
            "and a True Zero-Knowledge Client-Side E2EE Encrypted Backup Vault."
        )
        desc.setFont(get_font("Segoe UI", 10))
        desc.setStyleSheet(f"color: {FG_SECONDARY};")
        desc.setWordWrap(True)
        text_box.addWidget(desc)

        s_layout.addLayout(text_box, stretch=1)
        layout.addWidget(splash_card)

        arch_card = Card()
        a_l = QVBoxLayout(arch_card)
        a_l.setContentsMargins(24, 20, 24, 20)
        a_l.setSpacing(12)

        a_title = QLabel("System Architecture Specifications (V1.5 Enterprise Features)")
        a_title.setFont(get_font("Segoe UI", 12, bold=True))
        a_title.setStyleSheet(f"color: {FG_PRIMARY};")
        a_l.addWidget(a_title)

        features_info = [
            "1. 🔒 True Zero-Knowledge E2EE Encrypted Vault (V1.5 New): Client-side AES-256-GCM encryption for files & full directory packages. Server stores 100% opaque ciphertext blobs and encrypted metadata with zero access to plaintext or keys.",
            "2. 🔑 Independent SRP-6a PAKE Authentication (V1.5 New): Password authentication is handled via zero-knowledge RFC 5054 SRP-6a PAKE, completely isolating authentication secrets from the vault encryption key domain.",
            "3. ⚡ Instant Password Rotation & K_vault Indirection (V1.5 New): K_vault indirection allows changing master passwords instantly without re-encrypting backup blobs.",
            "4. 📦 Composite Folder Package Backup (V1.5 New): Ultra-fast single-request folder archiving & automatic decrypted folder extraction.",
            "5. 🧪 Dynamic Windows Sandbox & Stealth Monitoring: Copy-on-Write (COW) file/registry virtualization, process injection detection, ADS support, and PEB un-linking anti-evasion.",
            "6. 🔍 Static PE Analyzer & AI Machine Learning: Capstone disassembler for opcode n-grams, Shannon entropy, YARA rule generation, and LightGBM / GNN machine learning.",
            "7. 💾 Disk & Database Persistence (V1.5 New): User registration data and ciphertext blobs are permanently stored on server disk (uploads/vault/), surviving server restarts.",
            "8. 🚀 Non-Blocking 60 FPS Asynchronous Architecture (V1.5 New): KDF derivation (Argon2id/PBKDF2), crypto operations, and network I/O run on background QThread workers.",
        ]


        for item in features_info:
            lbl = QLabel(item)
            lbl.setFont(get_font("Segoe UI", 9.5))
            lbl.setStyleSheet(f"color: {FG_SECONDARY}; line-height: 1.5;")
            lbl.setWordWrap(True)
            a_l.addWidget(lbl)

        layout.addWidget(arch_card)
        layout.addStretch()

class BHPAIApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} ({APP_VERSION})")
        self.resize(1280, 840)
        self.setMinimumSize(1100, 720)

        if LOGO_PATH.exists():
            self.setWindowIcon(QIcon(str(LOGO_PATH)))

        self._is_quitting = False
        self._nav_items: dict[str, NavButton] = {}
        self._active_page: str | None = None
        self._build_ui()

        self._realtime_engine = RealtimeGuardEngine()
        self._realtime_worker = RealtimeGuardWorkerThread(self._realtime_engine, self)
        self._realtime_worker.threat_detected.connect(self._on_realtime_threat_detected)
        self._realtime_worker.start()

        self._setup_system_tray()

    def _setup_system_tray(self) -> None:
        self.tray_icon = QSystemTrayIcon(self)
        if LOGO_PATH.exists():
            self.tray_icon.setIcon(QIcon(str(LOGO_PATH)))

        self.tray_icon.setToolTip("BHPAI Real-Time Protection - ACTIVE")

        tray_menu = QMenu()
        show_action = QAction("🖥️ Mở giao diện BHPAI", self)
        show_action.setFont(get_font("Segoe UI", 9.5, bold=True))
        show_action.triggered.connect(self._restore_from_tray)

        self.toggle_guard_action = QAction("🛡️ Realtime Protection: Đang bật", self)
        self.toggle_guard_action.triggered.connect(self._toggle_realtime_from_tray)

        scan_down_action = QAction("⚡ Quét nhanh Downloads", self)
        scan_down_action.triggered.connect(self._scan_downloads_from_tray)

        quit_action = QAction("🚪 Thoát hoàn toàn BHPAI", self)
        quit_action.triggered.connect(self._quit_app)

        tray_menu.addAction(show_action)
        tray_menu.addSeparator()
        tray_menu.addAction(self.toggle_guard_action)
        tray_menu.addAction(scan_down_action)
        tray_menu.addSeparator()
        tray_menu.addAction(quit_action)

        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.activated.connect(self._on_tray_activated)
        self.tray_icon.show()

    def closeEvent(self, event) -> None:
        if self._is_quitting:
            if hasattr(self, "_realtime_worker") and self._realtime_worker.isRunning():
                self._realtime_worker.stop()
            event.accept()
        else:
            event.ignore()
            self.hide()
            if hasattr(self, "tray_icon") and self.tray_icon.isVisible():
                self.tray_icon.showMessage(
                    "BHPAI Security Guard",
                    "BHPAI đang chạy ẩn dưới khay hệ thống (System Tray) để bảo vệ máy tính 24/7.",
                    QSystemTrayIcon.MessageIcon.Information,
                    3000
                )

    def _restore_from_tray(self) -> None:
        self.showNormal()
        self.activateWindow()
        self.raise_()

    def _on_tray_activated(self, reason) -> None:
        if reason in (QSystemTrayIcon.ActivationReason.Trigger, QSystemTrayIcon.ActivationReason.DoubleClick):
            self._restore_from_tray()

    def _toggle_realtime_from_tray(self) -> None:
        enabled = not self._realtime_engine.enabled
        self._realtime_engine.enabled = enabled
        status_str = "Đang bật" if enabled else "Đã tắt"
        self.toggle_guard_action.setText(f"🛡️ Realtime Protection: {status_str}")

        if hasattr(self, "tray_icon"):
            self.tray_icon.setToolTip(f"BHPAI Protection - Real-time Guard {status_str}")
            self.tray_icon.showMessage(
                "BHPAI Real-Time Guard",
                f"Bảo vệ thời gian thực đã được {status_str.lower()}.",
                QSystemTrayIcon.MessageIcon.Information,
                2000
            )

        if hasattr(self, "dash_page"):
            self.dash_page.update_realtime_guard_ui(
                enabled,
                self._realtime_engine._total_scanned_count,
                self._realtime_engine._total_threats_count
            )

        if hasattr(self, "sf_status"):
            if enabled:
                self.sf_status.setText("● Guard: REAL-TIME ON")
                self.sf_status.setStyleSheet(f"color: {EMERALD_GREEN};")
            else:
                self.sf_status.setText("● Guard: PAUSED")
                self.sf_status.setStyleSheet(f"color: {ROSE_RED};")

    def _scan_downloads_from_tray(self) -> None:
        self._restore_from_tray()
        self._switch("Scan")
        downloads = Path.home() / "Downloads"
        if downloads.exists() and hasattr(self, "scan_page"):
            self.scan_page.file_input.setText(str(downloads))

    def _quit_app(self) -> None:
        self._is_quitting = True
        self.close()

    def _on_realtime_threat_detected(self, threat_info: dict) -> None:
        if hasattr(self, "dash_page"):
            self.dash_page.update_realtime_guard_ui(
                self._realtime_engine.enabled,
                self._realtime_engine._total_scanned_count,
                self._realtime_engine._total_threats_count
            )

        fn = threat_info.get("filename", "File")
        score = threat_info.get("threat_score", 0)

        if hasattr(self, "tray_icon") and self.tray_icon.isVisible():
            self.tray_icon.showMessage(
                "⚠️ CẢNH BÁO MÃ ĐỘC REAL-TIME!",
                f"Phát hiện tệp tin nguy cơ: {fn} ({score}% Risk). Nhấp để chọn xử lý.",
                QSystemTrayIcon.MessageIcon.Warning,
                5000
            )

        dialog = RealtimeThreatDialog(threat_info, self)
        dialog.exec()

        action = dialog.selected_action
        filepath = threat_info.get("filepath", "")

        if action == RealtimeThreatDialog.ACTION_QUARANTINE:
            ok, msg = self._realtime_engine.quarantine_file(filepath)
            if ok:
                QMessageBox.information(self, "Cách ly thành công", f"File đã được chuyển an toàn vào Trạm cách ly:\n{msg}")
            else:
                QMessageBox.warning(self, "Lỗi cách ly", f"Không thể cách ly file:\n{msg}")

        elif action == RealtimeThreatDialog.ACTION_DELETE:
            ok, msg = self._realtime_engine.delete_file_safely(filepath)
            if ok:
                QMessageBox.information(self, "Xóa thành công", "File mã độc đã được xóa khỏi hệ thống theo yêu cầu của bạn.")
            else:
                QMessageBox.warning(self, "Lỗi xóa file", f"Không thể xóa file:\n{msg}")

        elif action == RealtimeThreatDialog.ACTION_SANDBOX:
            self._restore_from_tray()
            self._switch("Sandbox")
            if hasattr(self, "sandbox_page"):
                self.sandbox_page.file_input.setText(filepath)
                self.sandbox_page.add_log(f"[Realtime Guard] Đã nạp file {filepath} vào Sandbox container.", "warn")

        elif action == RealtimeThreatDialog.ACTION_TRUST:
            sha = threat_info.get("sha256", "")
            self._realtime_engine.trust_file(sha)
            QMessageBox.information(self, "Đã thêm vào danh sách Tin tưởng", f"Mẫu file SHA256 ({sha[:16]}...) sẽ được bỏ qua trong các lần quét sau.")

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)

        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        sidebar = QWidget()
        sidebar.setFixedWidth(SIDEBAR_W)
        sidebar.setStyleSheet(f"background-color: {BG_PANEL}; border-right: 1px solid {BORDER_LIGHT};")

        sb_layout = QVBoxLayout(sidebar)
        sb_layout.setContentsMargins(0, 0, 0, 0)
        sb_layout.setSpacing(0)

        brand_card = QFrame()
        brand_card.setStyleSheet(f"background-color: #f8fafc; border-bottom: 1px solid {BORDER_LIGHT};")
        bc_layout = QVBoxLayout(brand_card)
        bc_layout.setContentsMargins(18, 18, 18, 16)
        bc_layout.setSpacing(8)

        logo_row = QHBoxLayout()
        logo_row.setSpacing(12)

        pm = load_logo_scaled(70)
        if pm:
            brand_logo = QLabel()
            brand_logo.setPixmap(pm)
            logo_row.addWidget(brand_logo)

        brand_text_box = QVBoxLayout()
        brand_text_box.setSpacing(2)

        brand_title = QLabel("BHPAI SOC")
        brand_title.setFont(get_font("Segoe UI", 13, bold=True))
        brand_title.setStyleSheet(f"color: {FG_PRIMARY}; letter-spacing: 0.5px;")
        brand_text_box.addWidget(brand_title)

        brand_ver = QLabel("V1.5 ENTERPRISE")
        brand_ver.setFont(get_font("Segoe UI", 8, bold=True))
        brand_ver.setStyleSheet(f"color: {ACCENT_BLUE};")
        brand_text_box.addWidget(brand_ver)


        logo_row.addLayout(brand_text_box)
        logo_row.addStretch()
        bc_layout.addLayout(logo_row)

        sub_brand_desc = QLabel("Behavioral Heuristic PE AI")
        sub_brand_desc.setFont(get_font("Segoe UI", 8.5))
        sub_brand_desc.setStyleSheet(f"color: {FG_MUTED}; font-weight: 600;")
        bc_layout.addWidget(sub_brand_desc)

        sb_layout.addWidget(brand_card)

        nav_items_spec = [
            ("Dashboard", "SOC Overview"),
            ("Scan", "PE Analysis & AI Scan"),
            ("Sandbox", "Runtime Behavior Emulation"),
            ("Benchmark", "AI Benchmark Simulation"),
            ("Vault", "Zero-Knowledge Encrypted Backup"),
            ("About", "Version Info"),
        ]


        sb_layout.addSpacing(10)

        for name, subtitle in nav_items_spec:
            btn = NavButton(name, subtitle, on_click=lambda n=name: self._switch(n))
            sb_layout.addWidget(btn)
            self._nav_items[name] = btn

        sb_layout.addStretch()

        sb_footer = QVBoxLayout()
        sb_footer.setContentsMargins(20, 16, 20, 20)
        sb_footer.setSpacing(4)

        sf_title = QLabel("BHPAI AI Engine V1.5 Enterprise")
        sf_title.setFont(get_font("Segoe UI", 9, bold=True))
        sf_title.setStyleSheet(f"color: {FG_MUTED};")

        sb_footer.addWidget(sf_title)

        self.sf_status = QLabel("● Guard: REAL-TIME ON")
        self.sf_status.setFont(get_font("Segoe UI", 8.5, bold=True))
        self.sf_status.setStyleSheet(f"color: {EMERALD_GREEN};")
        sb_footer.addWidget(self.sf_status)

        sb_layout.addLayout(sb_footer)
        main_layout.addWidget(sidebar)

        self._stack = QStackedWidget()
        self._stack.setStyleSheet(f"background-color: {BG_MAIN};")

        self.dash_page = DashboardPage()
        self.scan_page = ScanPage()
        self.sandbox_page = SandboxPage()
        self.benchmark_page = BenchmarkPage()
        self.vault_page = EncryptedBackupVaultWidget() if EncryptedBackupVaultWidget else QWidget()
        self.about_page = AboutPage()

        self._pages = {
            "Dashboard": self.dash_page,
            "Scan": self.scan_page,
            "Sandbox": self.sandbox_page,
            "Benchmark": self.benchmark_page,
            "Vault": self.vault_page,
            "About": self.about_page,
        }


        self._page_indices: dict[str, int] = {}
        for name, page in self._pages.items():
            idx = self._stack.addWidget(page)
            self._page_indices[name] = idx

        main_layout.addWidget(self._stack, stretch=1)
        self._switch("Dashboard")

    def _switch(self, name: str) -> None:
        if self._active_page == name:
            return
        self._stack.setCurrentIndex(self._page_indices[name])
        for nav_name, btn in self._nav_items.items():
            btn.set_active(nav_name == name)
        self._active_page = name

def is_admin() -> bool:
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def main() -> int:
    if sys.platform == "win32" and not is_admin() and "--no-elevate" not in sys.argv:
        try:
            import ctypes
            script = os.path.abspath(sys.argv[0])
            params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script}" {params}', None, 1)
            return 0
        except Exception as e:
            print(f"[WARN] Unable to elevate to Administrator mode: {e}")

    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    app.setStyle("Fusion")
    app.setStyleSheet(APP_STYLESHEET)
    window = BHPAIApp()
    window.showMaximized()
    return app.exec()

if __name__ == "__main__":
    sys.exit(main())