"""
BHPAI Modern Encrypted Backup Vault GUI Component (PyQt6 / PySide6)
===================================================================
Provides an ultra-responsive visual interface for Zero-Knowledge Client-Side Encrypted Backup.
Supports both single-file and full-directory encrypted backups.
All heavy cryptographic operations (Argon2id/PBKDF2 KDF, SRP-6a PAKE, AES-GCM encryption)
and network I/O run in background QThreads to ensure 60 FPS smooth GUI responsiveness.
"""

import os
import enum
from pathlib import Path
from typing import Optional, Any, Dict, List

try:
    from PyQt6.QtCore import Qt, pyqtSignal, QThread
    from PyQt6.QtGui import QFont, QColor, QIcon
    from PyQt6.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit,
        QTableWidget, QTableWidgetItem, QFileDialog, QMessageBox, QFrame,
        QCheckBox, QSplitter, QHeaderView, QGroupBox, QDialog, QProgressBar,
        QInputDialog
    )

except ImportError:
    from PySide6.QtCore import Qt, Signal as pyqtSignal, QThread
    from PySide6.QtGui import QFont, QColor, QIcon
    from PySide6.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit,
        QTableWidget, QTableWidgetItem, QFileDialog, QMessageBox, QFrame,
        QCheckBox, QSplitter, QHeaderView, QGroupBox, QDialog, QProgressBar,
        QInputDialog
    )


from Core.vault.client import VaultClient


class VaultAction(enum.Enum):
    REGISTER = "register"
    UNLOCK = "unlock"
    BACKUP = "backup"
    BACKUP_FOLDER = "backup_folder"
    REFRESH = "refresh"
    RESTORE = "restore"
    REKEY = "rekey"


class VaultWorkerThread(QThread):
    """Background worker thread to offload KDF, encryption, and network I/O from the GUI thread."""
    task_finished = pyqtSignal(str, bool, object)
    progress_signal = pyqtSignal(int, int, str)

    def __init__(self, client: VaultClient, action: VaultAction, kwargs: Dict[str, Any]):
        super().__init__()
        self.client = client
        self.action = action
        self.kwargs = kwargs

    def run(self):
        try:
            if self.action == VaultAction.REGISTER:
                res = self.client.register_vault(self.kwargs["username"], self.kwargs["password"])
                self.task_finished.emit(self.action.value, True, res)
            elif self.action == VaultAction.UNLOCK:
                res = self.client.unlock_vault(self.kwargs["username"], self.kwargs["password"])
                self.task_finished.emit(self.action.value, True, res)
            elif self.action == VaultAction.BACKUP:
                res = self.client.backup_file(self.kwargs["file_path"], apply_padding=self.kwargs.get("apply_padding", True))
                self.task_finished.emit(self.action.value, True, res)
            elif self.action == VaultAction.BACKUP_FOLDER:
                def prog_cb(curr, tot, name):
                    self.progress_signal.emit(curr, tot, name)

                res = self.client.backup_directory(
                    self.kwargs["dir_path"],
                    apply_padding=self.kwargs.get("apply_padding", True),
                    progress_callback=prog_cb
                )
                self.task_finished.emit(self.action.value, True, res)
            elif self.action == VaultAction.REFRESH:
                res = self.client.list_backups()
                self.task_finished.emit(self.action.value, True, res)
            elif self.action == VaultAction.RESTORE:
                res = self.client.restore_file(self.kwargs["blob_id"], self.kwargs["dest_path"])
                self.task_finished.emit(self.action.value, True, res)
            elif self.action == VaultAction.REKEY:
                res = self.client.rekey_password(self.kwargs["new_password"])
                self.task_finished.emit(self.action.value, True, res)
        except Exception as e:
            self.task_finished.emit(self.action.value, False, str(e))


class EncryptedBackupVaultWidget(QWidget):
    """Encrypted Backup Vault Tab Widget for BHPAI GUI."""

    def __init__(self, parent=None, server_url: str = "http://localhost:8000"):
        super().__init__(parent)
        self.client = VaultClient(server_url=server_url)
        self.worker: Optional[VaultWorkerThread] = None
        self._init_ui()

    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)

        header_frame = QFrame()
        header_frame.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0f172a, stop:1 #1e293b);
                border-radius: 12px;
                padding: 16px;
            }
        """)
        header_layout = QHBoxLayout(header_frame)

        title_box = QVBoxLayout()
        title_label = QLabel("🛡️ BHPAI Zero-Knowledge Encrypted Backup Vault")
        title_label.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        title_label.setStyleSheet("color: #f8fafc;")

        subtitle_label = QLabel("Client-side end-to-end encrypted backup (AES-256-GCM + SRP-6a PAKE). Even BHPAI server cannot decrypt your files.")
        subtitle_label.setFont(QFont("Segoe UI", 10))
        subtitle_label.setStyleSheet("color: #94a3b8;")

        title_box.addWidget(title_label)
        title_box.addWidget(subtitle_label)
        header_layout.addLayout(title_box)

        self.status_badge = QLabel("🔒 LOCKED")
        self.status_badge.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        self.status_badge.setStyleSheet("""
            QLabel {
                background-color: #ef4444;
                color: white;
                padding: 6px 14px;
                border-radius: 16px;
            }
        """)
        header_layout.addWidget(self.status_badge, alignment=Qt.AlignmentFlag.AlignRight)

        main_layout.addWidget(header_frame)

        auth_card = QFrame()
        auth_card.setStyleSheet("""
            QFrame {
                background-color: #ffffff;
                border: 1px solid #e2e8f0;
                border-radius: 10px;
                padding: 12px;
            }
        """)
        auth_layout = QHBoxLayout(auth_card)

        auth_layout.addWidget(QLabel("User:"))
        last_user = self._load_last_username() or "user@bhpai.local"
        self.user_input = QLineEdit(last_user)
        self.user_input.setFixedWidth(160)
        auth_layout.addWidget(self.user_input)


        auth_layout.addWidget(QLabel("Master Password:"))
        self.pass_input = QLineEdit()
        self.pass_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.pass_input.setPlaceholderText("Enter master password...")
        self.pass_input.setFixedWidth(200)
        auth_layout.addWidget(self.pass_input)

        self.btn_unlock = QPushButton("🔓 Unlock Vault")
        self.btn_unlock.setStyleSheet("""
            QPushButton {
                background-color: #2563eb; color: white; font-weight: bold;
                padding: 8px 16px; border-radius: 6px; border: none;
            }
            QPushButton:hover { background-color: #1d4ed8; }
            QPushButton:disabled { background-color: #cbd5e1; color: #94a3b8; }
        """)
        self.btn_unlock.clicked.connect(self._handle_unlock)
        auth_layout.addWidget(self.btn_unlock)

        self.btn_register = QPushButton("✨ Create New Vault")
        self.btn_register.setStyleSheet("""
            QPushButton {
                background-color: #059669; color: white; font-weight: bold;
                padding: 8px 16px; border-radius: 6px; border: none;
            }
            QPushButton:hover { background-color: #047857; }
            QPushButton:disabled { background-color: #cbd5e1; color: #94a3b8; }
        """)
        self.btn_register.clicked.connect(self._handle_register)
        auth_layout.addWidget(self.btn_register)

        self.btn_rekey = QPushButton("🔑 Change Password (Re-key)")
        self.btn_rekey.setEnabled(False)
        self.btn_rekey.setStyleSheet("""
            QPushButton {
                background-color: #d97706; color: white; font-weight: bold;
                padding: 8px 16px; border-radius: 6px; border: none;
            }
            QPushButton:hover { background-color: #b45309; }
            QPushButton:disabled { background-color: #cbd5e1; color: #94a3b8; }
        """)
        self.btn_rekey.clicked.connect(self._handle_rekey)
        auth_layout.addWidget(self.btn_rekey)

        auth_layout.addStretch()
        main_layout.addWidget(auth_card)

        sec_notice = QFrame()
        sec_notice.setStyleSheet("""
            QFrame {
                background-color: #f8fafc;
                border: 1px solid #cbd5e1;
                border-left: 4px solid #0284c7;
                border-radius: 6px;
                padding: 10px;
            }
        """)
        sec_layout = QVBoxLayout(sec_notice)
        sec_title = QLabel("🔒 True Zero-Knowledge Architecture Guarantee:")
        sec_title.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        sec_title.setStyleSheet("color: #0369a1;")
        
        sec_desc = QLabel(
            "1. Master Password & Keys stay local in client memory.\n"
            "2. Files are encrypted locally with unique AES-256-GCM DEKs and CSPRNG nonces.\n"
            "3. Filenames and paths are encrypted client-side; server sees only anonymous UUID blobs.\n"
            "⚠️ Client Integrity: E2EE protection relies on untampered BHPAI client execution."
        )
        sec_desc.setFont(QFont("Segoe UI", 8))
        sec_desc.setStyleSheet("color: #334155;")

        sec_layout.addWidget(sec_title)
        sec_layout.addWidget(sec_desc)
        main_layout.addWidget(sec_notice)

        content_splitter = QSplitter(Qt.Orientation.Horizontal)

        left_panel = QFrame()
        left_panel.setStyleSheet("QFrame { background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 10px; padding: 12px; }")
        left_layout = QVBoxLayout(left_panel)

        left_title = QLabel("📦 Backup Local File / Directory")
        left_title.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        left_layout.addWidget(left_title)

        self.btn_select_file = QPushButton("📄 Choose File to Encrypt & Backup")
        self.btn_select_file.setEnabled(False)
        self.btn_select_file.setStyleSheet("""
            QPushButton {
                background-color: #3b82f6; color: white; padding: 10px; border-radius: 6px; font-weight: bold;
            }
            QPushButton:hover { background-color: #2563eb; }
            QPushButton:disabled { background-color: #cbd5e1; color: #94a3b8; }
        """)
        self.btn_select_file.clicked.connect(self._handle_backup_file)
        left_layout.addWidget(self.btn_select_file)

        self.btn_select_folder = QPushButton("📂 Choose Folder to Encrypt & Backup")
        self.btn_select_folder.setEnabled(False)
        self.btn_select_folder.setStyleSheet("""
            QPushButton {
                background-color: #0284c7; color: white; padding: 10px; border-radius: 6px; font-weight: bold;
            }
            QPushButton:hover { background-color: #0369a1; }
            QPushButton:disabled { background-color: #cbd5e1; color: #94a3b8; }
        """)
        self.btn_select_folder.clicked.connect(self._handle_backup_folder)
        left_layout.addWidget(self.btn_select_folder)

        self.chk_padding = QCheckBox("Enable Application-Level Size Padding (Obfuscate File Size)")
        self.chk_padding.setChecked(True)
        left_layout.addWidget(self.chk_padding)

        self.lbl_backup_status = QLabel("Select file or folder to backup...")
        self.lbl_backup_status.setStyleSheet("color: #64748b; font-size: 11px;")
        self.lbl_backup_status.setWordWrap(True)
        left_layout.addWidget(self.lbl_backup_status)
        left_layout.addStretch()

        content_splitter.addWidget(left_panel)

        right_panel = QFrame()
        right_panel.setStyleSheet("QFrame { background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 10px; padding: 12px; }")
        right_layout = QVBoxLayout(right_panel)

        right_header = QHBoxLayout()
        right_title = QLabel("☁️ Encrypted Backups on Server")
        right_title.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        right_header.addWidget(right_title)

        self.btn_refresh = QPushButton("🔄 Refresh List")
        self.btn_refresh.setEnabled(False)
        self.btn_refresh.clicked.connect(self._refresh_backups)
        right_header.addWidget(self.btn_refresh)
        right_layout.addLayout(right_header)

        self.table_backups = QTableWidget(0, 5)
        self.table_backups.setHorizontalHeaderLabels(["Relative Path / Filename", "Original Path", "Size", "Created", "Actions"])
        self.table_backups.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        right_layout.addWidget(self.table_backups)

        content_splitter.addWidget(right_panel)
        content_splitter.setSizes([320, 680])

        main_layout.addWidget(content_splitter)

    def _set_busy(self, busy: bool, message: str = ""):
        """Enable/disable buttons and show status during background crypto operations."""
        self.btn_unlock.setEnabled(not busy and not self.client.is_unlocked)
        self.btn_register.setEnabled(not busy and not self.client.is_unlocked)
        self.btn_rekey.setEnabled(not busy and self.client.is_unlocked)
        self.btn_select_file.setEnabled(not busy and self.client.is_unlocked)
        self.btn_select_folder.setEnabled(not busy and self.client.is_unlocked)
        self.btn_refresh.setEnabled(not busy and self.client.is_unlocked)

        if busy:
            self.lbl_backup_status.setText(f"⏳ {message}...")
        elif message:
            self.lbl_backup_status.setText(message)

    def _run_worker(self, action: VaultAction, kwargs: Dict[str, Any], status_msg: str):
        if self.worker and self.worker.isRunning():
            return

        self._set_busy(True, status_msg)
        self.worker = VaultWorkerThread(self.client, action, kwargs)
        self.worker.task_finished.connect(self._on_worker_finished)
        self.worker.progress_signal.connect(self._on_worker_progress)
        self.worker.start()

    def _on_worker_progress(self, curr: int, tot: int, name: str):
        self.lbl_backup_status.setText(f"⏳ Encrypting folder: {curr}/{tot} ({name})...")

    def _get_config_path(self) -> Path:
        return Path(__file__).resolve().parent / "vault_config.json"

    def _load_last_username(self) -> Optional[str]:
        try:
            cfg_path = Path(__file__).resolve().parent / "vault_config.json"
            if cfg_path.exists():
                import json
                data = json.loads(cfg_path.read_text(encoding="utf-8"))
                return data.get("last_username")
        except Exception:
            pass
        return None

    def _save_last_username(self, username: str):
        try:
            cfg_path = Path(__file__).resolve().parent / "vault_config.json"
            import json
            cfg_path.write_text(json.dumps({"last_username": username}, indent=2), encoding="utf-8")
        except Exception:
            pass

    def _on_worker_finished(self, action_str: str, success: bool, payload_or_error: Any):
        self._set_busy(False)
        action = VaultAction(action_str)

        if action == VaultAction.REGISTER:
            if success:
                self._save_last_username(self.user_input.text().strip())
                QMessageBox.information(self, "Success", f"Vault created successfully for {self.user_input.text().strip()}. You can now unlock your vault.")
            else:
                QMessageBox.critical(self, "Registration Error", str(payload_or_error))

        elif action == VaultAction.UNLOCK:
            if success:
                self._save_last_username(self.user_input.text().strip())
                self.status_badge.setText("🔓 UNLOCKED")
                self.status_badge.setStyleSheet("""
                    QLabel {
                        background-color: #059669; color: white; padding: 6px 14px; border-radius: 16px; font-weight: bold;
                    }
                """)
                self.btn_select_file.setEnabled(True)
                self.btn_select_folder.setEnabled(True)
                self.btn_refresh.setEnabled(True)
                self.btn_rekey.setEnabled(True)
                self.lbl_backup_status.setText("Vault unlocked. Master Key in memory.")
                self._refresh_backups()
                QMessageBox.information(self, "Vault Unlocked", "Zero-Knowledge Vault unlocked. Master Key ready in memory.")
            else:
                QMessageBox.critical(self, "Unlock Failed", f"Invalid credentials or connection error: {payload_or_error}")


        elif action in (VaultAction.BACKUP, VaultAction.BACKUP_FOLDER):
            if success:
                count = len(payload_or_error) if isinstance(payload_or_error, list) else 1
                self.lbl_backup_status.setText(f"✅ Backup complete ({count} file(s)).")
                self._refresh_backups()
                QMessageBox.information(self, "Backup Complete", f"Successfully encrypted and backed up {count} file(s).")
            else:
                self.lbl_backup_status.setText("❌ Backup failed.")
                QMessageBox.critical(self, "Backup Error", str(payload_or_error))

        elif action == VaultAction.REFRESH:
            if success:
                records = payload_or_error
                self.table_backups.setRowCount(0)
                for row_idx, r in enumerate(records):
                    self.table_backups.insertRow(row_idx)
                    meta = r.get("metadata", {})

                    disp_name = meta.get("relative_path") or meta.get("filename", "Encrypted")
                    self.table_backups.setItem(row_idx, 0, QTableWidgetItem(disp_name))
                    self.table_backups.setItem(row_idx, 1, QTableWidgetItem(meta.get("orig_path", "Encrypted")))
                    self.table_backups.setItem(row_idx, 2, QTableWidgetItem(f"{r.get('size_bytes', 0):,} B"))
                    self.table_backups.setItem(row_idx, 3, QTableWidgetItem(r.get("created_at", "")[:19]))

                    btn_restore = QPushButton("⬇️ Decrypt & Restore")
                    blob_id = r["blob_id"]
                    is_folder = meta.get("is_folder", False)
                    btn_restore.clicked.connect(lambda _, b=blob_id, name=meta.get("filename", "restored.file"), f=is_folder: self._handle_restore(b, name, f))
                    self.table_backups.setCellWidget(row_idx, 4, btn_restore)

            else:
                QMessageBox.warning(self, "Refresh Error", f"Failed to refresh backups: {payload_or_error}")

        elif action == VaultAction.RESTORE:
            if success:
                QMessageBox.information(self, "Restoration Complete", "Ciphertext downloaded and decrypted locally to target directory.")
            else:
                QMessageBox.critical(self, "Restore Failed", str(payload_or_error))

        elif action == VaultAction.REKEY:
            if success:
                QMessageBox.information(self, "Re-key Success", "Password changed and K_vault re-encrypted. Existing backup files remain completely valid.")
            else:
                QMessageBox.critical(self, "Re-key Error", str(payload_or_error))

    def _handle_register(self):
        username = self.user_input.text().strip()
        password = self.pass_input.text()
        if not username or not password:
            QMessageBox.warning(self, "Warning", "Please enter username and master password.")
            return

        self._run_worker(VaultAction.REGISTER, {"username": username, "password": password}, "Computing Argon2id/PBKDF2 KDF & Creating Vault")

    def _handle_unlock(self):
        username = self.user_input.text().strip()
        password = self.pass_input.text()
        if not username or not password:
            QMessageBox.warning(self, "Warning", "Please enter username and master password.")
            return

        self._run_worker(VaultAction.UNLOCK, {"username": username, "password": password}, "Authenticating via SRP-6a PAKE & Deriving Keys")

    def _handle_rekey(self):
        new_pass, ok = QInputDialog.getText(self, "Change Password", "Enter new master password:", QLineEdit.EchoMode.Password)
        if ok and new_pass:
            self._run_worker(VaultAction.REKEY, {"new_password": new_pass}, "Re-keying K_vault envelope")

    def _handle_backup_file(self):
        file_path_str, _ = QFileDialog.getOpenFileName(self, "Select File to Backup")
        if not file_path_str:
            return

        file_path = Path(file_path_str)
        self._run_worker(
            VaultAction.BACKUP,
            {"file_path": file_path, "apply_padding": self.chk_padding.isChecked()},
            f"Encrypting {file_path.name} locally & uploading"
        )

    def _handle_backup_folder(self):
        dir_path_str = QFileDialog.getExistingDirectory(self, "Select Folder to Backup")
        if not dir_path_str:
            return

        dir_path = Path(dir_path_str)
        self._run_worker(
            VaultAction.BACKUP_FOLDER,
            {"dir_path": dir_path, "apply_padding": self.chk_padding.isChecked()},
            f"Zipping & Encrypting directory {dir_path.name}"
        )

    def _refresh_backups(self):
        if not self.client.is_unlocked:
            return
        self._run_worker(VaultAction.REFRESH, {}, "Fetching & Decrypting Backup Metadata")

    def _handle_restore(self, blob_id: str, default_name: str, is_folder: bool = False):
        if is_folder:
            dest_str = QFileDialog.getExistingDirectory(self, "Select Destination Folder to Restore Into")
        else:
            dest_str, _ = QFileDialog.getSaveFileName(self, "Save Decrypted File", default_name)

        if not dest_str:
            return

        self._run_worker(
            VaultAction.RESTORE,
            {"blob_id": blob_id, "dest_path": Path(dest_str)},
            f"Downloading & Decrypting {default_name}"
        )

