import os
import sys
import subprocess
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

class RamPagefilePythonExtractor:
    """
    Python wrapper for BHPAI Intelligent RAM & Pagefile Key Extraction Engine.
    Executes high-performance C++ RamPagefileKeyExtractor via CLI or subprocess.
    """

    @staticmethod
    def extract_keys_from_pagefile(pagefile_path: str = r"C:\pagefile.sys") -> List[Dict[str, Any]]:
        """
        Scans pagefile.sys or dump file for AES / ChaCha20 / RSA encryption keys.
        """
        bhr_exe = Path("bhr_identify.exe")
        if not bhr_exe.exists():
            bhr_exe = Path("BHR/build/bhr_identify.exe")

        if not Path(pagefile_path).exists():
            return []

        if bhr_exe.exists():
            try:
                cmd = [str(bhr_exe), "--extract-pagefile", pagefile_path]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                if res.returncode == 0 and res.stdout.strip():
                    return json.loads(res.stdout)
            except Exception as e:
                print(f"[RamPagefileExtractor] Pagefile scan error: {e}")

        return []

    @staticmethod
    def extract_keys_from_process_ram(pid: int) -> List[Dict[str, Any]]:
        """
        Scans targeted process RAM memory for AES round key schedules and ChaCha20 state arrays.
        """
        bhr_exe = Path("bhr_identify.exe")
        if not bhr_exe.exists():
            bhr_exe = Path("BHR/build/bhr_identify.exe")

        if bhr_exe.exists():
            try:
                cmd = [str(bhr_exe), "--extract-pid", str(pid)]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if res.returncode == 0 and res.stdout.strip():
                    return json.loads(res.stdout)
            except Exception as e:
                print(f"[RamPagefileExtractor] Process RAM scan error: {e}")

        return []

    @staticmethod
    def extract_keys_from_hiberfile(hiberfile_path: str = r"C:\hiberfil.sys") -> List[Dict[str, Any]]:
        """
        Scans hiberfil.sys (Windows Hibernate File) for encryption keys if present.
        """
        bhr_exe = Path("bhr_identify.exe")
        if not bhr_exe.exists():
            bhr_exe = Path("BHR/build/bhr_identify.exe")

        if not Path(hiberfile_path).exists():
            return []

        if bhr_exe.exists():
            try:
                cmd = [str(bhr_exe), "--extract-pagefile", hiberfile_path]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                if res.returncode == 0 and res.stdout.strip():
                    return json.loads(res.stdout)
            except Exception as e:
                print(f"[RamPagefileExtractor] Hiberfile scan error: {e}")

        return []

