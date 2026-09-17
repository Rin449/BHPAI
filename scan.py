#!/usr/bin/env python3
"""
BHPAI Folder & Dataset PE Scanner Utility (scan.py)
Scans directories, dataset folders (malware/benign), or single files recursively
using pe_analyzer.exe / pe.exe with integrated BHPAI-SE.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Generator, List, Dict, Any


def find_analyzer() -> Path | None:
    """Find pe_analyzer.exe or pe.exe in workspace or PATH."""
    candidates = [
        Path("pe_analyzer.exe"),
        Path("pe.exe"),
        Path("build/pe_analyzer.exe"),
        Path("release/bin/pe_analyzer.exe"),
        Path("Core/scanner/pe_analyzer.exe"),
    ]
    for candidate in candidates:
        if candidate.exists() and candidate.is_file():
            return candidate.resolve()
    
    # Try finding in PATH
    for path_dir in os.environ.get("PATH", "").split(os.pathsep):
        p = Path(path_dir) / "pe_analyzer.exe"
        if p.exists() and p.is_file():
            return p.resolve()

    return None


def find_target_files(root: Path, extensions: tuple = (".exe", ".dll", ".sys")) -> Generator[Path, None, None]:
    """Recursively find executable PE files, skipping system and build folders."""
    skip_dirs = {
        "$recycle.bin",
        "system volume information",
        "__pycache__",
        ".git",
        ".vscode",
        ".agents",
        "node_modules",
        "build",
        "release",
        "relase",
    }

    if root.is_file():
        if root.suffix.lower() in extensions or root.suffix == "":
            yield root
        return

    for current_root, dirs, files in os.walk(root, topdown=True):
        # Filter directories in-place to avoid entering skipped paths
        dirs[:] = [
            d for d in dirs
            if d.lower() not in skip_dirs
            and not d.startswith("$")
        ]

        for filename in files:
            p = Path(current_root) / filename
            if p.suffix.lower() in extensions or p.suffix == "":
                yield p


def infer_label_from_path(file_path: Path, default_label: str) -> str:
    """Infer malware/benign label automatically from directory path if not explicitly overridden."""
    if default_label != "unknown":
        return default_label

    path_parts = [p.lower() for p in file_path.parts]
    if "malware" in path_parts:
        return "malware"
    if "benign" in path_parts:
        return "benign"
    return "unknown"


def analyze_pe_file(
    exe_path: Path,
    analyzer: Path,
    label: str = "unknown",
    safe_run: bool = True,
    timeout: int = 300,
) -> Dict[str, Any]:
    """Analyze a single PE file using pe_analyzer executable."""
    eff_label = infer_label_from_path(exe_path, label)

    cmd = [
        str(analyzer),
        str(exe_path),
        eff_label,
    ]
    if safe_run:
        cmd.append("--safe-run")

    start_time = time.time()
    info: Dict[str, Any] = {
        "file": str(exe_path),
        "filename": exe_path.name,
        "label": eff_label,
        "status": "error",
        "returncode": -1,
        "time_seconds": 0.0,
        "json_report": None,
        "se_status": "none",
        "se_artifacts": 0,
        "score": None,
    }

    try:
        result = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        elapsed = time.time() - start_time
        info["time_seconds"] = round(elapsed, 2)
        info["returncode"] = result.returncode

        if result.returncode == 0:
            info["status"] = "success"
        else:
            info["status"] = f"failed (code {result.returncode})"

        # Check for generated .json report file
        json_report_file = Path(str(exe_path) + ".json")
        if json_report_file.exists():
            try:
                with open(json_report_file, "r", encoding="utf-8", errors="ignore") as f:
                    report_data = json.load(f)
                    info["json_report"] = str(json_report_file)
                    info["score"] = report_data.get("score")
                    
                    se_data = report_data.get("se", report_data.get("symbolic_execution", {}))
                    if isinstance(se_data, dict) and se_data.get("enabled"):
                        info["se_status"] = se_data.get("execution_status", "completed")
                        info["se_artifacts"] = se_data.get("discovered_artifacts_count", 0)
            except Exception as e:
                info["json_parse_error"] = str(e)

    except subprocess.TimeoutExpired:
        info["status"] = "timeout"
        info["time_seconds"] = float(timeout)
    except Exception as exc:
        info["status"] = f"error: {exc}"

    return info


def find_dataset_folders() -> List[Path]:
    """Find malware/benign dataset folders in workspace."""
    search_roots = [
        Path("Core/Train/dataset"),
        Path("dataset"),
        Path("Core/dataset"),
    ]
    folders = []
    for root in search_roots:
        if root.exists() and root.is_dir():
            m_dir = root / "malware"
            b_dir = root / "benign"
            if m_dir.exists() and m_dir.is_dir():
                folders.append(m_dir)
            if b_dir.exists() and b_dir.is_dir():
                folders.append(b_dir)
    return folders


def main():
    parser = argparse.ArgumentParser(
        description="BHPAI Folder & Dataset PE Scanner: Recursively analyze executable files with pe_analyzer & BHPAI-SE."
    )
    parser.add_argument(
        "targets",
        nargs="*",
        default=[],
        help="Directory, dataset folder, or single PE file to scan.",
    )
    parser.add_argument(
        "--dataset",
        action="store_true",
        help="Automatically scan dataset/malware and dataset/benign folders.",
    )
    parser.add_argument(
        "--analyzer",
        default=None,
        help="Path to pe_analyzer executable (auto-detected if omitted).",
    )
    parser.add_argument(
        "--label",
        default="unknown",
        choices=["unknown", "malware", "benign"],
        help="Explicit label tag (auto-inferred from path if left unknown).",
    )
    parser.add_argument(
        "--no-safe-run",
        action="store_true",
        help="Disable --safe-run mode (removes resource memory limits).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=120,
        help="Maximum seconds per file analysis (default: 120s).",
    )
    parser.add_argument(
        "--output-summary",
        default=None,
        help="Save consolidated scan summary JSON to specified file.",
    )
    parser.add_argument(
        "--ext",
        default=".exe,.dll,.sys",
        help="Comma-separated file extensions to scan (default: .exe,.dll,.sys).",
    )

    args = parser.parse_args()

    # Resolve analyzer binary
    analyzer_path = Path(args.analyzer).resolve() if args.analyzer else find_analyzer()
    if not analyzer_path or not analyzer_path.exists():
        print("[!] Could not locate pe_analyzer.exe! Please compile the project or specify --analyzer path.")
        sys.exit(1)

    target_paths: List[Path] = []
    if args.dataset:
        target_paths.extend(find_dataset_folders())

    for t in args.targets:
        p = Path(t).expanduser().resolve()
        if p.exists():
            target_paths.append(p)

    if not target_paths and not args.dataset:
        # Default fallback: check if dataset folders exist, else scan current dir
        ds_folders = find_dataset_folders()
        if ds_folders:
            target_paths.extend(ds_folders)
        else:
            target_paths.append(Path(".").resolve())

    extensions = tuple(e_item.strip().lower() if e_item.strip().startswith(".") else f".{e_item.strip().lower()}" for e_item in args.ext.split(","))

    print("=" * 80)
    print("                BHPAI SECURITY CONSOLE - DATASET & FOLDER PE SCANNER")
    print("=" * 80)
    print(f"[*] Analyzer    : {analyzer_path}")
    print(f"[*] Targets     : {', '.join(str(tp) for tp in target_paths)}")
    print(f"[*] Label Mode  : {args.label}")
    print(f"[*] Safe Run    : {not args.no_safe_run}")
    print(f"[*] Extensions  : {', '.join(extensions)}")
    print(f"[*] Timeout     : {args.timeout}s per file")
    print("=" * 80)

    files_to_scan: List[Path] = []
    for tp in target_paths:
        for f in find_target_files(tp, extensions=extensions):
            if f not in files_to_scan:
                files_to_scan.append(f)

    print(f"[*] Discovered {len(files_to_scan)} executable file(s) for scanning.\n")

    if not files_to_scan:
        print("[+] No matching files found to scan.")
        return

    results: List[Dict[str, Any]] = []
    summary_counts = {"success": 0, "timeout": 0, "error": 0}

    for idx, exe in enumerate(files_to_scan, 1):
        print(f"[{idx}/{len(files_to_scan)}] Scanning: {exe.name} (path: {exe}) ...", end="", flush=True)

        res = analyze_pe_file(
            exe_path=exe,
            analyzer=analyzer_path,
            label=args.label,
            safe_run=not args.no_safe_run,
            timeout=args.timeout,
        )
        results.append(res)

        if res["status"] == "success":
            summary_counts["success"] += 1
            se_str = f" [SE: {res['se_status']}, Artifacts: {res['se_artifacts']}]" if res['se_status'] != "none" else ""
            score_str = f" Score={res['score']}" if res['score'] is not None else ""
            print(f" OK ({res['time_seconds']}s) [Label: {res['label']}]{score_str}{se_str}")
        elif res["status"] == "timeout":
            summary_counts["timeout"] += 1
            print(f" TIMEOUT ({args.timeout}s)")
        else:
            summary_counts["error"] += 1
            print(f" FAILED ({res['status']})")

    print("\n" + "=" * 80)
    print("                        BHPAI SCAN SUMMARY")
    print("=" * 80)
    print(f" Total Files Analyzed : {len(files_to_scan)}")
    print(f" Successful Scans     : {summary_counts['success']}")
    print(f" Timeouts             : {summary_counts['timeout']}")
    print(f" Errors/Failures      : {summary_counts['error']}")
    print("=" * 80)

    if args.output_summary:
        summary_file = Path(args.output_summary).resolve()
        payload = {
            "targets": [str(tp) for tp in target_paths],
            "total_files": len(files_to_scan),
            "summary": summary_counts,
            "results": results,
        }
        with open(summary_file, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        print(f"[+] Consolidated scan summary written to: {summary_file}")


if __name__ == "__main__":
    main()
