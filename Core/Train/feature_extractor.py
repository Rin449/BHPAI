import json
import math
import os
from pathlib import Path
from typing import Any

import numpy as np

try:
    from sandbox_feature_utils import merge_sandbox_features
except ImportError:  # pragma: no cover
    def merge_sandbox_features(data, sample_path=None):
        return data

API_NGRAM_PREFIX = "api_ng__"
DISABLE_GNN_EMBEDDINGS = os.getenv('DISABLE_GNN_EMBEDDINGS', '1').lower() in {'1', 'true', 'yes', 'on'}
DISABLE_SEQ_EMBEDDINGS = os.getenv('DISABLE_SEQ_EMBEDDINGS', '0').lower() in {'1', 'true', 'yes', 'on'}


def extract_features_from_json(data: Any, api_ngram_vocab=None, sample_path: str | None = None) -> dict:
    if isinstance(data, (str, Path)):
        with open(data, "r", encoding="utf-8") as handle:
            data = json.load(handle)

    if isinstance(data, dict):
        data = merge_sandbox_features(data, sample_path=sample_path)

    features = {}

    # === BHPAI-SE Symbolic Execution Features & Coverage Metrics ===
    se_info = data.get("se", data.get("symbolic_execution", {})) if isinstance(data, dict) else {}
    features["se_enabled"] = int(bool(se_info.get("enabled", False)))
    features["se_status_completed"] = int(se_info.get("execution_status") == "completed")
    features["se_status_budget_exhausted"] = int(se_info.get("execution_status") == "budget_exhausted")
    features["se_artifacts_count"] = se_info.get("discovered_artifacts_count", 0)
    features["se_best_priority_score"] = float(se_info.get("best_path_priority_score", 0.0))
    features["se_tainted_branches"] = se_info.get("best_path_tainted_branches", 0)
    features["se_xor_loops"] = se_info.get("best_path_xor_loops", 0)

    features["se_blocks_visited"] = se_info.get("blocks_visited", 0)
    features["se_edges_visited"] = se_info.get("edges_visited", 0)
    features["se_unique_states"] = se_info.get("unique_states", 0)
    features["se_sat_paths"] = se_info.get("sat_paths", 0)
    features["se_unsat_paths"] = se_info.get("unsat_paths", 0)
    features["se_pruned_paths"] = se_info.get("pruned_paths", 0)
    features["se_max_depth"] = se_info.get("max_depth", 0)
    features["se_solver_calls"] = se_info.get("solver_calls", 0)
    features["se_solver_cache_hits"] = se_info.get("solver_cache_hits", 0)
    features["se_time_ms"] = float(se_info.get("time_ms", 0.0))

    features["code_section_entropy"] = data.get("code_section_entropy", 0.0)
    features["relocation_entropy"] = data.get("relocation_entropy", 0.0)
    features["code_ratio"] = data.get("code_ratio", 0.0)

    sections = data.get("sections", [])
    features["num_sections"] = data.get("num_sections", len(sections))
    if sections:
        entropies = [s.get("entropy", 0) for s in sections]
        features["max_section_entropy"] = max(entropies) if entropies else 0.0
        features["min_section_entropy"] = min(entropies) if entropies else 0.0
        features["mean_section_entropy"] = float(np.mean(entropies))
        features["std_section_entropy"] = float(np.std(entropies)) if len(entropies) > 1 else 0.0
    else:
        features["max_section_entropy"] = 0.0
        features["min_section_entropy"] = 0.0
        features["mean_section_entropy"] = 0.0
        features["std_section_entropy"] = 0.0

    features["overlay_size_bytes"] = data.get("overlay_size_bytes", 0)
    features["resource_size"] = data.get("resource_size", 0)
    features["num_resources"] = data.get("num_resources", 0)
    features["resource_entropy"] = data.get("resource_entropy", 0.0)
    size_bytes = data.get("size_bytes", 1)
    features["overlay_ratio"] = features["overlay_size_bytes"] / max(1, size_bytes)
    features["resource_ratio"] = features["resource_size"] / max(1, size_bytes)

    features["resource_total"] = data.get("resource_total", 0)
    features["resource_icon_count"] = data.get("resource_icon_count", 0)
    features["resource_cursor_count"] = data.get("resource_cursor_count", 0)
    features["resource_bitmap_count"] = data.get("resource_bitmap_count", 0)
    features["resource_dialog_count"] = data.get("resource_dialog_count", 0)
    features["resource_menu_count"] = data.get("resource_menu_count", 0)
    features["resource_stringtable_count"] = data.get("resource_stringtable_count", 0)
    features["resource_accelerator_count"] = data.get("resource_accelerator_count", 0)
    features["resource_manifest_count"] = data.get("resource_manifest_count", 0)
    features["resource_version_count"] = data.get("resource_version_count", 0)
    features["resource_rcdata_count"] = data.get("resource_rcdata_count", 0)
    features["resource_other_count"] = data.get("resource_other_count", 0)
    features["resource_entropy_mean"] = data.get("resource_entropy_mean", 0.0)
    features["resource_entropy_max"] = data.get("resource_entropy_max", 0.0)
    features["resource_entropy_std"] = data.get("resource_entropy_std", 0.0)

    manifest_present = int(bool(data.get("manifest_present", False)))
    manifest_size = data.get("manifest_size", 0)
    features["manifest_present"] = manifest_present
    features["manifest_size_log"] = float(np.log1p(manifest_size)) if manifest_present else 0.0
    features["manifest_entropy"] = data.get("manifest_entropy", 0.0)

    if "manifest_execution_level" in data:
        features["manifest_execution_level"] = data["manifest_execution_level"]
    elif data.get("manifest_requested_admin"):
        features["manifest_execution_level"] = 3
    else:
        features["manifest_execution_level"] = 0

    features["manifest_uiaccess"] = int(bool(data.get("manifest_uiaccess", False)))
    features["manifest_auto_elevate"] = int(bool(data.get("manifest_auto_elevate", False)))
    features["manifest_requested_privilege"] = data.get("manifest_requested_privilege", 0)
    features["manifest_has_dpi"] = int(bool(data.get("manifest_has_dpi", False)))
    features["manifest_has_com"] = int(bool(data.get("manifest_has_com", False)))
    features["manifest_has_dependencies"] = int(bool(data.get("manifest_has_dependencies", False)))
    features["manifest_dependency_count"] = data.get("manifest_dependency_count", 0)

    features["certificate_present"] = int(bool(data.get("certificate_present", False)))
    if "certificate_count" in data:
        features["certificate_count"] = data["certificate_count"]
    elif features["certificate_present"] or data.get("certificate_size", 0) > 0:
        features["certificate_count"] = 1
    else:
        features["certificate_count"] = 0

    features["has_version_info"] = int(bool(data.get("has_version_info", False)))
    features["version_company_name_length"] = data.get("version_company_name_length", 0)
    features["version_product_name_length"] = data.get("version_product_name_length", 0)
    features["version_description_length"] = data.get("version_description_length", 0)
    features["version_original_filename_len"] = data.get("version_original_filename_len", 0)
    features["version_product_version_len"] = data.get("version_product_version_len", 0)

    features["rich_header_present"] = int(bool(data.get("rich_header_present", False)))
    features["rich_header_entries"] = data.get("rich_header_entries", 0)
    features["rich_has_vs2015"] = int(bool(data.get("rich_has_vs2015", False)))
    features["rich_has_vs2017"] = int(bool(data.get("rich_has_vs2017", False)))
    features["rich_has_vs2019"] = int(bool(data.get("rich_has_vs2019", False)))
    features["rich_has_vs2022"] = int(bool(data.get("rich_has_vs2022", False)))
    features["rich_has_masm"] = int(bool(data.get("rich_has_masm", False)))
    features["rich_has_cvtres"] = int(bool(data.get("rich_has_cvtres", False)))

    features["import_function_count"] = data.get("import_function_count", 0)
    features["import_rva"] = data.get("import_rva", 0)
    features["import_size"] = data.get("import_size", 0)
    features["suspicious_api_count"] = data.get("suspicious_api_count", 0)
    features["suspicious_api_ratio"] = data.get("suspicious_api_ratio", 0.0)
    features["has_imphash"] = int(bool(data.get("imphash", "")))

    byte_hist = data.get("byte_histogram", [])
    for i in range(256):
        features[f"byte_hist_{i}"] = float(byte_hist[i]) if i < len(byte_hist) else 0.0
    features["zero_byte_ratio"] = data.get("zero_byte_ratio", 0.0)

    entropy_hist = data.get("byte_entropy_histogram", [])
    for i in range(16):
        features[f"byte_entropy_{i}"] = float(entropy_hist[i]) if i < len(entropy_hist) else 0.0

    entropy_mat = data.get("byte_entropy_matrix", [])
    for i in range(256):
        features[f"byte_entropy_mat_{i}"] = float(entropy_mat[i]) if i < len(entropy_mat) else 0.0

    features["windowed_entropy_mean"] = data.get("windowed_entropy_mean", 0.0)
    features["windowed_entropy_max"] = data.get("windowed_entropy_max", 0.0)
    features["windowed_entropy_min"] = data.get("windowed_entropy_min", 0.0)
    features["windowed_entropy_std"] = data.get("windowed_entropy_std", 0.0)

    markov_mat = data.get("nibble_transition_matrix", [])
    for i in range(256):
        features[f"markov_trans_{i}"] = float(markov_mat[i]) if i < len(markov_mat) else 0.0
    features["markov_matrix_entropy"] = data.get("markov_matrix_entropy", 0.0)

    features["export_count"] = data.get("export_count", 0)
    features["export_named_count"] = data.get("export_named_count", 0)
    features["export_ordinal_only_count"] = data.get("export_ordinal_only_count", 0)
    features["export_name_entropy_mean"] = data.get("export_name_entropy_mean", 0.0)
    features["export_name_entropy_max"] = data.get("export_name_entropy_max", 0.0)
    features["export_name_entropy_min"] = data.get("export_name_entropy_min", 0.0)
    features["export_name_entropy_std"] = data.get("export_name_entropy_std", 0.0)
    features["has_export_table"] = int(features["export_count"] > 0)
    features["has_export_name_hash"] = int(bool(data.get("export_name_hash", "")))

    api_flags = [
        "has_VirtualAlloc", "has_VirtualProtect", "has_WriteProcessMemory",
        "has_ReadProcessMemory", "has_CreateRemoteThread", "has_NtMapViewOfSection",
        "has_QueueUserAPC", "has_WinExec", "has_ShellExecute", "has_LoadLibrary",
        "has_GetProcAddress", "has_InternetOpen", "has_WinHttpOpen",
        "has_CryptEncrypt", "has_BCryptEncrypt"
    ]
    for flag in api_flags:
        features[flag] = int(bool(data.get(flag, False)))

    features["e_lfanew"] = data.get("e_lfanew", 0)
    features["entry_point_rva"] = data.get("entry_point_rva", 0)
    features["file_alignment"] = data.get("file_alignment", 0)
    features["image_base"] = data.get("image_base", 0)
    features["machine"] = data.get("machine", 0)
    features["magic"] = data.get("magic", 0)

    # Additional Static PE Header Fields
    features["section_alignment"] = data.get("section_alignment", 0)
    features["major_linker_version"] = data.get("major_linker_version", 0)
    features["minor_linker_version"] = data.get("minor_linker_version", 0)
    features["major_os_version"] = data.get("major_os_version", 0)
    features["minor_os_version"] = data.get("minor_os_version", 0)
    features["major_subsystem_version"] = data.get("major_subsystem_version", 0)
    features["minor_subsystem_version"] = data.get("minor_subsystem_version", 0)
    features["size_of_code"] = data.get("size_of_code", 0)
    features["size_of_initialized_data"] = data.get("size_of_initialized_data", 0)
    features["size_of_uninitialized_data"] = data.get("size_of_uninitialized_data", 0)
    features["size_of_image"] = data.get("size_of_image", 0)
    features["size_of_headers"] = data.get("size_of_headers", 0)
    features["subsystem"] = data.get("subsystem", 0)
    features["dll_characteristics"] = data.get("dll_characteristics", 0)
    features["characteristics"] = data.get("characteristics", 0)
    features["time_date_stamp"] = data.get("time_date_stamp", 0)
    features["size_of_optional_header"] = data.get("size_of_optional_header", 0)

    bool_flags = [
        "alignment_weird", "aslr_enabled", "cfg_enabled", "checksum_zero",
        "digital_signature_valid", "e_lfanew_not_aligned", "e_lfanew_too_large",
        "has_debug", "has_http_post_exfil", "has_luhn_or_cc_validation",
        "has_mutex_persistence", "has_signature", "has_tls", "has_track_pattern_strings",
        "is_console", "is_dll", "is_fsg", "is_gui", "is_invalid_dos", "is_upx",
        "is_wwpack", "likely_pos_scraper", "no_imports", "nx_enabled",
        "has_memory_scraping_apis", "timestamp_zero_or_future", "os_version_low"
    ]
    for flag in bool_flags:
        features[flag] = int(bool(data.get(flag, False)))

    # Delay import stats
    features["delay_import_count"] = data.get("delay_import_count", 0)
    features["delay_import_functions"] = data.get("delay_import_functions", 0)
    features["no_delay_imports"] = int(bool(data.get("no_delay_imports", False)))

    # CBPRA (Cross-Binary Pointer Resolution Analysis) Features
    cbpra = data.get("cbpra", {})
    features["cbpra_build_success"] = int(bool(cbpra.get("build_success", False)))
    features["cbpra_total_candidates"] = cbpra.get("total_candidates", 0)
    features["cbpra_aligned_candidates"] = cbpra.get("aligned_candidates", 0)
    features["cbpra_non_insn_candidates"] = cbpra.get("non_insn_candidates", 0)
    features["cbpra_low_entropy_candidates"] = cbpra.get("low_entropy_candidates", 0)
    features["cbpra_reloc_confirmed"] = cbpra.get("reloc_confirmed", 0)
    features["cbpra_iat_confirmed"] = cbpra.get("iat_confirmed", 0)
    features["cbpra_tls_confirmed"] = cbpra.get("tls_confirmed", 0)
    features["cbpra_pdata_confirmed"] = cbpra.get("pdata_confirmed", 0)
    features["cbpra_points_to_code"] = cbpra.get("points_to_code", 0)
    features["cbpra_chain_depth1_count"] = cbpra.get("chain_depth1_count", 0)
    features["cbpra_chain_depth2_count"] = cbpra.get("chain_depth2_count", 0)
    features["cbpra_chain_depth3_plus_count"] = cbpra.get("chain_depth3_plus_count", 0)
    features["cbpra_max_chain_depth"] = cbpra.get("max_chain_depth", 0)
    features["cbpra_vtable_candidate_count"] = cbpra.get("vtable_candidate_count", 0)
    features["cbpra_graph_node_count"] = cbpra.get("graph_node_count", 0)
    features["cbpra_graph_edge_count"] = cbpra.get("graph_edge_count", 0)
    features["cbpra_cross_section"] = cbpra.get("cross_section", 0)
    features["cbpra_cross_ratio"] = float(cbpra.get("cross_ratio", 0.0))
    features["cbpra_aligned_ratio"] = float(cbpra.get("aligned_ratio", 0.0))
    features["cbpra_reloc_ratio"] = float(cbpra.get("reloc_ratio", 0.0))
    features["cbpra_code_pointer_ratio"] = float(cbpra.get("code_pointer_ratio", 0.0))
    features["cbpra_chain_depth2_plus_ratio"] = float(cbpra.get("chain_depth2_plus_ratio", 0.0))
    features["cbpra_residual_entropy_mean"] = float(cbpra.get("residual_entropy_mean", 0.0))
    features["cbpra_residual_entropy_stddev"] = float(cbpra.get("residual_entropy_stddev", 0.0))
    sec_pairs = cbpra.get("section_pairs", {})
    features["cbpra_section_pair_count"] = len(sec_pairs) if isinstance(sec_pairs, dict) else 0

    # Section Anomalies
    if sections:
        wx_count = 0
        raw_vsize_ratios = []
        high_ent_count = 0
        for s in sections:
            ent = s.get("entropy", 0.0)
            if ent > 7.0:
                high_ent_count += 1
            chars = s.get("characteristics", 0)
            if (chars & 0x80000000) and (chars & 0x20000000):  # WRITE & EXECUTE
                wx_count += 1
            rsize = s.get("raw_size", 0)
            vsize = s.get("virtual_size", 0)
            if rsize > 0:
                raw_vsize_ratios.append(vsize / rsize)
        features["section_wx_count"] = wx_count
        features["section_high_entropy_count"] = high_ent_count
        features["section_vsize_vs_raw_ratio_mean"] = float(np.mean(raw_vsize_ratios)) if raw_vsize_ratios else 0.0
    else:
        features["section_wx_count"] = 0
        features["section_high_entropy_count"] = 0
        features["section_vsize_vs_raw_ratio_mean"] = 0.0

    for key, value in data.items():
        if not key.startswith("sandbox_"):
            continue
        if isinstance(value, bool):
            features[key] = int(value)
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            features[key] = value

    ngrams = data.get("top_suspicious_ngrams", [])
    features["top_suspicious_ngrams_count"] = len(ngrams)
    features["suspicious_ngrams_high_count"] = sum(1 for n in ngrams if n.get("count", 0) > 100)
    features["suspicious_ngrams_total_weight"] = sum(n.get("weight", 0.0) for n in ngrams)

    opcode_info = data.get("opcode_ngrams", {})
    features["opcode_ngrams_total"] = opcode_info.get("total_ngrams_found", len(opcode_info.get("opcode_ngrams", [])))
    features["approx_instructions_analyzed"] = opcode_info.get("approx_instructions_analyzed", 0)

    semantic_histogram = data.get("semantic_group_histogram", {})
    for group in ("DATA_XFER", "ARITHMETIC", "LOGIC", "CMP", "CONTROL_FLOW",
                  "SIMD", "CRYPTO", "STRING_OP", "OTHER"):
        features[f"opcode_semantic_{group.lower()}"] = semantic_histogram.get(group, 0)

    opcode_tfidf = data.get("opcode_tfidf", [])
    tfidf_scores = [item.get("score", 0.0) for item in opcode_tfidf]
    features["opcode_tfidf_term_count"] = len(tfidf_scores)
    features["opcode_tfidf_score_sum"] = sum(tfidf_scores)
    features["opcode_tfidf_score_max"] = max(tfidf_scores, default=0.0)
    features["opcode_tfidf_score_mean"] = float(np.mean(tfidf_scores)) if tfidf_scores else 0.0

    cfg_info = data.get("CFG", data.get("cfg", {}))
    features["cfg_build_success"] = int(bool(cfg_info.get("build_success", False)))
    features["cfg_num_basic_blocks"] = cfg_info.get("num_basic_blocks", 0)
    features["cfg_num_edges"] = cfg_info.get("num_edges", 0)
    features["cfg_cyclomatic_complexity"] = cfg_info.get("cyclomatic_complexity", 0)
    features["cfg_average_out_degree"] = cfg_info.get("average_out_degree", 0.0)
    features["cfg_average_in_degree"] = cfg_info.get("average_in_degree", 0.0)
    features["cfg_max_out_degree"] = cfg_info.get("max_out_degree", 0)
    features["cfg_max_call_depth"] = cfg_info.get("max_call_depth", 0)
    features["cfg_recursive_function_count"] = cfg_info.get("recursive_function_count", 0)
    features["cfg_back_edge_ratio"] = cfg_info.get("back_edge_ratio", 0.0)
    features["cfg_jump_density"] = cfg_info.get("jump_density", 0.0)
    features["cfg_branch_density"] = cfg_info.get("branch_density", 0.0)
    features["cfg_indirect_control_flow"] = cfg_info.get("indirect_control_flow", 0)
    features["cfg_indirect_call_ratio"] = cfg_info.get("indirect_call_ratio", 0.0)
    features["cfg_call_count"] = cfg_info.get("call_count", 0)
    features["cfg_avg_block_size"] = cfg_info.get("avg_block_size", 0.0)
    features["cfg_has_loops"] = int(bool(cfg_info.get("has_loops", False)))
    features["cfg_unreachable_blocks"] = cfg_info.get("unreachable_blocks", 0)
    features["tls_callback_count"] = data.get("tls_callback_count", 0)

    str_info = data.get("string_analysis", {})
    features["total_strings"] = str_info.get("total_strings_found", 0)
    interesting = str_info.get("interesting_strings", [])
    features["interesting_strings_count"] = len(interesting)
    features["interesting_strings_ratio"] = len(interesting) / max(1, features["total_strings"])
    string_stats = str_info.get("string_stats", {})
    features["ascii_string_count"] = string_stats.get("ascii_count", 0)
    features["unicode_string_count"] = string_stats.get("unicode_count", 0)
    features["string_avg_length"] = string_stats.get("avg_length", 0.0)
    features["string_median_length"] = string_stats.get("median_length", 0.0)
    features["string_avg_entropy"] = string_stats.get("avg_entropy", 0.0)
    features["string_printable_ratio"] = string_stats.get("printable_ratio", 0.0)
    features["string_unicode_ratio"] = string_stats.get("unicode_ratio", 0.0)

    api_ng: dict = data.get("api_ngrams", {})
    for ng in api_ngram_vocab or []:
        col = API_NGRAM_PREFIX + ng
        features[col] = api_ng.get(ng, 0)

    seq = data.get("api_sequence", [])
    seq_len = data.get("api_seq_length", len(seq))
    if seq_len is None or seq_len < 0:
        seq_len = len(seq)
    features["api_seq_length"] = int(seq_len)

    unique_calls = data.get("api_unique_calls", len(set(seq)) if seq else 0)
    if unique_calls is None or unique_calls < 0:
        unique_calls = len(set(seq)) if seq else 0
    features["api_unique_calls"] = int(unique_calls)

    if "api_repeat_ratio" in data and data["api_repeat_ratio"] is not None:
        repeat_ratio = data["api_repeat_ratio"]
        if not np.isfinite(repeat_ratio):
            repeat_ratio = 0.0
    else:
        repeat_ratio = (1.0 - unique_calls / max(1, seq_len) if seq_len > 0 else 0.0)
    features["api_repeat_ratio"] = float(repeat_ratio)
    features["api_sequence_present"] = int(bool(seq))

    counts = np.array(list(api_ng.values())) if api_ng else np.array([])
    if len(counts) > 0 and counts.sum() > 0:
        probs = counts / counts.sum()
        features["api_entropy"] = float(-np.sum(probs * np.log2(probs + 1e-12)))
    else:
        features["api_entropy"] = 0.0

    transitions = [(seq[i], seq[i + 1]) for i in range(len(seq) - 1)]
    features["api_total_transitions"] = len(transitions)
    features["api_unique_transitions"] = len(set(transitions))
    out_deg = {}
    loop_cnt = 0
    for src, dst in transitions:
        out_deg.setdefault(src, set()).add(dst)
        if src == dst:
            loop_cnt += 1
    features["api_avg_out_degree"] = float(np.mean([len(t) for t in out_deg.values()])) if out_deg else 0.0
    features["api_loop_ratio"] = loop_cnt / max(len(transitions), 1)
    features["api_repeated_transition_ratio"] = (len(transitions) - len(set(transitions))) / max(len(transitions), 1)

    # === GNN Behavioral Graph Features ===
    bg_data = data.get("behavioral_graph", {})
    features["behavioral_graph_build_success"] = int(bool(bg_data.get("build_success", False)))
    features["behavioral_graph_num_nodes"] = bg_data.get("num_nodes", 0)
    features["behavioral_graph_num_edges"] = bg_data.get("num_edges", 0)

    if DISABLE_GNN_EMBEDDINGS:
        for idx in range(64):
            features[f"gnn_embed_{idx}"] = 0.0
        features['gnn_embedding_norm'] = 0.0
    else:
        try:
            from gnn_embedder import extract_gnn_embedding
            gnn_vector = extract_gnn_embedding(bg_data)
            # Quick sanity check: expose embedding norm for debugging/troubleshooting
            try:
                import numpy as _np
                norm = float(_np.linalg.norm(gnn_vector))
                # Attach a debug field so downstream training can log or inspect it
                features['gnn_embedding_norm'] = norm
            except Exception:
                features['gnn_embedding_norm'] = 0.0
            for idx, val in enumerate(gnn_vector):
                features[f"gnn_embed_{idx}"] = float(val)
        except Exception:
            for idx in range(64):
                features[f"gnn_embed_{idx}"] = 0.0
            features['gnn_embedding_norm'] = 0.0

    # === API Sequence Embedding Features ===
    if DISABLE_SEQ_EMBEDDINGS:
        for idx in range(32):
            features[f"seq_embed_{idx}"] = 0.0
        features['seq_embedding_norm'] = 0.0
    else:
        try:
            from api_sequence_embedder import extract_sequence_embedding, API_SEQ_EMBEDDING_DIM
            seq_vec = extract_sequence_embedding(seq)
            norm = float(np.linalg.norm(seq_vec)) if len(seq_vec) > 0 else 0.0
            features['seq_embedding_norm'] = norm
            for idx, val in enumerate(seq_vec):
                features[f"seq_embed_{idx}"] = float(val)
        except Exception:
            for idx in range(32):
                features[f"seq_embed_{idx}"] = 0.0
            features['seq_embedding_norm'] = 0.0

    return features

