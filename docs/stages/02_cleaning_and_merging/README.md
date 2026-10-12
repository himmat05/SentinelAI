# Stage 02: Dataset Inspection, Cleaning & Interim Merging

**Location**: `docs/stages/02_cleaning_and_merging/`  
**Primary Notebooks**: 
* [`ml/notebooks/02_IDS2018_Inspection_and_Merging.ipynb`](../../../ml/notebooks/02_IDS2018_Inspection_and_Merging.ipynb)
* [`ml/notebooks/03_UNSW_NB15_Inspection_and_Merging.ipynb`](../../../ml/notebooks/03_UNSW_NB15_Inspection_and_Merging.ipynb)  
**Status**: ✅ Completed

---

## 🎯 Stage Objectives

1. Handle out-of-memory constraints when combining multi-gigabyte raw files.
2. Clean encoding artifacts (e.g. UTF-8 Byte Order Marks `\ufeff`).
3. Sanitize corrupt or mixed-type fields:
   * Parse hex ports (e.g., `0x000b`) and strings to standard integers.
   * Clean `ct_ftp_cmd`, impute `ct_flw_http_mthd`, and binarize `is_ftp_login`.
   * Standardize attack names (e.g. harmonize `'Backdoors'` to `'Backdoor'`).
4. Execute memory-efficient chunked streaming merges to generate compressed Parquet interim tables:
   * `ml/data/interim/CIC-IDS2017/cicids2017_merged_raw.parquet`
   * `ml/data/interim/CSE-CIC-IDS2018/cse-cic-ids2018_merged_raw.parquet`
   * `ml/data/interim/UNSW-NB15/unsw_nb15_merged_clean.parquet`
