# Stage 01: Raw Dataset Overview & Ingestion

**Location**: `docs/stages/01_data_overview/`  
**Primary Notebook**: [`ml/notebooks/01_dataset_overview.ipynb`](../../../ml/notebooks/01_dataset_overview.ipynb)  
**Status**: ✅ Completed

---

## 🎯 Stage Objectives

1. Survey the raw CSV dumps for the three primary intrusion detection datasets:
   * **CIC-IDS2017**: 8 individual day files.
   * **CSE-CIC-IDS2018**: 10 individual day files on AWS.
   * **UNSW-NB15**: 4 raw CSV parts + feature names dictionary.
2. Verify file sizes, row counts, memory footprints, and header naming formats.
3. Establish data directory layout under `ml/data/raw/` and `ml/data/interim/`.

---

## 📊 Summary of Discovered Metrics

| Dataset | Raw Source Structure | Est. Flow Count | Raw Features | Raw Disk Size |
| :--- | :--- | :--- | :--- | :--- |
| **CIC-IDS2017** | 8 Daily CSVs | $2,830,743$ | 80 columns | $\sim 1.08\text{ GB}$ |
| **CSE-CIC-IDS2018** | 10 Daily CSVs | $16,232,943$ | 80 columns | $\sim 6.79\text{ GB}$ |
| **UNSW-NB15** | 4 Partitioned CSVs | $2,540,047$ (raw) | 49 columns | $\sim 339\text{ MB}$ |
