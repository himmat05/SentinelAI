# Stage 03: Inter-Dataset Inspection & Merging Strategy

**Location**: `docs/stages/03_inter_dataset_inspection/`  
**Primary Notebook**: [`ml/notebooks/04_Inter_dataset_inspection.ipynb`](../../../ml/notebooks/04_Inter_dataset_inspection.ipynb)  
**Status**: ✅ Completed

---

## 🎯 Stage Objectives

1. Load and compare the schemas of all three interim benchmark datasets (**CIC-IDS2017**, **CSE-CIC-IDS2018**, and **UNSW-NB15**).
2. Quantify literal string intersections vs semantic feature overlaps.
3. Discover and mathematically resolve unit/scale divergences ($\mu s$ vs $s$ vs $ms$, bits vs bytes, 8-bit vs 16-bit windows).
4. Perform 9-metric statistical distribution profiling and correlation consistency analysis across datasets.
5. Standardize binary target labels and design canonical multi-class attack taxonomy.
6. Classify every candidate feature into the **5-Category Merging Framework (A, B, C, D, E)**.

---

## 📑 Core Documentation in this Folder

* **[04_inter_dataset_inspection_and_merging_strategy.md](04_inter_dataset_inspection_and_merging_strategy.md)**: The complete architectural report detailing:
  * Full breakdown of all 49 UNSW-NB15 features and 80 CIC-IDS features.
  * The 5-Category Merging Strategy (Categories A, B, C, D, E).
  * The 8 critical pre-training traps (time scale gaps, timeout caps, string casing, 2018 typos, skewness).
  * 16-feature unified core blueprint + preprocessing recommendations.
* **Manifest Artifact**: [`ml/data/interim/unified_merging_manifest.json`](../../../ml/data/interim/unified_merging_manifest.json) containing machine-readable mapping rules.
