"""
SentinelAI - Streaming ETL Merge Pipeline
Merges CIC-IDS2017, CSE-CIC-IDS2018, and UNSW-NB15 into ml/data/processed/merged_sentinel_core.parquet.
Features: Zero-OOM streaming, PyArrow columnar batching, microsecond-to-second unit conversions,
and canonical threat family mapping.
"""

import os
import time
import pyarrow as pa
import pyarrow.parquet as pq
import pandas as pd
import numpy as np

# Directory paths
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
INTERIM_DIR = os.path.join(BASE_DIR, "data", "interim")
PROCESSED_DIR = os.path.join(BASE_DIR, "data", "processed")
os.makedirs(PROCESSED_DIR, exist_ok=True)

PATH_2017 = os.path.join(INTERIM_DIR, "CIC-IDS2017", "cicids2017_merged_raw.parquet")
PATH_2018 = os.path.join(INTERIM_DIR, "CSE-CIC-IDS2018", "cse-cic-ids2018_merged_raw.parquet")
PATH_NB15 = os.path.join(INTERIM_DIR, "UNSW-NB15", "unsw_nb15_merged_clean.parquet")
OUTPUT_PARQUET = os.path.join(PROCESSED_DIR, "merged_sentinel_core.parquet")

BATCH_SIZE = 250000

# Canonical 19-Column Schema
UNIFIED_SCHEMA = pa.schema([
    ('source_dataset', pa.string()),
    ('dst_port', pa.int32()),
    ('flow_duration_s', pa.float32()),
    ('flow_iat_mean_s', pa.float32()),
    ('fwd_iat_mean_s', pa.float32()),
    ('bwd_iat_mean_s', pa.float32()),
    ('fwd_packets', pa.int32()),
    ('bwd_packets', pa.int32()),
    ('fwd_bytes', pa.float32()),
    ('bwd_bytes', pa.float32()),
    ('fwd_pkt_len_mean', pa.float32()),
    ('bwd_pkt_len_mean', pa.float32()),
    ('flow_bytes_per_sec', pa.float32()),
    ('flow_pkts_per_sec', pa.float32()),
    ('fwd_tcp_win_ratio', pa.float32()),
    ('bwd_tcp_win_ratio', pa.float32()),
    ('traffic_symmetry_ratio', pa.float32()),
    ('label', pa.int8()),
    ('attack_family', pa.string())
])

TAXONOMY_MAP = {
    'BENIGN': 'Normal', 'Benign': 'Normal', 'Normal': 'Normal',
    'DoS Hulk': 'DoS', 'DoS attacks-Hulk': 'DoS', 'DoS GoldenEye': 'DoS',
    'DoS attacks-GoldenEye': 'DoS', 'DoS slowloris': 'DoS', 'DoS attacks-Slowloris': 'DoS',
    'DoS Slowhttptest': 'DoS', 'DoS attacks-SlowHTTPTest': 'DoS', 'DoS': 'DoS',
    'DDoS': 'DDoS', 'DDOS attack-HOIC': 'DDoS', 'DDoS attacks-LOIC-HTTP': 'DDoS', 'DDOS attack-LOIC-UDP': 'DDoS',
    'FTP-Patator': 'Brute Force', 'SSH-Patator': 'Brute Force', 'FTP-BruteForce': 'Brute Force', 'SSH-Bruteforce': 'Brute Force',
    'PortScan': 'Reconnaissance', 'Reconnaissance': 'Reconnaissance', 'Analysis': 'Reconnaissance',
    'Bot': 'Botnet',
    'Infiltration': 'Infiltration', 'Infilteration': 'Infiltration',
    'Web Attack - Brute Force': 'Web & Exploitation', 'Web Attack - XSS': 'Web & Exploitation',
    'Web Attack - Sql Injection': 'Web & Exploitation', 'Brute Force -Web': 'Web & Exploitation',
    'Brute Force -XSS': 'Web & Exploitation', 'SQL Injection': 'Web & Exploitation',
    'Heartbleed': 'Web & Exploitation', 'Exploits': 'Web & Exploitation',
    'Fuzzers': 'Other / Fuzzing', 'Generic': 'Other / Fuzzing',
    'Backdoor': 'Infiltration', 'Shellcode': 'Web & Exploitation', 'Worms': 'Other / Fuzzing'
}

def transform_batch_2017(batch):
    df = batch.to_pandas()
    out = pd.DataFrame()
    out['source_dataset'] = ['CIC-IDS2017'] * len(df)
    out['dst_port'] = pd.to_numeric(df['Destination Port'], errors='coerce').fillna(0).astype('int32')
    out['flow_duration_s'] = (pd.to_numeric(df['Flow Duration'], errors='coerce').fillna(0) / 1e6).astype('float32')
    out['flow_iat_mean_s'] = (pd.to_numeric(df['Flow IAT Mean'], errors='coerce').fillna(0) / 1e6).astype('float32')
    out['fwd_iat_mean_s'] = (pd.to_numeric(df['Fwd IAT Mean'], errors='coerce').fillna(0) / 1e6).astype('float32')
    out['bwd_iat_mean_s'] = (pd.to_numeric(df['Bwd IAT Mean'], errors='coerce').fillna(0) / 1e6).astype('float32')
    out['fwd_packets'] = pd.to_numeric(df['Total Fwd Packets'], errors='coerce').fillna(0).astype('int32')
    out['bwd_packets'] = pd.to_numeric(df['Total Backward Packets'], errors='coerce').fillna(0).astype('int32')
    out['fwd_bytes'] = pd.to_numeric(df['Total Length of Fwd Packets'], errors='coerce').fillna(0).astype('float32')
    out['bwd_bytes'] = pd.to_numeric(df['Total Length of Bwd Packets'], errors='coerce').fillna(0).astype('float32')
    out['fwd_pkt_len_mean'] = pd.to_numeric(df['Fwd Packet Length Mean'], errors='coerce').fillna(0).astype('float32')
    out['bwd_pkt_len_mean'] = pd.to_numeric(df['Bwd Packet Length Mean'], errors='coerce').fillna(0).astype('float32')
    out['flow_bytes_per_sec'] = pd.to_numeric(df['Flow Bytes/s'], errors='coerce').replace([np.inf, -np.inf], 0).fillna(0).astype('float32')
    out['flow_pkts_per_sec'] = pd.to_numeric(df['Flow Packets/s'], errors='coerce').replace([np.inf, -np.inf], 0).fillna(0).astype('float32')
    out['fwd_tcp_win_ratio'] = (np.maximum(pd.to_numeric(df['Init_Win_bytes_forward'], errors='coerce').fillna(0), 0) / 65535.0).astype('float32')
    out['bwd_tcp_win_ratio'] = (np.maximum(pd.to_numeric(df['Init_Win_bytes_backward'], errors='coerce').fillna(0), 0) / 65535.0).astype('float32')
    tot_bytes = out['fwd_bytes'] + out['bwd_bytes']
    out['traffic_symmetry_ratio'] = (out['fwd_bytes'] / np.maximum(tot_bytes, 1e-6)).astype('float32')
    lbl_clean = df['Label'].astype(str).str.strip()
    out['label'] = (lbl_clean.str.upper() != 'BENIGN').astype('int8')
    out['attack_family'] = lbl_clean.map(TAXONOMY_MAP).fillna('Other').astype(str)
    return pa.Table.from_pandas(out, schema=UNIFIED_SCHEMA)

def transform_batch_2018(batch):
    df = batch.to_pandas()
    out = pd.DataFrame()
    out['source_dataset'] = ['CSE-CIC-IDS2018'] * len(df)
    out['dst_port'] = pd.to_numeric(df['Dst Port'], errors='coerce').fillna(0).astype('int32')
    out['flow_duration_s'] = (pd.to_numeric(df['Flow Duration'], errors='coerce').fillna(0) / 1e6).astype('float32')
    out['flow_iat_mean_s'] = (pd.to_numeric(df['Flow IAT Mean'], errors='coerce').fillna(0) / 1e6).astype('float32')
    out['fwd_iat_mean_s'] = (pd.to_numeric(df['Fwd IAT Mean'], errors='coerce').fillna(0) / 1e6).astype('float32')
    out['bwd_iat_mean_s'] = (pd.to_numeric(df['Bwd IAT Mean'], errors='coerce').fillna(0) / 1e6).astype('float32')
    out['fwd_packets'] = pd.to_numeric(df['Tot Fwd Pkts'], errors='coerce').fillna(0).astype('int32')
    out['bwd_packets'] = pd.to_numeric(df['Tot Bwd Pkts'], errors='coerce').fillna(0).astype('int32')
    out['fwd_bytes'] = pd.to_numeric(df['TotLen Fwd Pkts'], errors='coerce').fillna(0).astype('float32')
    out['bwd_bytes'] = pd.to_numeric(df['TotLen Bwd Pkts'], errors='coerce').fillna(0).astype('float32')
    out['fwd_pkt_len_mean'] = pd.to_numeric(df['Fwd Pkt Len Mean'], errors='coerce').fillna(0).astype('float32')
    out['bwd_pkt_len_mean'] = pd.to_numeric(df['Bwd Pkt Len Mean'], errors='coerce').fillna(0).astype('float32')
    out['flow_bytes_per_sec'] = pd.to_numeric(df['Flow Byts/s'], errors='coerce').replace([np.inf, -np.inf], 0).fillna(0).astype('float32')
    out['flow_pkts_per_sec'] = pd.to_numeric(df['Flow Pkts/s'], errors='coerce').replace([np.inf, -np.inf], 0).fillna(0).astype('float32')
    out['fwd_tcp_win_ratio'] = (np.maximum(pd.to_numeric(df['Init Fwd Win Byts'], errors='coerce').fillna(0), 0) / 65535.0).astype('float32')
    out['bwd_tcp_win_ratio'] = (np.maximum(pd.to_numeric(df['Init Bwd Win Byts'], errors='coerce').fillna(0), 0) / 65535.0).astype('float32')
    tot_bytes = out['fwd_bytes'] + out['bwd_bytes']
    out['traffic_symmetry_ratio'] = (out['fwd_bytes'] / np.maximum(tot_bytes, 1e-6)).astype('float32')
    lbl_clean = df['Label'].astype(str).str.strip()
    out['label'] = (lbl_clean.str.upper() != 'BENIGN').astype('int8')
    out['attack_family'] = lbl_clean.map(TAXONOMY_MAP).fillna('Other').astype(str)
    return pa.Table.from_pandas(out, schema=UNIFIED_SCHEMA)

def transform_batch_nb15(batch):
    df = batch.to_pandas()
    out = pd.DataFrame()
    out['source_dataset'] = ['UNSW-NB15'] * len(df)
    out['dst_port'] = pd.to_numeric(df['dsport'], errors='coerce').fillna(0).astype('int32')
    dur_raw = pd.to_numeric(df['dur'], errors='coerce').fillna(0).astype('float32')
    dur_safe = np.maximum(dur_raw, 1e-6)
    out['flow_duration_s'] = dur_raw
    out['flow_iat_mean_s'] = pd.to_numeric(df['tcprtt'], errors='coerce').fillna(0).astype('float32')
    out['fwd_iat_mean_s'] = (pd.to_numeric(df['Sintpkt'], errors='coerce').fillna(0) / 1e3).astype('float32')
    out['bwd_iat_mean_s'] = (pd.to_numeric(df['Dintpkt'], errors='coerce').fillna(0) / 1e3).astype('float32')
    spkts = pd.to_numeric(df['Spkts'], errors='coerce').fillna(0).astype('int32')
    dpkts = pd.to_numeric(df['Dpkts'], errors='coerce').fillna(0).astype('int32')
    sbytes = pd.to_numeric(df['sbytes'], errors='coerce').fillna(0).astype('float32')
    dbytes = pd.to_numeric(df['dbytes'], errors='coerce').fillna(0).astype('float32')
    out['fwd_packets'] = spkts
    out['bwd_packets'] = dpkts
    out['fwd_bytes'] = sbytes
    out['bwd_bytes'] = dbytes
    out['fwd_pkt_len_mean'] = pd.to_numeric(df['smeansz'], errors='coerce').fillna(0).astype('float32')
    out['bwd_pkt_len_mean'] = pd.to_numeric(df['dmeansz'], errors='coerce').fillna(0).astype('float32')
    out['flow_bytes_per_sec'] = ((sbytes + dbytes) / dur_safe).astype('float32')
    out['flow_pkts_per_sec'] = ((spkts + dpkts) / dur_safe).astype('float32')
    out['fwd_tcp_win_ratio'] = (pd.to_numeric(df['swin'], errors='coerce').fillna(0) / 255.0).astype('float32')
    out['bwd_tcp_win_ratio'] = (pd.to_numeric(df['dwin'], errors='coerce').fillna(0) / 255.0).astype('float32')
    tot_bytes = sbytes + dbytes
    out['traffic_symmetry_ratio'] = (sbytes / np.maximum(tot_bytes, 1e-6)).astype('float32')
    out['label'] = pd.to_numeric(df['Label'], errors='coerce').fillna(0).astype('int8')
    lbl_clean = df['attack_cat'].astype(str).str.strip()
    out['attack_family'] = lbl_clean.map(TAXONOMY_MAP).fillna('Other').astype(str)
    return pa.Table.from_pandas(out, schema=UNIFIED_SCHEMA)

def run_merge():
    datasets_to_stream = [
        {
            'name': 'CIC-IDS2017',
            'path': PATH_2017,
            'transform_fn': transform_batch_2017,
            'columns': [
                'Destination Port', 'Flow Duration', 'Flow IAT Mean', 'Fwd IAT Mean', 'Bwd IAT Mean',
                'Total Fwd Packets', 'Total Backward Packets', 'Total Length of Fwd Packets',
                'Total Length of Bwd Packets', 'Fwd Packet Length Mean', 'Bwd Packet Length Mean',
                'Flow Bytes/s', 'Flow Packets/s', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'Label'
            ]
        },
        {
            'name': 'CSE-CIC-IDS2018',
            'path': PATH_2018,
            'transform_fn': transform_batch_2018,
            'columns': [
                'Dst Port', 'Flow Duration', 'Flow IAT Mean', 'Fwd IAT Mean', 'Bwd IAT Mean',
                'Tot Fwd Pkts', 'Tot Bwd Pkts', 'TotLen Fwd Pkts', 'TotLen Bwd Pkts',
                'Fwd Pkt Len Mean', 'Bwd Pkt Len Mean', 'Flow Byts/s', 'Flow Pkts/s',
                'Init Fwd Win Byts', 'Init Bwd Win Byts', 'Label'
            ]
        },
        {
            'name': 'UNSW-NB15',
            'path': PATH_NB15,
            'transform_fn': transform_batch_nb15,
            'columns': [
                'dsport', 'dur', 'tcprtt', 'Sintpkt', 'Dintpkt', 'Spkts', 'Dpkts',
                'sbytes', 'dbytes', 'smeansz', 'dmeansz', 'swin', 'dwin', 'Label', 'attack_cat'
            ]
        }
    ]

    if os.path.exists(OUTPUT_PARQUET):
        os.remove(OUTPUT_PARQUET)

    print("=" * 80)
    print("🚀 SENTINELAI: STREAMING MERGE PIPELINE INITIALIZED")
    print(f"• Target Output: {OUTPUT_PARQUET}")
    print(f"• Batch Size   : {BATCH_SIZE:,} rows")
    print("=" * 80)

    t_start = time.time()
    total_written = 0

    writer = pq.ParquetWriter(OUTPUT_PARQUET, UNIFIED_SCHEMA, compression='snappy', use_dictionary=True)

    try:
        for ds in datasets_to_stream:
            name = ds['name']
            path = ds['path']
            fn = ds['transform_fn']
            cols = ds['columns']

            pf = pq.ParquetFile(path)
            total_ds_rows = pf.metadata.num_rows
            print(f"▶ Processing {name} ({total_ds_rows:,} rows)...")
            t_ds = time.time()
            ds_written = 0

            for batch in pf.iter_batches(batch_size=BATCH_SIZE, columns=cols):
                table = fn(batch)
                writer.write_table(table)
                ds_written += table.num_rows
                total_written += table.num_rows
                print(f"  Streamed {ds_written:,} / {total_ds_rows:,} rows ({(ds_written/total_ds_rows)*100:.1f}%)", end="\r", flush=True)

            print(f"  ✅ {name} complete: {ds_written:,} rows streamed in {time.time()-t_ds:.1f}s.")

    finally:
        writer.close()

    elapsed = time.time() - t_start
    size_mb = os.path.getsize(OUTPUT_PARQUET) / (1024**2)
    print("=" * 80)
    print("🎉 STREAMING MERGE COMPLETE!")
    print(f"• Total Rows Written : {total_written:,}")
    print(f"• Execution Time     : {elapsed:.1f}s ({elapsed/60:.2f} mins)")
    print(f"• Output File Size   : {size_mb:.1f} MB ({size_mb/1024:.2f} GB)")
    print(f"• Final File Path    : {OUTPUT_PARQUET}")
    print("=" * 80)

if __name__ == "__main__":
    run_merge()
