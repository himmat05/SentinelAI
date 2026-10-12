"""
SentinelAI - Stage 05 Full-Scale ETL: Transform All 20,432,819 Flows
=====================================================================
Streams through all 83 row groups of merged_sentinel_core.parquet,
computes physical ratios (pkt_len_ratio, bytes_per_packet),
applies np.log1p on all 14 heavy-tailed columns, and writes
sentinel_20M_transformed.parquet in clean pyarrow chunks.
"""

import os
import time
import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

INPUT_PATH = "ml/data/processed/merged_sentinel_core.parquet"
OUTPUT_PATH = "ml/data/processed/sentinel_20M_transformed.parquet"

LOG_COLS = [
    'flow_bytes_per_sec',
    'flow_pkts_per_sec',
    'flow_duration_s',
    'flow_iat_mean_s',
    'fwd_iat_mean_s',
    'bwd_iat_mean_s',
    'fwd_bytes',
    'bwd_bytes',
    'fwd_packets',
    'bwd_packets',
    'fwd_pkt_len_mean',
    'bwd_pkt_len_mean',
    'pkt_len_ratio',
    'bytes_per_packet'
]

TARGET_COL_ORDER = [
    'source_dataset',
    'dst_port',
    'flow_duration_s',
    'flow_iat_mean_s',
    'fwd_iat_mean_s',
    'bwd_iat_mean_s',
    'fwd_packets',
    'bwd_packets',
    'fwd_bytes',
    'bwd_bytes',
    'fwd_pkt_len_mean',
    'bwd_pkt_len_mean',
    'flow_bytes_per_sec',
    'flow_pkts_per_sec',
    'fwd_tcp_win_ratio',
    'bwd_tcp_win_ratio',
    'traffic_symmetry_ratio',
    'label',
    'attack_family',
    'pkt_len_ratio',
    'bytes_per_packet'
]

# Exact PyArrow schema matching sentinel_1M_transformed
ARROW_SCHEMA = pa.schema([
    ('source_dataset', pa.string()),
    ('dst_port', pa.int32()),
    ('flow_duration_s', pa.float32()),
    ('flow_iat_mean_s', pa.float32()),
    ('fwd_iat_mean_s', pa.float32()),
    ('bwd_iat_mean_s', pa.float32()),
    ('fwd_packets', pa.float32()),
    ('bwd_packets', pa.float32()),
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
    ('attack_family', pa.string()),
    ('pkt_len_ratio', pa.float32()),
    ('bytes_per_packet', pa.float32()),
])


def transform_and_stream():
    if not os.path.exists(INPUT_PATH):
        raise FileNotFoundError(f"Input file {INPUT_PATH} not found.")

    print(f"=== SentinelAI 20.4M Streaming Transformation ===")
    print(f"Source: {INPUT_PATH}")
    print(f"Destination: {OUTPUT_PATH}")

    # Remove existing output if present
    if os.path.exists(OUTPUT_PATH):
        os.remove(OUTPUT_PATH)

    parquet_file = pq.ParquetFile(INPUT_PATH)
    num_row_groups = parquet_file.metadata.num_row_groups
    total_expected_rows = parquet_file.metadata.num_rows

    print(f"Total Row Groups: {num_row_groups} | Total Expected Flows: {total_expected_rows:,}")
    t_start = time.time()

    writer = pq.ParquetWriter(
        OUTPUT_PATH,
        ARROW_SCHEMA,
        compression='snappy'
    )

    total_rows_processed = 0

    try:
        for rg_idx in range(num_row_groups):
            t_rg_0 = time.time()
            df = parquet_file.read_row_group(rg_idx).to_pandas()
            n_rows = len(df)

            # 1. Feature Engineering: Physical ratios
            df['pkt_len_ratio'] = (df['fwd_pkt_len_mean'] / (df['bwd_pkt_len_mean'] + 1e-6)).astype(np.float32)
            df['bytes_per_packet'] = ((df['fwd_bytes'] + df['bwd_bytes']) / (df['fwd_packets'] + df['bwd_packets'] + 1e-6)).astype(np.float32)

            # 2. Log-transforms with non-negative clipping
            for col in LOG_COLS:
                df[col] = np.log1p(np.maximum(df[col].values, 0)).astype(np.float32)

            # 3. Ratio type conversions
            df['fwd_tcp_win_ratio'] = df['fwd_tcp_win_ratio'].astype(np.float32)
            df['bwd_tcp_win_ratio'] = df['bwd_tcp_win_ratio'].astype(np.float32)
            df['traffic_symmetry_ratio'] = df['traffic_symmetry_ratio'].astype(np.float32)
            df['dst_port'] = df['dst_port'].astype(np.int32)
            df['label'] = df['label'].astype(np.int8)

            # 4. Reorder columns
            df = df[TARGET_COL_ORDER]

            # 5. Convert to PyArrow Table
            table = pa.Table.from_pandas(df, schema=ARROW_SCHEMA, preserve_index=False)
            writer.write_table(table)

            total_rows_processed += n_rows
            rg_time = time.time() - t_rg_0

            if (rg_idx + 1) % 10 == 0 or (rg_idx + 1) == num_row_groups:
                elapsed = time.time() - t_start
                rate = total_rows_processed / elapsed
                print(f"[{rg_idx + 1:2d}/{num_row_groups}] Processed {total_rows_processed:,} flows "
                      f"({total_rows_processed / total_expected_rows * 100:.1f}%) | "
                      f"Speed: {rate:,.0f} flows/s | Elapsed: {elapsed:.1f}s")

    finally:
        writer.close()

    total_time = time.time() - t_start
    output_size_mb = os.path.getsize(OUTPUT_PATH) / (1024 * 1024)

    print(f"\n✅ Successfully created {OUTPUT_PATH}")
    print(f"Total Rows: {total_rows_processed:,} | File Size: {output_size_mb:.2f} MB")
    print(f"Total Duration: {total_time:.2f}s ({total_time / 60:.2f} minutes)")


if __name__ == "__main__":
    transform_and_stream()
