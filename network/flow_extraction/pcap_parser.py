"""
SentinelAI - Pure-Python PCAP Flow Extractor
===========================================
Zero-driver libpcap (.pcap) packet parser that reconstructs bidirectional 5-tuple
network flows and computes all 18 canonical SentinelAI FlowData input features
directly from uploaded packet captures (works identically on Windows, Linux, Docker).
"""

import ipaddress
import struct
from collections import defaultdict
from typing import Dict, List, Tuple

from backend.app.schemas.flow import FlowData

# Supported libpcap global magic headers (little/big endian, microsecond/nanosecond)
_PCAP_MAGIC_MAP = {
    0xA1B2C3D4: ("<", 1e-6),   # Big-endian writer, read LE -> swap? Standard LE host
    0xD4C3B2A1: (">", 1e-6),   # Swapped endian
    0xA1B23C4D: ("<", 1e-9),   # Nanosecond resolution
    0x4D3CB2A1: (">", 1e-9),
}


def parse_pcap_bytes(pcap_bytes: bytes, max_flows: int = 2000) -> List[FlowData]:
    """
    Parse a classic .pcap binary buffer into bidirectional FlowData objects
    matching SentinelAI's 18-feature production model schema.
    """
    if len(pcap_bytes) < 24:
        raise ValueError("Invalid PCAP file: buffer shorter than 24-byte global header.")

    magic_le = struct.unpack("<I", pcap_bytes[:4])[0]
    if magic_le not in _PCAP_MAGIC_MAP:
        raise ValueError(
            "Unsupported packet capture format. Upload a classic libpcap (.pcap) file (Ethernet + IPv4)."
        )

    endian, ts_scale = _PCAP_MAGIC_MAP[magic_le]
    # Header: magic(I), v_major(H), v_minor(H), thiszone(i), sigfigs(I), snaplen(I), linktype(I)
    _, _, _, _, _, _, link_type = struct.unpack(f"{endian}IHHiIII", pcap_bytes[:24])
    if link_type != 1:
        raise ValueError(f"Unsupported PCAP link-layer type {link_type} (only Ethernet DLT_EN10MB=1 supported).")

    # Key: canonical sorted 5-tuple -> state
    flows: Dict[Tuple[str, int, str, int, str], Dict] = {}

    offset = 24
    total_len = len(pcap_bytes)

    while offset + 16 <= total_len:
        ts_sec, ts_sub, incl_len, _orig_len = struct.unpack(f"{endian}IIII", pcap_bytes[offset : offset + 16])
        offset += 16
        if incl_len == 0 or offset + incl_len > total_len:
            break

        pkt = pcap_bytes[offset : offset + incl_len]
        offset += incl_len
        ts = float(ts_sec) + float(ts_sub) * ts_scale

        # Parse Ethernet header (14 bytes; handle single 802.1Q VLAN tag if 0x8100)
        if len(pkt) < 14:
            continue
        eth_type = struct.unpack("!H", pkt[12:14])[0]
        l3_offset = 14
        if eth_type == 0x8100 and len(pkt) >= 18:
            eth_type = struct.unpack("!H", pkt[16:18])[0]
            l3_offset = 18

        if eth_type != 0x0800 or len(pkt) < l3_offset + 20:
            continue  # IPv4 only

        ip_hdr = pkt[l3_offset : l3_offset + 20]
        ver_ihl, _, ip_total_len, _, _, _, proto_num, _, src_raw, dst_raw = struct.unpack("!BBHHHBBH4s4s", ip_hdr)
        ihl = (ver_ihl & 0x0F) * 4
        if ihl < 20 or len(pkt) < l3_offset + ihl:
            continue

        src_ip = str(ipaddress.IPv4Address(src_raw))
        dst_ip = str(ipaddress.IPv4Address(dst_raw))
        l4_offset = l3_offset + ihl

        src_port = 0
        dst_port = 0
        win_norm = 0.5
        protocol = "OTHER"

        if proto_num == 6 and len(pkt) >= l4_offset + 20:
            protocol = "TCP"
            src_port, dst_port, _, _, _, _, win_size = struct.unpack("!HHIIBBH", pkt[l4_offset : l4_offset + 16])
            win_norm = min(max(win_size / 65535.0, 0.0), 1.0)
        elif proto_num == 17 and len(pkt) >= l4_offset + 8:
            protocol = "UDP"
            src_port, dst_port = struct.unpack("!HH", pkt[l4_offset : l4_offset + 4])
            win_norm = 0.0
        elif proto_num == 1:
            protocol = "ICMP"
        else:
            continue

        # Bidirectional flow key oriented by first observed packet
        forward_key = (src_ip, src_port, dst_ip, dst_port, protocol)
        reverse_key = (dst_ip, dst_port, src_ip, src_port, protocol)

        if forward_key in flows:
            fstate = flows[forward_key]
            is_fwd = True
        elif reverse_key in flows:
            fstate = flows[reverse_key]
            is_fwd = False
        else:
            if len(flows) >= max_flows:
                continue
            fstate = {
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": protocol,
                "all_ts": [],
                "fwd_ts": [],
                "bwd_ts": [],
                "fwd_lens": [],
                "bwd_lens": [],
                "fwd_wins": [],
                "bwd_wins": [],
            }
            flows[forward_key] = fstate
            is_fwd = True

        pkt_bytes = max(ip_total_len, len(pkt) - l3_offset)
        fstate["all_ts"].append(ts)
        if is_fwd:
            fstate["fwd_ts"].append(ts)
            fstate["fwd_lens"].append(pkt_bytes)
            fstate["fwd_wins"].append(win_norm)
        else:
            fstate["bwd_ts"].append(ts)
            fstate["bwd_lens"].append(pkt_bytes)
            fstate["bwd_wins"].append(win_norm)

    if not flows:
        raise ValueError("No valid IPv4 TCP/UDP/ICMP packets discovered inside PCAP.")

    results: List[FlowData] = []
    for st in flows.values():
        all_ts = sorted(st["all_ts"])
        fwd_ts = sorted(st["fwd_ts"])
        bwd_ts = sorted(st["bwd_ts"])

        duration_s = max(all_ts[-1] - all_ts[0], 0.0001)
        all_iats = [all_ts[i] - all_ts[i - 1] for i in range(1, len(all_ts))]
        fwd_iats = [fwd_ts[i] - fwd_ts[i - 1] for i in range(1, len(fwd_ts))]
        bwd_iats = [bwd_ts[i] - bwd_ts[i - 1] for i in range(1, len(bwd_ts))]

        fwd_pkts = len(st["fwd_lens"])
        bwd_pkts = len(st["bwd_lens"])
        fwd_bytes = float(sum(st["fwd_lens"]))
        bwd_bytes = float(sum(st["bwd_lens"]))
        total_bytes = fwd_bytes + bwd_bytes
        total_pkts = fwd_pkts + bwd_pkts

        results.append(
            FlowData(
                src_ip=st["src_ip"],
                dst_ip=st["dst_ip"],
                src_port=st["src_port"],
                protocol=st["protocol"],
                dst_port=st["dst_port"],
                flow_duration_s=round(duration_s, 6),
                flow_iat_mean_s=round(sum(all_iats) / len(all_iats), 6) if all_iats else 0.0,
                fwd_iat_mean_s=round(sum(fwd_iats) / len(fwd_iats), 6) if fwd_iats else 0.0,
                bwd_iat_mean_s=round(sum(bwd_iats) / len(bwd_iats), 6) if bwd_iats else 0.0,
                fwd_packets=float(fwd_pkts),
                bwd_packets=float(bwd_pkts),
                fwd_bytes=fwd_bytes,
                bwd_bytes=bwd_bytes,
                fwd_pkt_len_mean=round(fwd_bytes / fwd_pkts, 3) if fwd_pkts > 0 else 0.0,
                bwd_pkt_len_mean=round(bwd_bytes / bwd_pkts, 3) if bwd_pkts > 0 else 0.0,
                flow_bytes_per_sec=round(total_bytes / duration_s, 2),
                flow_pkts_per_sec=round(total_pkts / duration_s, 2),
                fwd_tcp_win_ratio=round(sum(st["fwd_wins"]) / len(st["fwd_wins"]), 4) if st["fwd_wins"] else 0.0,
                bwd_tcp_win_ratio=round(sum(st["bwd_wins"]) / len(st["bwd_wins"]), 4) if st["bwd_wins"] else 0.0,
                traffic_symmetry_ratio=round(fwd_bytes / total_bytes, 4) if total_bytes > 0 else 0.5,
            )
        )

    return results
