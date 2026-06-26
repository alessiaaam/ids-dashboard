import pandas as pd

def extract_features(packets, window_size=10):
    if not packets:
        return pd.DataFrame()

    df = pd.DataFrame(packets)
    df["timestamp"] = pd.to_numeric(df["timestamp"])
    df = df.sort_values("timestamp").reset_index(drop=True)

    t_min = df["timestamp"].min()
    df["window"] = ((df["timestamp"] - t_min) // window_size).astype(int)

    windows = []

    for window_id, group in df.groupby("window"):
        duration = group["timestamp"].max() - group["timestamp"].min()
        if duration == 0:
            duration = 1

        syn_count = group["SYN"].sum() if "SYN" in group.columns else 0
        ack_count = group["ACK"].sum() if "ACK" in group.columns else 0

        syn_ack_ratio = syn_count / ack_count if ack_count > 0 else float(syn_count)

        repeated = group.groupby(["src_ip", "dst_ip", "dst_port"]).size()
        repeated_connections = int((repeated > 1).sum())

        top_src_ip = group["src_ip"].value_counts().idxmax() if len(group) > 0 else "unknown"

        features = {
            "window_id": window_id,
            "window_start": group["timestamp"].min(),
            "window_end": group["timestamp"].max(),
            "total_packets": len(group),
            "total_bytes": group["length"].sum(),
            "packets_per_second": len(group) / duration,
            "bytes_per_second": group["length"].sum() / duration,
            "unique_source_ips": group["src_ip"].nunique(),
            "unique_destination_ips": group["dst_ip"].nunique(),
            "unique_destination_ports": group["dst_port"].dropna().nunique(),
            "syn_count": int(syn_count),
            "ack_count": int(ack_count),
            "syn_ack_ratio": round(syn_ack_ratio, 4),
            "repeated_connections_to_same_port": repeated_connections,
            "src_ip": top_src_ip,
        }

        windows.append(features)

    return pd.DataFrame(windows)
