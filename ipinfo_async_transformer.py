import ipaddress
import pandas as pd
import asyncio
from sklearn.base import BaseEstimator, TransformerMixin
from async_ipinfo_client import AsyncIPInfoClient

# Unified ASN/ORG Normalizer
def normalize_org_asn(enriched):
    if not enriched:
        return {
            "asn": None,
            "asn_number": None,
            "asn_org": None,
            "asn_domain": None,
            "org_raw": None
        }

    asn_block = enriched.get("asn")
    org_raw = enriched.get("org")

    # ---------------------------
    # first search asn from asn block
    # ---------------------------
    if isinstance(asn_block, dict):
        asn = asn_block.get("asn")                 # e.g. "AS15169"
        asn_org = asn_block.get("name")            # "Google LLC"
        asn_domain = asn_block.get("domain")       # "google.com"

        # parse AS number
        try:
            asn_number = int(asn[2:]) if asn else None
        except:
            asn_number = None

    else:
        # no asn block → fallback to parsing org string
        asn = None
        asn_org = None
        asn_domain = None
        asn_number = None

    # ---------------------------
    # ② Fallback：从 org_raw 解析 (Lite always has “ASxxxx Name”)
    # ---------------------------
    if org_raw and isinstance(org_raw, str) and org_raw.startswith("AS"):

        # if structured ASN is missing, parse from org
        if asn is None:
            parts = org_raw.split(" ", 1)
            asn = parts[0]                     # AS15169
            try:
                asn_number = int(asn[2:])
            except:
                pass

        # if structured asn_org missing, parse name
        if asn_org is None:
            parts = org_raw.split(" ", 1)
            if len(parts) > 1:
                asn_org = parts[1]             # Google LLC

    return {
        "asn": asn,
        "asn_number": asn_number,
        "asn_org": asn_org,
        "asn_domain": asn_domain,
        "org_raw": org_raw
    }



# Local subnet + iptype parser

def parse_ip_local(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
    except:
        return {"subnet": None, "iptype": "unknown"}

    if ip_obj.is_private:
        iptype = 'private'
    elif ip_obj.is_loopback:
        iptype = 'loopback'
    elif ip_obj.is_multicast:
        iptype = 'multicast'
    elif ip_obj.is_reserved:
        iptype = 'reserved'
    else:
        iptype = 'public'

    prefix = 16 if ip_obj.version == 4 and ip_obj.is_private else 24
    subnet = str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))

    return {"subnet": subnet, "iptype": iptype}


# --------------------------
# Async Transformer
# --------------------------

class IPInfoAsyncTransformer(BaseEstimator, TransformerMixin):
    """
    Sklearn-compatible transformer for asynchronous IP enrichment.
    """
    def __init__(self, ip_columns, token, concurrency=5):
        self.ip_columns = ip_columns
        self.token = token
        self.concurrency = concurrency

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        X_copy = X.copy().reset_index(drop=True)

        # Collect all IPs
        ips = []
        for col in self.ip_columns:
            ips.extend(X_copy[col].fillna("").astype(str).tolist())

        # Async enrichment
        client = AsyncIPInfoClient(self.token, max_concurrency=self.concurrency)
        loop = asyncio.get_event_loop()
        enrichment_map = loop.run_until_complete(client.fetch_bulk(ips))

        # Attach features
        for col in self.ip_columns:
            records = []

            for ip in X_copy[col].fillna("").astype(str):
                enriched = enrichment_map.get(ip, {}) or {}
                local_info = parse_ip_local(ip)
                clean = normalize_org_asn(enriched)

                row = {
                    f"{col}_ip": ip,
                    f"{col}_asn": clean["asn"],
                    f"{col}_asn_number": clean["asn_number"],
                    f"{col}_asn_org": clean["asn_org"],
                    f"{col}_isp_org": clean["isp_org"],
                    f"{col}_org_raw": clean["org_raw"],
                    f"{col}_city": enriched.get("city"),
                    f"{col}_country": enriched.get("country"),
                    f"{col}_subnet": local_info.get("subnet"),
                    f"{col}_iptype": local_info.get("iptype"),
                }
                records.append(row)

            df_features = pd.DataFrame(records)
            X_copy = pd.concat([X_copy, df_features], axis=1)

        return X_copy
