import uuid
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin

class AlertOutputTransformer(BaseEstimator, TransformerMixin):
    """
    final transformer to output standardized alert format with explanations
    """

    def __init__(self, include_reasons=True, include_enrichment=True):
        self.include_reasons = include_reasons
        self.include_enrichment = include_enrichment

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        X = X.copy()

        # alert_id
        X["alert_id"] = [str(uuid.uuid4()) for _ in range(len(X))]

        # alert_reason
        if self.include_reasons:
            X["alert_reason"] = X.apply(self.build_reason, axis=1)

        return X

    def build_reason(self, row):
        reasons = []

        if row.get("ioc_hit") == 1:
            reasons.append("IOC hit")
        if row.get("ids_alert") == 1:
            reasons.append("IDS alert")
        if row.get("fw_block") == 1:
            reasons.append("Firewall block")
        if row.get("suspicious_port_cat", 0) > 0:
            reasons.append(f"Suspicious port category {row['suspicious_port_cat']}")
        if row.get("geo_anomaly") == 1:
            reasons.append("Geo anomaly")
        if row.get("uncommon_subnet") == 1:
            reasons.append("Uncommon subnet")

        # ASN example
        if "src_asn" in row and row["src_asn"] in {9009, 49505, 14061}:
            reasons.append(f"Known malicious ASN {row['src_asn']}")

        if len(reasons) == 0:
            reasons.append("No major risk factors triggered")

        return reasons
