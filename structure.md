# A little thought on ML-driven Security Analysis

```
┌─────────────────────────────┐
│     1. Event Normalization  │
└─────────┬───────────────────┘
          │
┌─────────▼───────────────────┐
│       2. Enrichment Layer   │
│  (IPInfo, Ports, Subnet…)   │
└─────────┬───────────────────┘
          │
┌─────────▼───────────────────┐
│ 3. Risk Factor Engineering  │
│  (ioc_hit, fw_block, geo…)  │
└─────────┬───────────────────┘
          │
┌─────────▼───────────────────┐
│      4. Scoring Layer       │
│ Rule-Based + Logistic + BO  │
└─────────┬───────────────────┘
          │
┌─────────▼───────────────────┐
│      5. Alert Output        │
│  (score, prob, level)       │
└─────────────────────────────┘
```

$$
Pipeline = Preprocessing + Feature Engineering + Model
$$

$$
risk(event)=f(flags,enrichment,model)
$$


## Root Level Object:
```
{
  "type": "object",
  "properties": {

    "alert_id": { "type": "string" },
    "timestamp": { "type": "string", "format": "date-time" },

    "raw": { "$ref": "#/definitions/raw" },
    "enrichment": { "$ref": "#/definitions/enrichment" },
    "risk_factors": { "$ref": "#/definitions/risk_factors" },
    "scoring": { "$ref": "#/definitions/scoring" },
    "explanation": { "$ref": "#/definitions/explanation" },

    "analysis_agent": {
      "type": "object",
      "description": "reserved for agent-level insights"
    }
  },
  "required": ["alert_id", "timestamp", "raw", "enrichment", "risk_factors", "scoring", "explanation"]
}
```

## Raw Section

```
"definitions": {
  "raw": {
    "type": "object",
    "properties": {
      "src_ip": { "type": "string" },
      "dst_ip": { "type": "string" },
      "src_port": { "type": ["integer", "null"] },
      "dst_port": { "type": ["integer", "null"] },
      "protocol": { "type": "string" },
      "action": { "type": "string" },
      "event_type": { "type": "string" },
      "severity": { "type": ["number", "null"] }
    },
    "required": ["src_ip", "dst_ip", "action", "event_type"]
  }
}
```

---

## Event Normalization

For now, I'm trying to format the logs into the below table:

| field             | description               |
| ----------------- | ------------------------- |
| src_ip            | 源 IP                      |
| dst_ip            | 目的 IP                     |
| src_port          | 源端口                       |
| dst_port          | 目的端口                      |
| action            | firewall 允许/阻断            |
| severity          | IDS/IPS 级别                |
| signature         | IDS rule name             |
| malware_ioc_match | 是否命中 IOC                  |
| alert_type        | alert/warning/IDS/FW/etc. |

## Feature Enrichment

Then, we can have our enriched ip data (`async_ipinfo_client.py` | `ipinfo_async_tranformer.py`)

## IOC Correlation

For malware indicators, we might need an IOC log

| feature          | meaning             |
| ---------------- | ------------------- |
| src_ip_ioc_hit   | 源 IP 是否命中恶意 IP      |
| dst_ip_ioc_hit   | 目的 IP 是否命中恶意 IP     |
| domain_ioc_hit   | URL/domain 是否命中 IOC |
| hash_ioc_hit     | 文件 hash 是否命中恶意样本    |
| ioc_threat_level | 命中的最高恶意等级           |

## Alert Fusion

Here, we could combine all features into one fusion, and output a standardized alert score

```
score = 
    W1 * IOC_hit +
    W2 * IDS_alert +
    W3 * firewall_block +
    W4 * suspicious_port +
    W5 * geo_anomaly +
    W6 * uncommon_subnet
```

And we plan to use Logistic regression to realize a ML-driven weighting process:

```
score = 
    β1 * ioc_hit +
    β2 * ids_alert +
    β3 * fw_block +
    β4 * suspicious_port +
    β5 * geo_anomaly +
    β6 * uncommon_subnet +
    bias
```
