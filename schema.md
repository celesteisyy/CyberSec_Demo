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

## Enrichment Section

```
"enrichment": {
  "type": "object",
  "properties": {
    "src_asn": { "type": ["integer", "null"] },
    "src_org": { "type": ["string", "null"] },
    "src_geo": { "type": ["string", "null"] },
    "src_city": { "type": ["string", "null"] },
    "src_iptype": { "type": ["string", "null"] },

    "dst_asn": { "type": ["integer", "null"] },
    "dst_org": { "type": ["string", "null"] },
    "dst_geo": { "type": ["string", "null"] },
    "dst_city": { "type": ["string", "null"] },
    "dst_iptype": { "type": ["string", "null"] },

    "subnet_src": { "type": ["string", "null"] },
    "subnet_dst": { "type": ["string", "null"] },

    "threat_intel": {
      "type": "object",
      "properties": {
        "ioc_matched": { "type": "boolean" },
        "ioc_id": { "type": ["string", "null"] },
        "ioc_severity": { "type": ["string", "null"] }
      }
    }
  }
}
```

## Risk Factor Section

> The core input for ML model, all categorical variables

```
"risk_factors": {
  "type": "object",
  "properties": {

    "ioc_hit": { "type": "integer" },
    "fw_block": { "type": "integer" },
    "ids_alert": { "type": "integer" },
    "uncommon_subnet": { "type": "integer" },
    "geo_anomaly": { "type": "integer" },

    "suspicious_port_cat": { "type": "integer" },

    "bad_asn": { "type": "integer" },
    "vpn_hosting_flag": { "type": "integer" },
    "tor_exit_node": { "type": "integer" },
    "lateral_movement_flag": { "type": "integer" }
  },
  "required": ["ioc_hit", "fw_block", "ids_alert"]
}
```

## Scoring Section

> ML output

```
"scoring": {
  "type": "object",
  "properties": {
    "alert_raw_score": { "type": "number" },
    "alert_probability": { "type": "number" },
    "alert_level": { "type": "string" },
    "model_version": { "type": "string" }
  },
  "required": ["alert_raw_score", "alert_probability", "alert_level"]
}
```


## Reason List

```
"explanation": {
  "type": "object",
  "properties": {
    "alert_reason": {
      "type": "array",
      "items": { "type": "string" }
    },
    "risk_factor_details": {
      "type": "object",
      "properties": {
        "ioc_hit": { "type": "string" },
        "fw_block": { "type": "string" },
        "ids_alert": { "type": "string" },
        "suspicious_port_cat": { "type": "string" }
      }
    }
  },
  "required": ["alert_reason"]
}
```

---

## An Example Output (Intended Output)

```
{
  "alert_id": "b4a62f33-f0fc-4a50-9cec-30c9b73e8c07",
  "timestamp": "2025-11-14T21:15:00Z",

  "raw": {
    "src_ip": "185.220.101.4",
    "dst_ip": "10.0.0.8",
    "src_port": 3389,
    "dst_port": 445,
    "protocol": "TCP",
    "action": "DENY",
    "event_type": "firewall",
    "severity": 4
  },

  "enrichment": {
    "src_asn": 9009,
    "src_org": "M247 Ltd",
    "src_geo": "NL",
    "src_city": "Amsterdam",
    "src_iptype": "hosting",

    "dst_asn": 16509,
    "dst_org": "Amazon AWS",
    "dst_geo": "US",
    "dst_city": "Virginia",
    "dst_iptype": "cloud"
  },

  "risk_factors": {
    "ioc_hit": 1,
    "fw_block": 1,
    "ids_alert": 1,
    "uncommon_subnet": 1,
    "geo_anomaly": 0,

    "suspicious_port_cat": 2,
    "bad_asn": 1,
    "vpn_hosting_flag": 1,
    "tor_exit_node": 0,
    "lateral_movement_flag": 0
  },

  "scoring": {
    "alert_raw_score": 4.93,
    "alert_probability": 0.94,
    "alert_level": "HIGH",
    "model_version": "logreg_v1.0.0"
  },

  "explanation": {
    "alert_reason": [
      "IOC hit",
      "Firewall block",
      "IDS alert triggered",
      "Known malicious ASN 9009",
      "Suspicious port category 2"
    ]
  },

  "analysis_agent": {}
}
```