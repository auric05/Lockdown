# Lockdown
> A Distributed network security platform.
Lockdown deploys lightweight C sensor agents that capture and dissect raw network
traffic, feeding structured telemetry to a Python controller. A customer rule-based
detection engine classifies suspicious activity against the MITRE ATT&CK framework, every
detection traceable to a rule you can read. A React dashboard surfaces alerts in real time.

# Architecture
sensor agents (C) → controller API (Python) → detection engine → dashboard

  # Components
  - **sensor/** - libpcap packet capture and protocol dissection, written in C
  - **controller/** - FastAPI data ingestion and storage
  - **detection/** - custom rule engine, MITRE ATT&CK classification
  - **dashboard/** - React frontend
