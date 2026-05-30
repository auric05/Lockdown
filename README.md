# Lockdown
> AI enhanced distributed network security platform
- Lockdown deploys lightweight C sensor agents across network segments over a Tailscale mesh.
  Agents run continuous Nmap scans and libpcap packet capture, shipping structured data to a
  central controller. An AI intelligence layer analyses the feed - correlating events, tagging
  MITRE ATT&CK techniques, and generating threat reports. A React dashboard surfaces everything
  in real time.

  # Architecture
- sensor agents (C) → controller API (Python) → AI layer → dashboard

  # Components
  - **sensor/** - libpcap packet capture + Nmap wrapper, written in C
  - **controller/** - FastAPI data ingestion and storage
  - **intelligence/** - Claude API threat analysis pipeline
  - **dashboard/** - React frontend
