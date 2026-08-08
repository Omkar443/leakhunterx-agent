# LeakHunterX Agent
# LeakHunterX Agent (`lhx-agent`)
Lightweight open-source security scanning agent for LeakHunterX SaaS.
[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/Omkar443/leakhunterx-agent)
[![Python Version](https://img.shields.io/badge/python->=3.9-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)](https://github.com/Omkar443/leakhunterx-agent)
[![Privacy First](https://img.shields.io/badge/privacy-100%25%20Local%20Code%20Processing-brightgreen.svg)]()
## Features
Lightweight, high-performance security scanning agent for the **LeakHunterX** SaaS security platform. It performs automated client-side security analysis, endpoint discovery, and secret leak detection locally on your machine—ensuring that **your source code and target scripts never leave your environment**.
- Secure backend communication
- JS leak detection
- Endpoint discovery
- Cross-platform (Linux, Windows, macOS)
---
## Installation
## 🏗️ System Architecture
### One-liner (Linux/macOS)
LeakHunterX Agent operates on a **privacy-first local execution architecture**. Scanning, parsing, and JavaScript leak detection happen locally within your infrastructure. Only structured finding metadata (with secrets redacted) is streamed back to the cloud backend.
### Architecture Diagram
```mermaid
flowchart TD
    subgraph LocalMachine ["Your Machine (Local Environment)"]
        direction TB
        CLI["CLI Agent (lhx-agent)"]
        Engine["Scan Engine"]
        SourceCode["Source Code (Stays Here)"]
        
        CLI <--> Engine
        SourceCode -. Local Scan Only .-> Engine
    end
    subgraph Backend ["LeakHunterX Backend (Cloud Infrastructure)"]
        direction TB
        Redis["Redis Queue"]
