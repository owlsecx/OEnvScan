# 🦉 OEnvScan

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-0a0c10?style=flat-square"/>
  <img src="https://img.shields.io/badge/Category-Forensics%20/%20DFIR-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/Part%20of-OwlSec%20Toolkit-7b5ea7?style=flat-square"/>
  <img src="https://img.shields.io/badge/Version-1.0-cyan?style=flat-square"/>
</p>

> **OEnvScan** — .env / environment secret + misconfig scanner — tokens, git exposure, perms, drift ║

---

> ⚠️ **AUTHORISED USE ONLY** — Use only on systems you own or have explicit written permission to test. Unauthorised use is illegal.

---

## 📌 Overview

OEnvScan — .env / environment secret + misconfig scanner — tokens, git exposure, perms, drift. .env / Environment Secret & Misconfig Scanner Finds hardcoded credentials, provider tokens and insecure settings in .env / config files, the process environment and other processes' environments, then weighs them by context: git exposure, file permissions, template files, secret reuse and .env ↔ .env.example drift. v1.1 adds git-history scanning, a generic high-entropy rule, baselines / .oenvscanignore and an opt-in --fix mode.

---

## ✨ Features

- Scan .env and environment files for secrets and misconfigurations
- Detect tokens, API keys, private material and git exposure risks
- Check permissions and drift against expected baselines
- Rank findings with severity and posture grading
- MITRE ATT&CK tagging where meaningful
- Export to TXT, Markdown, JSON, CSV or SARIF

---

## ⚙️ Requirements

- **Linux**
- **Go 1.21+** (stdlib only; `CGO_ENABLED=0`)

---

## 🚀 Usage

```bash
go build -ldflags="-s -w" -o OEnvScan OEnvScan.go
./OEnvScan --help
./OEnvScan --path .
./OEnvScan --input .env --format sarif
./OEnvScan --path /app --format json --output env.sarif
```

---

## 📦 Part of OwlSec Toolkit

This tool is part of the **OwlSec** suite — a collection of 300+ security and privacy tools.

🔗 [owlsec.org](https://owlsec.org)

---

## ©️ License

MIT License — © Khaled S. Haddad
