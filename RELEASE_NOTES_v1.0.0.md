# v1.0.0 — First Stable Release 🎉

A lightweight Go utility that parses and analyzes ProxySQL logs, generating interactive HTML report.

## ✨ What's New

- **Event Timeline** — Complete chronological view of all ProxySQL events
- **Advanced Filtering** — Search by time range, node status, hostgroup, and log level
- **Configuration Audit** — Track all LOAD/SAVE operations with checksums
- **Backend Node Tracking** — Monitor node status changes (ONLINE, SHUNNED, OFFLINE_SOFT, OFFLINE_HARD)
- **Dark UI** — 8 analysis tabs with interactive filters and responsive design

## 🚀 Quick Start

```bash
./proxysql-log-analyzer --file=proxysql.log --port=8080
# Open http://localhost:8080
```

Pre-compiled binaries available for Linux, Windows, and macOS.

## 📋 Features

- ProxySQL metadata extraction
- Error & warning isolation
- Node dump visualization  
- Interactive global search
- Full log categorization

**Built with:** Go 1.25.1 | **License:** MIT
