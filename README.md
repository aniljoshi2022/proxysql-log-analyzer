# 🔆 ProxySQL Log Analyzer

A lightweight Go-based utility that parses and analyzes ProxySQL log files and generates a comprehensive HTML report for easy visualization and troubleshooting.

## ⌛️How to Run

### 🧰 Option 1: Download Pre-compiled Binaries (Easiest)

Go to the **Releases** tab, download the binary for your OS, and run it via terminal/command prompt:

**Linux:** `./proxysql-log-analyzer-<ARCH> --file=<FILENAME> --port=<PORT>`

**Windows:** `proxysql-log-analyzer_win.exe --file=<FILENAME> --port=<PORT>`

**Mac:** `./proxysql-log-analyzer_mac_Darwin_<ARCH> --file=<FILENAME> --port=<PORT>`

### 🛠️ Option 2: Build from Source (Requires Go installed)

```bash

git clone https://github.com/aniljoshi2022/proxysql-log-analyzer.git

cd proxysql-log-analyzer

go build -o proxysql-log-analyzer main.go

./proxysql-log-analyzer --file=proxysql.log --port=8080
```

## 👨‍💻How to Access UI

`http://<URL>:<PORT`

`http://<URL>:<PORT/api/analysis`


## 📝Requirements

To build this project from source, you need to have Go (Golang) installed on your machine.

- Mac (Homebrew): `brew install go`
- Linux (Ubuntu/Debian): `sudo apt install golang-go`
- Linux (Centos/Rhel): `sudo yum/dnf install go`
- Windows: Download the installer from `https://go.dev/dl/`

## ✨ Features
- Parses ProxySQL logs efficiently
- Time range and other status filters for more granularity in search
- Details related to events, backend nodes, errors, warnings, etc
  
---



## 📸 Screenshots


**Dashboard/UI**
<img width="3024" height="1268" alt="image" src="https://github.com/user-attachments/assets/7c7a91b4-dbdd-4352-bfe8-0bb8bfe3551e" />

---

**Date/Time filter to get matching searches**
<img width="3024" height="1000" alt="image" src="https://github.com/user-attachments/assets/859a50c5-722b-4d2e-a58d-b0cd8e986380" />

---

**Node and Host group level filters** 
<img width="2928" height="844" alt="image" src="https://github.com/user-attachments/assets/ce21658f-6ff3-447b-a59d-9a33319d83ba" />

---

**More granular filters for the full logs**
<img width="3024" height="850" alt="image" src="https://github.com/user-attachments/assets/f4a001ff-1534-4278-bc40-e6173dcbc42e" />

---

## **🔖Usage**

```bash
./proxysql-log-analyzer --help
Usage of ./proxysql-log-analyzer:
  -file string
      path to proxysql.log (default "proxysql.log")
  -port string
      HTTP listen port (default "8080")

```
