# 🔆 ProxySQL Log Analyzer

A lightweight Go-based utility that parses and analyzes ProxySQL log files and generates a comprehensive HTML report for easy visualization and troubleshooting.

## ⌛️How to Run

### Option 1: Download Pre-compiled Binaries (Easiest)

Go to the **Releases** tab, download the binary for your OS, and run it via terminal/command prompt:

**Linux:** `./proxysql-log-analyzer-<ARCH> --file <FILENAME> --port <PORT>`
**Windows:** `proxysql-log-analyzer_win.exe --file <FILENAME> --port <PORT>`
**Mac:** `./proxysql-log-analyzer_mac_Darwin_<ARCH> --file <FILENAME> --port <PORT>`

### Option 2: Build from Source (Requires Go installed)

```bash
git clone https://github.com/aniljoshi2022/proxysql-log-analyzer.git
cd proxysql-log-analyzer
go build -o proxysql-log-analyzer main.go
./proxysql-log-analyzer --file proxysql.log --port 8080
```

To build this project from source, you need to have Go (Golang) installed on your machine.

- Mac (Homebrew): `brew install go`
- Linux (Ubuntu/Debian): `sudo apt install golang-go`
- Linux (Centos/Rhel): `sudo yum/dnf install go`
- Windows: Download the installer from `https://go.dev/dl/`


---



## 📸 Screenshots

image.png
image.png
image.png


## **🔖Usage**

```bash
./proxysql-log-analyzer --help
Usage of ./proxysql-log-analyzer:
  -addr string
    	HTTP listen address (default ":8080")
  -file string
    	path to proxysql.log (default "proxysql.log")

```
