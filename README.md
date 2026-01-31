# Reality - TLS - Scanner

TLS scanner for Reality servers with cross-platform GUI and automatic GeoIP database updates.

## Features

- **CLI Mode**: Command-line interface for automation and scripting
- **GUI Mode**: Cross-platform graphical interface (Windows, macOS, Linux)
- **Auto GeoIP**: Automatic download and update of MaxMind GeoLite2 Country database
- **Multiple Sources**: Scan single IP/domain, CIDR ranges, file lists, or crawl from URLs
- **Real-time Results**: Live scanning progress and results display
- **Export to CSV**: Save results for further analysis

## Building

Requirements:
- Go 1.24+
- GCC/MinGW-w64 (for GUI build with Fyne)

```bash
# CLI + GUI build (shows console window)
go build -o RealiTLScanner.exe

# GUI build without console window (Windows only)
go build -ldflags -H=windowsgui -o RealiTLScanner-GUI.exe

# CLI only (no CGO required)
CGO_ENABLED=0 go build
```

## Usage

### GUI Mode

Launch the graphical interface by double-clicking the executable or running:

```bash
./RealiTLScanner --gui
# or simply
./RealiTLScanner
```

**GUI Features:**
- Source selection: IP/CIDR/Domain, File, or URL
- Configurable scan parameters (port, threads, timeout)
- Real-time results table
- Progress monitoring and logs
- Export results to CSV

### CLI Mode

```bash
# Show help
./RealiTLScanner --help

# Scan a specific IP, IP CIDR or domain:
./RealiTLScanner -addr 1.2.3.4
# Note: infinity mode will be enabled automatically if `addr` is an IP or domain

# Scan a list of targets from a file (targets should be divided by line break):
./RealiTLScanner -in in.txt

# Crawl domains from a URL and scan:
./RealiTLScanner -url https://launchpad.net/ubuntu/+archivemirrors

# Specify a port to scan, default: 443
./RealiTLScanner -addr 1.1.1.1 -port 443

# Show verbose output, including failed scans and infeasible targets:
./RealiTLScanner -addr 1.2.3.0/24 -v

# Save results to a file, default: out.csv
./RealiTLScanner -addr www.microsoft.com -out file.csv

# Set a thread count, default: 2
./RealiTLScanner -addr wiki.ubuntu.com -thread 10

# Set a timeout for each scan, default: 10 (seconds)
./RealiTLScanner -addr 107.172.1.1/16 -timeout 5

# Enable IPv6 scanning
./RealiTLScanner -addr example.com -46
```

### Docker

Build container (no Go required on host):
```bash
docker build -t realitlscanner .
```

Run:
```bash
# show help
docker run --rm realitlscanner

# scan
docker run --rm realitlscanner -addr 1.1.1.1
```

## GeoIP Database

The application **automatically downloads and updates** the MaxMind GeoLite2 Country database:

- **First run**: Downloads `Country.mmdb` (~6 MB) from [P3TERX/GeoLite.mmdb](https://github.com/P3TERX/GeoLite.mmdb)
- **Subsequent runs**: Checks for updates and downloads if available (~100ms check)
- **No internet**: Works without GeoIP, shows "N/A" for country codes

You can also manually place a GeoLite2/GeoIP2 Country Database in the executing folder with the exact name `Country.mmdb`.

## Output Examples

Example stdout:

```bash
2024/02/08 20:51:10 INFO Started all scanning threads time=2024-02-08T20:51:10.017+08:00
2024/02/08 20:51:10 INFO Connected to target feasible=true host=107.172.103.9 tls=1.3 alpn=h2 domain=rocky-linux.tk issuer="Let's Encrypt"
2024/02/08 20:51:10 INFO Connected to target feasible=true host=107.172.103.11 tls=1.3 alpn=h2 domain=rn.allinai.dev issuer="Let's Encrypt"
2024/02/08 20:51:13 INFO Connected to target feasible=true host=107.172.103.16 tls=1.3 alpn=h2 domain=san.hiddify01.foshou.vip issuer="Let's Encrypt"
2024/02/08 20:51:38 INFO Scanning completed time=2024-02-08T20:51:38.988+08:00 elapsed=28.97043s
```

Example CSV output:

```csv
IP,ORIGIN,CERT_DOMAIN,CERT_ISSUER,GEO_CODE
202.70.64.2,ntc.net.np,*.ntc.net.np,"GlobalSign nv-sa",NP
196.200.160.70,mirror.marwan.ma,mirror.marwan.ma,"Let's Encrypt",MA
103.194.167.213,mirror.i3d.net,*.i3d.net,"Sectigo Limited",JP
194.127.172.131,nl.mirrors.clouvider.net,nl.mirrors.clouvider.net,"Let's Encrypt",NL
202.36.220.86,mirror.2degrees.nz,mirror.2degrees.nz,"Let's Encrypt",NZ
158.37.28.65,ubuntu.hi.no,alma.hi.no,"Let's Encrypt",NO
193.136.164.6,ftp.rnl.tecnico.ulisboa.pt,ftp.rnl.ist.utl.pt,"Let's Encrypt",PT
```

## Notes

- It is recommended to run this tool locally, as running the scanner in the cloud may cause the VPS to be flagged
- The compiled executable does not require Go or GCC installation on end-user systems
- GUI binary size is approximately 40-50 MB due to embedded Fyne libraries

