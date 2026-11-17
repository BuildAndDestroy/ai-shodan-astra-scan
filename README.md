# ai-shodan-astra-scan

Search for Astra Linux systems on the internet using multiple Shodan queries and prepare data for AI analysis.

## Features

- **Multiple Query Support**: Runs 33 Shodan queries targeting Astra Linux across SSH, HTTP, SMTP, DNS and Prometheus exporters
- **Free Query Validation**: `-count` mode reports per-query totals and version breakdowns via Shodan's count endpoint (no query credits)
- **`.env` Support**: API key is read from a gitignored `.env` file (environment variables take precedence)
- **Structured Output**: Saves results in JSON format ready for AI analysis
- **Geo Mapping**: Converts results to geo-mapping format for visualization
- **Rate Limited**: Respects Shodan API limits with built-in delays
- **Agent Playbook**: [`prompts/astra-recon-agent.md`](prompts/astra-recon-agent.md) lets an AI agent run the tooling and fan out analysis

## Astra Linux Fingerprints

Signals were verified against Astra ISOs (Orel/CE 2.12.43, CE 2.12.46, Smolensk 1.6) and live Shodan data (Nov 2026).
Shodan strips punctuation when searching, so `"#astra"`, `"+astra"` and `"(Astra)"` all collapse to the noisy token `astra`. Query whole tokens instead.

| Service | Banner example | Query | Notes |
|---|---|---|---|
| SSH | `OpenSSH_7.4p1 Debian-10+deb9u6astra6` | `deb9u6astra*` | Orel/CE 2.12 and SE 1.6 (`astra6seN`) |
| SSH | `OpenSSH_8.4p1 Debian-2~deb10u1astra6se14` | `deb10u1astra*` | SE 1.7 era (`astra6seN`) |
| SSH | `OpenSSH_9.6p1 Debian-2~deb10u1astra8se8+ci3` | `deb10u1astra*` | newer SE builds (`astra8seN`) |
| SSH | `OpenSSH_7.4p1 Debian-10+deb9u4astra6se3` | `deb9u4astra*` | Smolensk 1.6 ISO build |
| HTTP | `Server: Apache/2.4.46 (AstraLinuxCE)` | `"AstraLinuxCE"` | CE 2.12.46 |
| HTTP | `Server: Apache/2.4.46 (AstraLinuxSE)` | `"AstraLinuxSE"` | SE |
| HTTP | `Server: Apache/2.4.62 (AstraLinux)` | `astralinux` | 2.4.52/2.4.57/2.4.62, newer SE releases |
| SMTP | `ESMTP Postfix (Astra Linux/GNU)` | `"Astra Linux/GNU"` | |
| DNS | `9.11.3-1ubuntu1.15+ci202105041610+astra1-Debian` | exact string | CE 2.12.4x BIND `version.bind` |
| Node Exporter | `pretty_name: Astra Linux (Orel 2.12.46)`, kernel `#astra1+ci3 SMP` | `product:"Prometheus Node Exporter" "astra"` | exact point release |

Checked and found **not** useful: Samba, Exim, Dovecot, vsftpd, CUPS, NTP, MariaDB and Squid report stock Debian strings. SNMP `sysDescr` hits for `astra` are hostnames, not Astra kernels. No `deb11u*astra*` or `deb12u*astra*` SSH builds were observed.

## Search Queries

See the `queries` slice in [`main.go`](main.go) for the authoritative list with per-query comments. In summary:

- **SSH package versions**: `deb9u6astra*`, `deb10u1astra*`, `deb9u4astra*`, plus pinned builds (`deb10u1astra8se8+ci3`, `10+deb9u6astra6se5`, ...)
- **HTTP**: `astralinux`, `"AstraLinuxCE"`, `"AstraLinuxSE"`
- **SMTP**: `"Astra Linux/GNU"`, `"Astra Linux"`
- **DNS**: Astra BIND `version.bind` string
- **Prometheus Node Exporter**: `product:"Prometheus Node Exporter" "astra"`
- **Shodan OS field**: `os:"Astra Linux"`
- **Legacy keyword queries** (`ssh "Astra Linux"`, `banner:` etc.), which currently return 0 hits

Run `go run . -count` to see which queries are live and the version spread behind each one.

## Output Structure

The tool creates a `shodan_results/` directory containing:

- **Individual Query Results**: `query_XX_<sanitized_query>.json` - Results for each specific query
- **Combined Results**: `combined_results_<timestamp>.json` - All matches from all queries
- **Geo Data**: `geo_data_<timestamp>.json` - Location data for mapping visualization
- **Summary Report**: `scan_summary_<timestamp>.json` - Statistical analysis and metadata

## Build

```bash
docker build -t astra-scanner .
```

## Run

### API Key

```bash
cp .env.example .env
chmod 600 .env
# edit .env and set SHODAN_API_KEY=...
```

`.env` is gitignored and excluded from the Docker build context via `.dockerignore`.

### Basic Usage
```bash
docker run --rm -it --env-file .env astra-scanner:latest
```

### Validate Queries (no query credits)
```bash
go run . -count                               # totals + top 15 versions per query
go run . -count -facets "version:30,port:5"   # wider breakdown
docker run --rm -it --env-file .env astra-scanner:latest -count
```

### Save Results to Host Directory
```bash
# Create local results directory
mkdir -p ./results

# Run with volume mount to persist results
docker run --rm -it \
  -e SHODAN_API_KEY=YOURAPIKEYFORSHODAN \
  -v $(pwd)/results:/app/shodan_results \
  astra-scanner:latest
```

### Local Development
```bash
# Uses .env automatically (or: export SHODAN_API_KEY=...)

# Run directly
go run main.go
```

## Output Files

### Individual Query Results
```json
{
  "query": "ssh \"Astra Linux\"",
  "timestamp": "20240812_143022",
  "total": 45,
  "matches": [...]
}
```

### Combined Results
```json
{
  "scan_timestamp": "20240812_143022",
  "total_queries": 12,
  "total_matches": 234,
  "queries_run": [...],
  "all_matches": [...]
}
```

### Geo Data
```json
[
  {
    "ip": "192.168.1.1",
    "country": "Russia",
    "city": "Moscow",
    "latitude": 55.7558,
    "longitude": 37.6173,
    "port": 22,
    "ssh_info": "Product: OpenSSH, Version: 7.4, Type: ssh2",
    "timestamp": "2024-08-12T14:30:22.000Z"
  }
]
```

### Summary Report
```json
{
  "scan_timestamp": "20240812_143022",
  "queries_executed": 12,
  "total_matches": 234,
  "unique_ips": 187,
  "geolocated_hosts": 156,
  "countries_found": 23,
  "top_countries": {
    "Russia": 89,
    "Belarus": 34,
    "Kazakhstan": 12
  },
  "ports_found": {
    "22": 201,
    "2222": 15,
    "443": 8
  },
  "products_found": {
    "OpenSSH": 178,
    "nginx": 12,
    "Apache": 8
  }
}
```

## Security Scanning

The `Security` workflow runs on every push and PR to `main`, weekly, and on demand:

| Job | Tool | Scope |
|---|---|---|
| CodeQL | `github/codeql-action` (`security-and-quality`) | Go, Python, GitHub Actions SAST |
| gosec | `securego/gosec` | Go SAST |
| govulncheck | `golang.org/x/vuln` | Go stdlib and module CVEs (reachability-aware) |
| Bandit + pip-audit | PyCQA / PyPA | MCP server SAST and dependency CVEs |
| Gitleaks | `gitleaks/gitleaks-action` | Secrets in git history |

Dependabot keeps Go modules, pip, GitHub Actions and the Docker base image up to date.

## API Rate Limiting

The tool includes a 2-second delay between queries to respect Shodan's API rate limits. For production use with large-scale scanning, consider:

- Using Shodan's bulk search APIs
- Implementing exponential backoff
- Monitoring your API quota usage

## Test Drive Astra Linux

Download Astra for Desktop, Server, Mobile, and Embedded

* https://astralinux.ru/os/
* https://dl.astralinux.ru/astra/stable/2.12_x86-64/iso/
* https://dl.astralinux.ru/astra/frozen/

## Search Notes

Use Shodan to search for astra, specifically OpenSSH service

* https://www.shodan.io/search/facet?query=product%3Aopenssh&facet=version


## Next Steps

The structured JSON output is designed for AI analysis. Each file contains:

- **Raw data** for detailed investigation
- **Metadata** for context and provenance
- **Geographic information** for threat landscape analysis
- **Statistical summaries** for quick insights

The data is ready for ingestion by AI tools for threat hunting, pattern analysis, and security assessment.