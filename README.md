# ai-shodan-astra-scan

Search for Astra Linux systems on the internet using multiple Shodan queries and prepare data for AI analysis.

## Features

- **Multiple Query Support**: Runs 12 different search queries targeting Astra Linux systems
- **Comprehensive Data Collection**: Searches for SSH banners, package versions, and domain references
- **Structured Output**: Saves results in JSON format ready for AI analysis
- **Geo Mapping**: Converts results to geo-mapping format for visualization
- **Rate Limited**: Respects Shodan API limits with built-in delays
- **Summary Reports**: Generates analysis-ready summary statistics

## Search Queries

The tool runs these queries to find Astra Linux systems:

1. `10+deb9u6astra6` - Specific package version signatures
2. `ssh "Astra Linux"` - SSH banners containing "Astra Linux"
3. `ssh banner:"astra"` - SSH banners with "astra" keyword
4. `ssh banner:"AstraLinux"` - SSH banners with "AstraLinux"
5. `"Astra Linux" port:22` - Port 22 services mentioning Astra Linux
6. `"astra" "debian" port:22` - Astra with Debian on SSH port
7. `"orel" "astra"` - Orel keyword with astra (Russian Astra variant)
8. `product:"OpenSSH" "astra"` - OpenSSH services with astra references
9. `"SE Linux" "astra"` - SELinux with astra (Astra uses SELinux)
10. `"Red OS" OR "Astra Linux" OR "astra linux"` - Multiple Astra variants
11. `"astra.ru"` - References to Astra domain
12. `"astralinux.ru"` - References to AstraLinux domain

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

### Basic Usage
```bash
docker run --rm -it -e SHODAN_API_KEY=YOURAPIKEYFORSHODAN astra-scanner:latest
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
# Set environment variable
export SHODAN_API_KEY=your_shodan_api_key_here

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