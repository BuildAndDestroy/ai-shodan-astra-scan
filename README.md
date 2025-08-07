# ai-shodan-astra-scan
Search for Astra Linux on the internet


# Build

```
docker build -t astra-scanner .
```

# Run

```
docker run --rm -it -e SHODAN_API_KEY=YOURAPIKEYFORSHODAN astra-scanner:latest
```