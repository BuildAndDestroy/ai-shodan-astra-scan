package main

import (
	"anthropic-shodan-scan/pkg/geomapper"
	"anthropic-shodan-scan/pkg/report"
	"anthropic-shodan-scan/pkg/shodan"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func main() {
	apiKey := os.Getenv("SHODAN_API_KEY")
	if apiKey == "" {
		fmt.Fprintf(os.Stderr, "Error: SHODAN_API_KEY environment variable is required\n")
		os.Exit(1)
	}

	// Create output directory
	outputDir := "shodan_results"
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output directory: %v\n", err)
		os.Exit(1)
	}

	// Multiple search queries for Astra Linux
	queries := []string{
		"10+deb9u6astra6",                                  // Current query - specific package version
		"ssh \"Astra Linux\"",                              // SSH banner containing Astra Linux
		"ssh banner:\"astra\"",                             // SSH banner with astra keyword
		"ssh banner:\"AstraLinux\"",                        // SSH banner with AstraLinux keyword
		"\"Astra Linux\" port:22",                          // Port 22 with Astra Linux
		"\"astra\" \"debian\" port:22",                     // Astra with Debian on SSH
		"\"orel\" \"astra\"",                               // Orel is another keyword for Astra
		"product:\"OpenSSH\" \"astra\"",                    // OpenSSH with astra
		"\"SE Linux\" \"astra\"",                           // SELinux with astra (Astra has SELinux)
		"\"Red OS\" OR \"Astra Linux\" OR \"astra linux\"", // Multiple Astra variants
		"\"astra.ru\"",                                     // Astra domain references
		"\"astralinux.ru\"",                                // AstraLinux domain
	}

	// Store all results for combined analysis
	var allMatches []shodan.ShodanMatch
	var allGeoData []geomapper.GeoMapData

	timestamp := time.Now().Format("20060102_150405")

	for i, query := range queries {
		fmt.Printf("Running query %d/%d: %s\n", i+1, len(queries), query)

		results, err := shodan.SearchShodan(apiKey, query)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error searching Shodan for query '%s': %v\n", query, err)
			continue
		}

		fmt.Printf("Query: %s - Found %d total results, retrieved %d matches\n",
			query, results.Total, len(results.Matches))

		// Save individual query results
		queryFileName := fmt.Sprintf("query_%02d_%s.json", i+1, report.SanitizeFilename(query))
		queryFilePath := filepath.Join(outputDir, queryFileName)

		queryData := map[string]interface{}{
			"query":     query,
			"timestamp": timestamp,
			"total":     results.Total,
			"matches":   results.Matches,
		}

		if err := report.SaveJSON(queryData, queryFilePath); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving query results: %v\n", err)
			continue
		}

		// Convert to geo data and append to combined results
		geoData := geomapper.ConvertToGeoData(results.Matches)
		allGeoData = append(allGeoData, geoData...)
		allMatches = append(allMatches, results.Matches...)

		// Rate limiting - be respectful to Shodan API
		if i < len(queries)-1 {
			fmt.Println("Waiting 2 seconds before next query...")
			time.Sleep(2 * time.Second)
		}
	}

	// Save combined results
	combinedData := map[string]interface{}{
		"scan_timestamp": timestamp,
		"total_queries":  len(queries),
		"total_matches":  len(allMatches),
		"queries_run":    queries,
		"all_matches":    allMatches,
	}

	combinedPath := filepath.Join(outputDir, fmt.Sprintf("combined_results_%s.json", timestamp))
	if err := report.SaveJSON(combinedData, combinedPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving combined results: %v\n", err)
		os.Exit(1)
	}

	// Save geo mapping data
	geoPath := filepath.Join(outputDir, fmt.Sprintf("geo_data_%s.json", timestamp))
	if err := report.SaveJSON(allGeoData, geoPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving geo data: %v\n", err)
		os.Exit(1)
	}

	// Create summary report
	summary := report.CreateSummary(queries, allMatches, allGeoData, timestamp)
	summaryPath := filepath.Join(outputDir, fmt.Sprintf("scan_summary_%s.json", timestamp))
	if err := report.SaveJSON(summary, summaryPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving summary: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n=== SCAN COMPLETE ===\n")
	fmt.Printf("Total queries executed: %d\n", len(queries))
	fmt.Printf("Total matches found: %d\n", len(allMatches))
	fmt.Printf("Unique geolocated hosts: %d\n", len(allGeoData))
	fmt.Printf("\nResults saved to '%s' directory:\n", outputDir)
	fmt.Printf("- Individual query results: query_XX_*.json\n")
	fmt.Printf("- Combined results: %s\n", filepath.Base(combinedPath))
	fmt.Printf("- Geo mapping data: %s\n", filepath.Base(geoPath))
	fmt.Printf("- Scan summary: %s\n", filepath.Base(summaryPath))
	fmt.Printf("\nReady for AI analysis!\n")
}
