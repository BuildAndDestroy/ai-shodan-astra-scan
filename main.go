package main

import (
	"anthropic-shodan-scan/pkg/envfile"
	"anthropic-shodan-scan/pkg/geomapper"
	"anthropic-shodan-scan/pkg/report"
	"anthropic-shodan-scan/pkg/shodan"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func main() {
	countOnly := flag.Bool("count", false, "only report result counts and version facets per query (uses no query credits)")
	facets := flag.String("facets", "version:15", "facets to request in -count mode (e.g. \"version:15,port:10\")")
	envPath := flag.String("env", ".env", "path to a .env file containing SHODAN_API_KEY")
	flag.Parse()

	if err := envfile.Load(*envPath); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not read %s: %v\n", *envPath, err)
	}

	apiKey := os.Getenv("SHODAN_API_KEY")
	if apiKey == "" {
		fmt.Fprintf(os.Stderr, "Error: SHODAN_API_KEY is required (set it in the environment or in %s)\n", *envPath)
		os.Exit(1)
	}

	// Create output directory
	outputDir := "shodan_results"
	// #nosec G301 -- results dir must stay traversable on the host when created by the root container via a bind mount
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output directory: %v\n", err)
		os.Exit(1)
	}

	// Multiple search queries for Astra Linux
	queries := []string{
		"10+deb9u6astra6",                                  // specific package version
		"deb9u6astra*",                                     // specific package version with wildcard
		"deb10u1astra*",                                    // specific package version with wildcard
		"deb10u1astra6se11",                                // specific package version
		"deb10u1astra8se8+ci3",                             // specific package version
		"deb10u1astra6se9+ci1",                             // specific package version
		"deb10u1astra8se5",                                 // specific package version
		"deb10u1astra6se14",                                // specific package version
		"deb10u1astra6se10",                                // specific package version
		"10+deb9u6astra6se5",                               // specific package version
		"10+deb9u6astra6se5+b1",                            // specific package version
		"deb10u1astra8se7",                                 // specific package version
		"deb10u1astra8se4+b1",                              // specific package version
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

		// --- SSH builds not covered above ---
		"deb9u4astra*", // Smolensk 1.6 ISO ships OpenSSH_7.4p1 Debian-10+deb9u4astra6se3 (0 hits as of 2026-11; sentinel)

		// --- Non-SSH signals (validated with -count / banner review, 2026-11) ---
		// Shodan strips punctuation, so "#astra"/"+astra"/"(Astra)" all degrade to
		// plain "astra" (~26k noisy hits). Match whole tokens instead.
		"astralinux",          // Apache "(AstraLinux)" 2.4.52/2.4.57/2.4.62 (SE 1.7/1.8) + BIND "…-AstraLinux-2.12.45"
		"\"AstraLinuxCE\"",    // CE 2.12.46 Apache Server header: "Apache/2.4.46 (AstraLinuxCE)"
		"\"AstraLinuxSE\"",    // SE Apache Server header: "Apache/2.4.46 (AstraLinuxSE)"
		"\"Astra Linux\"",     // Postfix "(Astra Linux/GNU)", node exporter os-release, rsync mirrors
		"\"Astra Linux/GNU\"", // Postfix smtpd banner: "ESMTP Postfix (Astra Linux/GNU)"
		"product:\"Prometheus Node Exporter\" \"astra\"",      // node_os_info: exact version_id + "#astraNN+ciNN" kernel
		"\"9.11.3-1ubuntu1.15+ci202105041610+astra1-Debian\"", // CE 2.12.4x BIND version.bind response
		"os:\"Astra Linux\"", // Shodan OS fingerprint field (cheap to test)
	}

	if *countOnly {
		runCounts(apiKey, queries, *facets)
		return
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

// runCounts reports the total and facet breakdown for each query using the
// Shodan count endpoint, which does not consume query credits.
func runCounts(apiKey string, queries []string, facets string) {
	for i, query := range queries {
		res, err := shodan.CountShodan(apiKey, query, facets)
		if err != nil {
			fmt.Printf("%2d. %-55s ERROR: %v\n", i+1, query, err)
		} else {
			fmt.Printf("%2d. %-55s total=%d\n", i+1, query, res.Total)
			for name, buckets := range res.Facets {
				for _, b := range buckets {
					fmt.Printf("      %s: %-50v %d\n", name, b.Value, b.Count)
				}
			}
		}
		if i < len(queries)-1 {
			time.Sleep(1 * time.Second)
		}
	}
}
