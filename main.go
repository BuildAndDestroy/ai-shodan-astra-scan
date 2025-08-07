package main

import (
	"anthropic-shodan-scan/pkg/geomapper"
	"anthropic-shodan-scan/pkg/shodan"
	"encoding/json"
	"fmt"
	"log"
	"os"
)

func main() {
	apiKey := os.Getenv("SHODAN_API_KEY")
	if apiKey == "" {
		fmt.Fprintf(os.Stderr, "Error: SHODAN_API_KEY environment variable is required\n")
		os.Exit(1)
	}

	// Search query for Astra Linux SSH servers
	// This targets systems that might be running Astra Linux based on SSH banner information
	// query := "ssh \"Astra Linux\" OR ssh banner:\"astra\" OR ssh banner:\"AstraLinux\""
	query := "10+deb9u6astra6"

	results, err := shodan.SearchShodan(apiKey, query)
	log.Println(results)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error searching Shodan: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Found %d total results\n", results.Total)
	fmt.Printf("Retrieved %d matches\n", len(results.Matches))

	// Convert to geo map format
	geoData := geomapper.ConvertToGeoData(results.Matches)

	// Output as JSON for geo mapping
	output, err := json.MarshalIndent(geoData, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n=== GEO MAP DATA ===")
	fmt.Println(string(output))

	// Save to file for external geo mapping tools
	err = os.WriteFile("astra_linux_locations.json", output, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nData saved to: astra_linux_locations.json\n")
	fmt.Printf("You can use this data with geo mapping libraries like Leaflet, Google Maps, or Mapbox\n")
}
