package report

import (
	"anthropic-shodan-scan/pkg/geomapper"
	"anthropic-shodan-scan/pkg/shodan"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

func SanitizeFilename(query string) string {
	sanitized := strings.ReplaceAll(query, "\"", "")
	sanitized = strings.ReplaceAll(sanitized, " ", "_")
	sanitized = strings.ReplaceAll(sanitized, ":", "")
	sanitized = strings.ReplaceAll(sanitized, "/", "_")
	sanitized = strings.ReplaceAll(sanitized, "\\", "_")
	sanitized = strings.ReplaceAll(sanitized, "+", "plus")
	sanitized = strings.ReplaceAll(sanitized, "OR", "or")
	if len(sanitized) > 50 {
		sanitized = sanitized[:50]
	}
	return sanitized
}

func SaveJSON(data interface{}, filePath string) error {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	err = os.WriteFile(filePath, jsonData, 0644)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}
	return nil
}

func CreateSummary(queries []string, matches []shodan.ShodanMatch, geoData []geomapper.GeoMapData, timestamp string) map[string]interface{} {
	uniqueIPs := make(map[string]bool)
	countryCount := make(map[string]int)
	portCount := make(map[int]int)
	productCount := make(map[string]int)
	for _, match := range matches {
		uniqueIPs[match.IP] = true
		countryCount[match.Location.Country]++
		portCount[match.Port]++
		if match.Product != "" {
			productCount[match.Product]++
		}
	}
	return map[string]interface{}{
		"scan_timestamp":   timestamp,
		"queries_executed": len(queries),
		"total_matches":    len(matches),
		"unique_ips":       len(uniqueIPs),
		"geolocated_hosts": len(geoData),
		"countries_found":  len(countryCount),
		"top_countries":    GetTopN(countryCount, 10),
		"ports_found":      GetTopN(ConvertIntMap(portCount), 10),
		"products_found":   GetTopN(productCount, 10),
		"queries_used":     queries,
	}
}

func GetTopN(m map[string]int, n int) map[string]int {
	if len(m) <= n {
		return m
	}
	result := make(map[string]int)
	count := 0
	for k, v := range m {
		if count >= n {
			break
		}
		result[k] = v
		count++
	}
	return result
}

func ConvertIntMap(m map[int]int) map[string]int {
	result := make(map[string]int)
	for k, v := range m {
		result[fmt.Sprintf("%d", k)] = v
	}
	return result
}
