package shodan

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// ShodanResponse represents the response from Shodan API
type ShodanResponse struct {
	Matches []ShodanMatch `json:"matches"`
	Total   int           `json:"total"`
}

// ShodanMatch represents individual search results
type ShodanMatch struct {
	IP        string         `json:"ip_str"`
	Port      int            `json:"port"`
	Location  ShodanLocation `json:"location"`
	Banner    string         `json:"data"`
	Product   string         `json:"product"`
	Version   string         `json:"version"`
	Timestamp string         `json:"timestamp"`
	SSH       *ShodanSSH     `json:"ssh,omitempty"`
}

// ShodanLocation contains geolocation data
type ShodanLocation struct {
	Country     string  `json:"country_name"`
	CountryCode string  `json:"country_code"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
}

// ShodanSSH contains SSH-specific information
type ShodanSSH struct {
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"`
	Cipher      string `json:"cipher"`
	MAC         string `json:"mac"`
	Key         string `json:"key"`
}

func SearchShodan(apiKey, query string) (*ShodanResponse, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	var allMatches []ShodanMatch
	var totalResults int
	page := 1
	resultsPerPage := 100 // Shodan returns max 100 per page

	for {
		// Construct URL with pagination
		baseURL := "https://api.shodan.io/shodan/host/search"
		params := url.Values{}
		params.Add("key", apiKey)
		params.Add("query", query)
		params.Add("page", fmt.Sprintf("%d", page))

		requestURL := fmt.Sprintf("%s?%s", baseURL, params.Encode())

		resp, err := client.Get(requestURL)
		if err != nil {
			return nil, fmt.Errorf("HTTP request failed on page %d: %w", page, err)
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, fmt.Errorf("API request failed with status %d on page %d: %s", resp.StatusCode, page, string(body))
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to read response body on page %d: %w", page, err)
		}

		var pageResult ShodanResponse
		err = json.Unmarshal(body, &pageResult)
		if err != nil {
			return nil, fmt.Errorf("failed to parse JSON response on page %d: %w", page, err)
		}

		// Store total from first page
		if page == 1 {
			totalResults = pageResult.Total
			fmt.Printf("  Total results available: %d (fetching all pages...)\n", totalResults)
		}

		// Append matches from this page
		allMatches = append(allMatches, pageResult.Matches...)

		fmt.Printf("  Fetched page %d: %d results (total so far: %d/%d)\n",
			page, len(pageResult.Matches), len(allMatches), totalResults)

		// Check if we've retrieved all results or hit API limits
		if len(pageResult.Matches) < resultsPerPage || len(allMatches) >= totalResults {
			if len(allMatches) < totalResults {
				fmt.Printf("  Note: Retrieved %d of %d results (account limit reached)\n", len(allMatches), totalResults)
			}
			break
		}

		// Move to next page with rate limiting
		page++
		time.Sleep(1 * time.Second) // Be respectful to the API
	}

	return &ShodanResponse{
		Matches: allMatches,
		Total:   totalResults,
	}, nil
}
