package shodan

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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

	url := fmt.Sprintf("https://api.shodan.io/shodan/host/search?key=%s&query=%s", apiKey, query)

	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var result ShodanResponse
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON response: %w", err)
	}

	return &result, nil
}
