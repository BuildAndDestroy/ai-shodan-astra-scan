package shodan

import (
	"encoding/json"
	"errors"
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
			return nil, fmt.Errorf("HTTP request failed on page %d: %w", page, redactKey(err))
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			return nil, fmt.Errorf("API request failed with status %d on page %d: %s", resp.StatusCode, page, string(body))
		}

		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
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

// FacetValue is one bucket of a Shodan facet breakdown
type FacetValue struct {
	Count int `json:"count"`
	Value any `json:"value"`
}

// CountResponse represents the response from the Shodan count endpoint
type CountResponse struct {
	Total  int                     `json:"total"`
	Facets map[string][]FacetValue `json:"facets"`
}

// CountShodan returns the total number of results for a query along with
// optional facet breakdowns (e.g. "version:20,port:10"). The count endpoint
// does not consume query credits.
func CountShodan(apiKey, query, facets string) (*CountResponse, error) {
	client := &http.Client{Timeout: 30 * time.Second}

	params := url.Values{}
	params.Add("key", apiKey)
	params.Add("query", query)
	if facets != "" {
		params.Add("facets", facets)
	}

	resp, err := client.Get("https://api.shodan.io/shodan/host/count?" + params.Encode())
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", redactKey(err))
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result CountResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse JSON response: %w", err)
	}
	return &result, nil
}

// redactKey strips the API key from errors returned by net/http. A *url.Error
// embeds the full request URL, which includes the "key" query parameter, so
// printing it unredacted would leak the Shodan API key into logs.
func redactKey(err error) error {
	var uerr *url.Error
	if !errors.As(err, &uerr) {
		return err
	}
	if u, perr := url.Parse(uerr.URL); perr == nil {
		q := u.Query()
		if q.Has("key") {
			q.Set("key", "REDACTED")
			u.RawQuery = q.Encode()
		}
		uerr.URL = u.String()
	} else {
		uerr.URL = "<redacted>"
	}
	return uerr
}
