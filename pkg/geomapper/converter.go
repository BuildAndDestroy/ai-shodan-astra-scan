package geomapper

import (
	"fmt"

	"anthropic-shodan-scan/pkg/shodan"
)

// ShodanMatch represents the input data structure from Shodan
type ShodanMatch = shodan.ShodanMatch
type Location = shodan.ShodanLocation
type SSH = shodan.ShodanSSH

// GeoMapData represents the output format for geo mapping
type GeoMapData struct {
	IP        string  `json:"ip"`
	Country   string  `json:"country"`
	City      string  `json:"city"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	Port      int     `json:"port"`
	SSHInfo   string  `json:"ssh_info"`
	Timestamp string  `json:"timestamp"`
}

func ConvertToGeoData(matches []ShodanMatch) []GeoMapData {
	var geoData []GeoMapData

	for _, match := range matches {
		// Only include results with valid location data
		if match.Location.Latitude != 0 || match.Location.Longitude != 0 {
			sshInfo := fmt.Sprintf("Product: %s, Version: %s", match.Product, match.Version)
			if match.SSH != nil {
				sshInfo += fmt.Sprintf(", Type: %s", match.SSH.Type)
			}

			geo := GeoMapData{
				IP:        match.IP,
				Country:   match.Location.Country,
				City:      match.Location.City,
				Latitude:  match.Location.Latitude,
				Longitude: match.Location.Longitude,
				Port:      match.Port,
				SSHInfo:   sshInfo,
				Timestamp: match.Timestamp,
			}
			geoData = append(geoData, geo)
		}
	}

	return geoData
}
