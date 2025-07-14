// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package utils

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// IPinfo Format
// https://ipinfo.io/developers/data-types#geolocation-data
type Geo struct {
	Ip       string `json:"ip"`
	Country  string `json:"country"`
	Region   string `json:"region"`
	City     string `json:"city"`
	ZipCode  string `json:"postal"`
	Location string `json:"loc"`
	Org      string `json:"org"`
	Timezone string `json:"timezone"`
}

func NewGeo(ip string) (*Geo, error) {
	client := http.Client{
		Timeout: 1 * time.Second,
	}

	response, err := client.Get("https://ipinfo.io/" + ip)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	geo := &Geo{}
	if err = json.Unmarshal(body, geo); err != nil {
		return nil, err
	}
	return geo, nil
}

func (g *Geo) GetLatLng() (float64, float64, error) {
	ns := strings.Split(g.Location, ",")
	var err error
	if len(ns) == 2 {
		var lat, lng float64
		if lat, err = strconv.ParseFloat(ns[0], 64); err == nil {
			if lng, err = strconv.ParseFloat(ns[1], 64); err == nil {
				return lat, lng, nil
			}
		}
		return 0, 0, err
	}
	return 0, 0, errors.New("malformed location")
}
