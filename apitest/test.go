package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
)

type Iplocation struct {
	Ip             string `json:"ip"`
	Code_continent string `json:"continent_code"`
	Name_continent string `json:"continent_name"`
	Country_name   string `json:"country_name"`
	Country_code   string `json:"country_code2"`
	City           string `json:"city"`
	Organization   string `json:"organization"`
}

func main() {
	log.Println("call API...")
	apikey := "08ce3f5b88fa4d0d9c2b601afecdc350"
	iplocator := "90.70.25.230"
	response, err := http.Get("https://api.ipgeolocation.io/ipgeo?apiKey=" + apikey + "&ip=" + iplocator)

	if err != nil {
		log.Println("error : ", err)
	}

	responseData, err := ioutil.ReadAll(response.Body)

	if err != nil {
		log.Println("error : ", err)
	}

	var responseObject Iplocation

	json.Unmarshal(responseData, &responseObject)

	log.Println(responseObject.Ip)
	log.Println(responseObject.Code_continent)
	log.Println(responseObject.Name_continent)
	log.Println(responseObject.Country_code)
	log.Println(responseObject.Country_name)
	log.Println(responseObject.City)
	log.Println(responseObject.Organization)
}
