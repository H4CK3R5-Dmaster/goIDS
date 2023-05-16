package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
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

func containsString(strs []string, str string) bool {
	count := 0
	for _, s := range strs {
		if strings.Contains(s, str) {
			count++
			if count >= 5 {
				return true
			}
		}
	}
	return false
}

func isSuspectLine(line string) bool {

	maxcount := 5
	ipcount := make(map[string][]string)

	for i := 1; i <= maxcount; i++ {
		re := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`) // expression régulière pour récupérer l'adresse IP
		match := re.FindString(line)

		ipcount[match] = append(ipcount[match], line)
		//on regarde si notre string contient une erreur 401 après un POST depuis le login
		if strings.Contains(line, "POST /auth/login/") && strings.Contains(line, "401") {

			count := len(ipcount[match])

			if count >= maxcount {
				reqs := ipcount[match][count-5:]
				if containsString(reqs, "POST /auth/login/") && containsString(reqs, "401") {
					Iplocator(match)
					exec.Command("firewall-cmd", "--direct", "--add-rule", "ipv4", "filter", "INPUT", "1", "-m", "tcp", "--source", match, "-p", "tcp", "--dport", "80", "-j", "REJECT")
					go func() {
						time.Sleep(24 * time.Hour)

						unblockCmd := exec.Command("firewall-cmd", "--direct", "--remove-rule", "ipv4", "filter", "INPUT", "1", "-m", "tcp", "--source", match, "-p", "tcp", "--dport", "80", "-j", "ACCEPT")
						if err := unblockCmd.Run(); err != nil {
							fmt.Printf("Erreur lors de la suppression de la règle de blocage pour l'IP %s : %v\n", match, err)
						} else {
							fmt.Printf("IP %s débloquée\n", match)
						}
					}()
					return true
				}

			}

		}

		//on check si notre string contient le mot sqlmap
		if strings.Contains(line, "sqlmap") {

			re := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`) // expression régulière pour récupérer l'adresse IP
			match := re.FindString(line)
			count := len(ipcount[match])

			if count >= maxcount {
				reqs := ipcount[match][count-5:]
				if containsString(reqs, "sqlmap") {
					Iplocator(match)
					exec.Command("firewall-cmd", "--direct", "--add-rule", "ipv4", "filter", "INPUT", "1", "-m", "tcp", "--source", match, "-p", "tcp", "--dport", "80", "-j", "REJECT")
					go func() {
						time.Sleep(24 * time.Hour)

						unblockCmd := exec.Command("firewall-cmd", "--direct", "--remove-rule", "ipv4", "filter", "INPUT", "1", "-m", "tcp", "--source", match, "-p", "tcp", "--dport", "80", "-j", "ACCEPT")
						if err := unblockCmd.Run(); err != nil {
							fmt.Printf("Erreur lors de la suppression de la règle de blocage pour l'IP %s : %v\n", match, err)
						} else {
							fmt.Printf("IP %s débloquée\n", match)
						}
					}()
					return true
				}

			}

		}

		//on check si notre string contient le mot gobuster
		if strings.Contains(line, "gobuster") {
			re := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`) // expression régulière pour récupérer l'adresse IP
			match := re.FindString(line)
			count := len(ipcount[match])

			if count >= maxcount {
				reqs := ipcount[match][count-5:]
				if containsString(reqs, "gobuster") {
					Iplocator(match)
					exec.Command("firewall-cmd", "--direct", "--add-rule", "ipv4", "filter", "INPUT", "1", "-m", "tcp", "--source", match, "-p", "tcp", "--dport", "80", "-j", "REJECT")
					go func() {
						time.Sleep(24 * time.Hour)

						unblockCmd := exec.Command("firewall-cmd", "--direct", "--remove-rule", "ipv4", "filter", "INPUT", "1", "-m", "tcp", "--source", match, "-p", "tcp", "--dport", "80", "-j", "ACCEPT")
						if err := unblockCmd.Run(); err != nil {
							fmt.Printf("Erreur lors de la suppression de la règle de blocage pour l'IP %s : %v\n", match, err)
						} else {
							fmt.Printf("IP %s débloquée\n", match)
						}
					}()
					return true
				}

			}

		}
		if strings.Contains(line, "Nikto") {
			re := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`) // expression régulière pour récupérer l'adresse IP
			match := re.FindString(line)
			count := len(ipcount[match])

			if count >= maxcount {
				reqs := ipcount[match][count-5:]
				if containsString(reqs, "Nikto") {
					Iplocator(match)
					exec.Command("firewall-cmd", "--direct", "--add-rule", "ipv4", "filter", "INPUT", "1", "-m", "tcp", "--source", match, "-p", "tcp", "--dport", "80", "-j", "REJECT")
					go func() {
						time.Sleep(24 * time.Hour)

						unblockCmd := exec.Command("firewall-cmd", "--direct", "--remove-rule", "ipv4", "filter", "INPUT", "1", "-m", "tcp", "--source", match, "-p", "tcp", "--dport", "80", "-j", "ACCEPT")
						if err := unblockCmd.Run(); err != nil {
							fmt.Printf("Erreur lors de la suppression de la règle de blocage pour l'IP %s : %v\n", match, err)
						} else {
							fmt.Printf("IP %s débloquée\n", match)
						}
					}()
					return true
				}

			}

		}

	}

	return false
}

func sendEmail(ip string, codecontinent string, namecontinent string, countrycode string, countryname string, city string, orga string) error {

	dynamicData := make(map[string]interface{})
	dynamicData["ip"] = ip
	if codecontinent != "" {
		dynamicData["codecontinent"] = codecontinent
	} else {
		dynamicData["codecontinent"] = ""
	}
	if namecontinent != "" {
		dynamicData["namecontinent"] = namecontinent
	} else {
		dynamicData["namecontinent"] = ""
	}
	if countrycode != "" {
		dynamicData["countrycode"] = countrycode
	} else {
		dynamicData["countrycode"] = ""
	}
	if countryname != "" {
		dynamicData["countryname"] = countryname
	} else {
		dynamicData["countryname"] = ""
	}
	if city != "" {
		dynamicData["city"] = city
	} else {
		dynamicData["city"] = ""
	}
	if orga != "" {
		dynamicData["orga"] = orga
	} else {
		dynamicData["orga"] = ""
	}

	//client va utiliser l'API sendgrid et se préparer à l'envoie du mail
	client := sendgrid.NewSendClient("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")
	//from est la variable de l'expéditeur
	from := mail.NewEmail("INTRUSION DETECTION SYSTEM", "seiffekaier@gmail.com")

	//to est la variable du receveur
	to := mail.NewEmail("IDS DEVELOPPERS", "sfekaier@gmail.com")

	//message est la variable qui réuni les variables en un mail
	message := mail.NewV3Mail()

	message.SetFrom(from)
	message.SetTemplateID("d-708cc747c17d4091aa7519ed1c514fa7")

	perso := mail.NewPersonalization()
	perso.AddTos(to)
	for key, value := range dynamicData {
		perso.SetDynamicTemplateData(key, value)
	}

	message.AddPersonalizations(perso)

	//response va envoyer le mail grâce à la variable client
	response, err := client.Send(message)

	if err != nil {
		log.Println(err)
	} else {
		if response.StatusCode >= 400 {
			log.Println("error")
		}
		fmt.Println(response.StatusCode)
		fmt.Println(response.Body)
		fmt.Println(response.Headers)
		return nil
	}
	return nil
}

func Iplocator(ip string) {
	log.Println("call API...")
	apikey := "08ce3f5b88fa4d0d9c2b601afecdc350"
	response, err := http.Get("https://api.ipgeolocation.io/ipgeo?apiKey=" + apikey + "&ip=" + ip)

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

	sendEmail(responseObject.Ip, responseObject.Code_continent, responseObject.Name_continent, responseObject.Country_code, responseObject.Country_name, responseObject.City, responseObject.Organization)

}

func main() {

	exec.Command("clear")
	//accessLog est notre variable qui contient le fichier log et err sera la variable d'erreur

	accessLog, err := os.Open("/var/log/apache2/access.log")
	//sniffer()

	//si l'erreur n'est pas null alors on print l'erreur
	if err != nil {
		log.Println("Erreur de l'ouverture des logs apache2 : ", err)
		return
	}

	//on ferme le fichier accesslog
	defer accessLog.Close()

	//la boucle nous permettra de scanner les différentes ligne des logs
	for {
		//scanlog nous permet de faire un scan dans le fichier log
		scanlog := bufio.NewScanner(accessLog)
		for scanlog.Scan() {

			//line récupère ces lignes sous forme de texte
			line := scanlog.Text()
			//log.Println(line)

			//si la fonction isSuspectLine retourne vrai cela affiche la line d'intrusion suspecté avec l'ip et etc

			if isSuspectLine(line) {
				log.Println("Intrusion détéctée dans les logs : ", line)
				//Iplocator(match)
				//sendEmail()

			}
		}
		if scanlog.Err() != nil {
			// En cas d'erreur lors de la lecture, afficher l'erreur et arrêter la boucle
			log.Fatal(scanlog.Err())
			log.Println("Erreur lors de la lecture du fichier de logs : ", err)
			break
		}
	}
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

}
