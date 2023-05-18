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

//création de la structure Iplocation
type Iplocation struct {
	Ip             string `json:"ip"`
	Code_continent string `json:"continent_code"`
	Name_continent string `json:"continent_name"`
	Country_name   string `json:"country_name"`
	Country_code   string `json:"country_code2"`
	City           string `json:"city"`
	Organization   string `json:"organization"`
}

/* prend en entrée une slice de chaînes de caractères (strs) et 
une chaîne de caractères (str) à rechercher. Elle renvoie true si str est 
contenu dans au moins cinq éléments de strs, sinon elle renvoie false */
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

//permet de détecter toutes requêtes suspectes
func isSuspectLine(line string) bool {
	//max 5 requêtes
	maxcount := 5
	
	//map pour récuperer les ip
	ipcount := make(map[string][]string)

	for i := 1; i <= maxcount; i++ {
		re := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`) // expression régulière pour récupérer l'adresse IP
		match := re.FindString(line) //récupére les IP qui match avec le regex

		ipcount[match] = append(ipcount[match], line) // ajout des ip et leurs requêtes
		
		//on regarde si notre string contient une erreur 401 après un POST depuis le login
		if strings.Contains(line, "POST /auth/login/") && strings.Contains(line, "401") {

			count := len(ipcount[match]) // count est égale à la taille de ipcount 
			
			//si count est supérieur ou égale à 5
			if count >= maxcount { 
				reqs := ipcount[match][count-5:] //récupére les 5 derniers slices de l'ip
				if containsString(reqs, "POST /auth/login/") && containsString(reqs, "401") {
					Iplocator(match) //renvoies à la fonction pour géolocaliser l'ip
					//execute une règle ACL
					exec.Command("firewall-cmd", "--direct", "--add-rule", "ipv4", "filter", "INPUT", "1", "-m", "tcp", "--source", match, "-p", "tcp", "--dport", "80", "-j", "REJECT")
					//permet de débannir l'ip après 24h
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
			match := re.FindString(line)//récupére les IP qui match avec le regex
			count := len(ipcount[match])// count est égale à la taille de ipcount 

			//si count est supérieur ou égale à 5
			if count >= maxcount {
				reqs := ipcount[match][count-5:] //récupére les 5 derniers slices de l'ip
				if containsString(reqs, "sqlmap") {
					Iplocator(match) //fonction de géolocalisation
					//mise en place règle ACL
					exec.Command("firewall-cmd", "--direct", "--add-rule", "ipv4", "filter", "INPUT", "1", "-m", "tcp", "--source", match, "-p", "tcp", "--dport", "80", "-j", "REJECT")
					//débannir l'ip après 24h
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
			match := re.FindString(line)//récupére les IP qui match avec le regex
			count := len(ipcount[match]) // count est égale à la taille de ipcount 

			//si count est égale à 5
			if count >= maxcount {
				reqs := ipcount[match][count-5:] //recupère les 5 derniers slices de l'ip
				if containsString(reqs, "gobuster") {
					Iplocator(match)//géolocalisation
					//règle ACL
					exec.Command("firewall-cmd", "--direct", "--add-rule", "ipv4", "filter", "INPUT", "1", "-m", "tcp", "--source", match, "-p", "tcp", "--dport", "80", "-j", "REJECT")
					//débannir après 24h
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
		//on check si notre string contient le mot Nikto
		if strings.Contains(line, "Nikto") {
			re := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`) // expression régulière pour récupérer l'adresse IP
			match := re.FindString(line) //récupére les IP qui match avec le regex
			count := len(ipcount[match]) //count est égale à la taille de ipcount de l'ip

			// count est égale à 5
			if count >= maxcount {
				reqs := ipcount[match][count-5:] // on récupère les 5 derniers slices de l'ip
				if containsString(reqs, "Nikto") {
					Iplocator(match)//géolocalisation
					//règle ACL
					exec.Command("firewall-cmd", "--direct", "--add-rule", "ipv4", "filter", "INPUT", "1", "-m", "tcp", "--source", match, "-p", "tcp", "--dport", "80", "-j", "REJECT")
					//débannir après 24h
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
//permet d'envoyer un mail avec les données de l'IP
func sendEmail(ip string, codecontinent string, namecontinent string, countrycode string, countryname string, city string, orga string) error {
	
	dynamicData := make(map[string]interface{})
	dynamicData["ip"] = ip
	//vérification si les paramètres sont vide ou pas
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

	//client va utiliser l'API key sendgrid et se préparer à l'envoie du mail
	client := sendgrid.NewSendClient("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")
	//from est la variable de l'expéditeur
	from := mail.NewEmail("INTRUSION DETECTION SYSTEM", "seiffekaier@gmail.com") //ne pas changer l'email sender

	//to est la variable du receveur
	to := mail.NewEmail("IDS DEVELOPPERS", "(METTEZ VOTRE EMAIL ICI)")

	//message est la variable qui utilise la v3 de sendgrid
	message := mail.NewV3Mail()
	//on set l'expediteur
	message.SetFrom(from)
	//on set l'ID d'une template
	message.SetTemplateID("d-708cc747c17d4091aa7519ed1c514fa7")
	//on ajoute une petite personnalisation
	perso := mail.NewPersonalization()
	//on ajoute le receveur
	perso.AddTos(to)
	//pour chaque key - value de dynamicData on set les variables dynamiques du mail
	for key, value := range dynamicData {
		perso.SetDynamicTemplateData(key, value)
	}
	//message va récupérer toute la personnalisation
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
//permet de geolocaliser l'ip suspectes et envoyer les données à sendEmail
func Iplocator(ip string) {
	log.Println("call API...")
	//apiKy de iplocation
	apikey := "08ce3f5b88fa4d0d9c2b601afecdc350"
	//on prépare une requête get pour récupérer les données
	response, err := http.Get("https://api.ipgeolocation.io/ipgeo?apiKey=" + apikey + "&ip=" + ip)

	if err != nil {
		log.Println("error : ", err)
	}
	//on read la totalité des résultats du body de http
	responseData, err := ioutil.ReadAll(response.Body)

	if err != nil {
		log.Println("error : ", err)
	}
	//on créer une variable de type Iplocation
	var responseObject Iplocation
	
	//est utilisée pour décoder (ou désérialiser) des données JSON contenues dans la variable responseData et les stocker dans une variable de type structuré responseObject
	json.Unmarshal(responseData, &responseObject)

	log.Println(responseObject.Ip)
	log.Println(responseObject.Code_continent)
	log.Println(responseObject.Name_continent)
	log.Println(responseObject.Country_code)
	log.Println(responseObject.Country_name)
	log.Println(responseObject.City)
	//appelles sendEmail et donne en paramètre les données de l'ip
	sendEmail(responseObject.Ip, responseObject.Code_continent, responseObject.Name_continent, responseObject.Country_code, responseObject.Country_name, responseObject.City, responseObject.Organization)

}
//fonction principal où tout démarre
func main() {

	
	//accessLog est notre variable qui contient le fichier log et err sera la variable d'erreur
	accessLog, err := os.Open("/var/log/apache2/access.log")
	

	//si l'erreur n'est pas null alors on print l'erreur
	if err != nil {
		log.Println("Erreur de l'ouverture des logs apache2 : ", err)
		return
	}

	//on retarde la fermeture d'accessLog
	defer accessLog.Close()

	//la boucle nous permettra de scanner les différentes ligne des logs
	for {
		//scanlog nous permet de faire un scan dans le fichier log
		scanlog := bufio.NewScanner(accessLog)
		for scanlog.Scan() {

			//line récupère ces lignes sous forme de texte
			line := scanlog.Text()
			

			//si la fonction isSuspectLine retourne vrai cela affiche la line d'intrusion suspecté avec l'ip et etc

			if isSuspectLine(line) {
				log.Println("Intrusion détéctée dans les logs : ", line)

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
