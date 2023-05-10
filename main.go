package main

import (
	"bufio"
	"encoding/json"
	"flag"
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

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

type EmailData struct {
	Iptracked    string
	Locatedip    []Located
	Useragent    string
	Browser      string
	Warninglevel int
}

type Located struct {
	Continent_code string
	Continent_name string
	Name_country   string
	Code_country   string
	City_name      string
	Organiz        string
}

type Iplocation struct {
	Ip             string `json:"ip"`
	Code_continent string `json:"continent_code"`
	Name_continent string `json:"continent_name"`
	Country_name   string `json:"country_name"`
	Country_code   string `json:"country_code2"`
	City           string `json:"city"`
	Organization   string `json:"organization"`
}

func isSuspectLine(line string, ip string) bool {

	//maxcount := 3

	//on regarde si notre string contient une erreur 401 après un POST depuis le login
	if strings.Contains(line, "POST /auth/login/") && strings.Contains(line, "401") {
		return true
	}

	//on check si notre string contient le mot sqlmap
	if strings.Contains(line, "sqlmap") {
		return true
	}

	//on check si notre string contient le mot gobuster
	if strings.Contains(line, "gobuster") {
		return true
	}

	return false
}

func sendEmail() {
	//from est la variable de l'expéditeur
	from := mail.NewEmail("INTRUSION DETECTION SYSTEM", "sfekaier@gmail.com")

	//subject est la variable du sujet du mail
	subject := "CODE RED ALERT : INTRUSION DETECTED"

	//to est la variable du receveur
	to := mail.NewEmail("IDS DEVELOPPERS", "sfekaier@gmail.com")

	//plainTexteContent est la variable du corps du mail
	plainTextContent := "Warning : check ids logs now"

	//htmlContent est la variable du corps du mail mais avec du html
	htmlContent := "<strong>It's a important message !</strong>"

	//message est la variable qui réuni les variables en un mail
	message := mail.NewSingleEmail(from, subject, to, plainTextContent, htmlContent)

	//set une template dynamic
	message.SetTemplateID("")

	//client va utiliser l'API sendgrid et se préparer à l'envoie du mail
	client := sendgrid.NewSendClient("")

	//response va envoyer le mail grâce à la variable client
	response, err := client.Send(message)

	if err != nil {
		log.Println(err)
	} else {
		fmt.Println(response.StatusCode)
		fmt.Println(response.Body)
		fmt.Println(response.Headers)
	}
}
func sniffer() {
	var filter = flag.String("filter", "", "BPF filter for capture")
	var iface = flag.String("iface", "ens33", "Select interface where to capture")
	var snaplen = flag.Int("snaplen", 1024, "Maximun sise to read for each packet")
	var promisc = flag.Bool("promisc", false, "Enable promiscuous mode")
	var timeoutT = flag.Int("timeout", 30, "Connection Timeout in seconds")
	log.Println("start")
	defer log.Println("end")

	flag.Parse()

	var timeout time.Duration = time.Duration(*timeoutT) * time.Second

	handle, err := pcap.OpenLive(*iface, int32(*snaplen), *promisc, timeout)
	if err != nil {
		log.Fatal(err)
	}

	defer handle.Close()

	if *filter != "" {
		log.Println("applying filter ", *filter)
		err := handle.SetBPFFilter(*filter)
		if err != nil {
			log.Fatalf("error applyign BPF Filter %s - %v", *filter, err)
		}
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		fmt.Println(packet)
	}
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

	//scanlog nous permet de faire un scan dans le fichier log
	scanlog := bufio.NewScanner(accessLog)

	//la boucle nous permettra de scanner les différentes ligne des logs
	for {
		if scanlog.Scan() {

			//line récupère ces lignes sous forme de texte
			line := scanlog.Text()
			//log.Println(line)
			re := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`) // expression régulière pour récupérer l'adresse IP
			match := re.FindString(line)
			log.Println(match)
			ipList := make(map[string]bool)
			ipList[match] = true

			outputFile, err := os.Open("ip_list_visitor.txt")
			if err != nil {
				fmt.Println("Erreur lors de la création du fichier des ip visiteurs:", err)
				return
			}
			defer outputFile.Close()

			// Écrire les adresses IP uniques dans le fichier de sortie
			writer := bufio.NewWriter(outputFile)
			for ip := range ipList {
				fmt.Fprintln(writer, ip)
			}

			writer.Flush()

			//si la fonction isSuspectLine retourne vrai cela affiche la line d'intrusion suspecté avec l'ip et etc
			if isSuspectLine(line, match) {
				log.Println("Intrusion détéctée dans les logs : ", line)
				Iplocator(match)
				//sendEmail()

			}
		} else if scanlog.Err() != nil {
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
