package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

type EmailData struct {
	iptracked    string
	located      string
	useragent    string
	browser      string
	warninglevel int
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
	var iface = flag.String("iface", "en0", "Select interface where to capture")
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

func main() {

	exec.Command("clear")
	//accessLog est notre variable qui contient le fichier log et err sera la variable d'erreur
	for {
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
		for scanlog.Scan() {

			//line récupère ces lignes sous forme de texte
			line := scanlog.Text()
			//log.Println(line)
			re := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`) // expression régulière pour récupérer l'adresse IP
			match := re.FindString(line)
			log.Println(match)

			//si la fonction isSuspectLine retourne vrai cela affiche la line d'intrusion suspecté avec l'ip et etc
			if isSuspectLine(line, match) {
				log.Println("Intrusion détéctée dans les logs : ", line)
				//sendEmail()

			}
		}

		//en cas d'erreur cela affiche une erreur
		if err := scanlog.Err(); err != nil {
			log.Println("Erreur lors de la lecture du fichier de logs : ", err)
		}
	}

}
