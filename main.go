package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"

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

func main() {

	exec.Command("clear")
	//accessLog est notre variable qui contient le fichier log et err sera la variable d'erreur
	accessLog, err := os.Open("./var/log/apache2/access.log")

	//si l'erreur n'est pas null alors on print l'erreur
	if err != nil {
		fmt.Println("Erreur de l'ouverture des logs apache2 : ", err)
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
		//fmt.Println(line)
		re := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`) // expression régulière pour récupérer l'adresse IP
		match := re.FindString(line)
		fmt.Println(match)

		//si la fonction isSuspectLine retourne vrai cela affiche la line d'intrusion suspecté avec l'ip et etc
		if isSuspectLine(line, match) {
			fmt.Println("Intrusion détéctée dans les logs : ", line)
			//sendEmail()

		}
	}

	//en cas d'erreur cela affiche une erreur
	if err := scanlog.Err(); err != nil {
		fmt.Println("Erreur lors de la lecture du fichier de logs : ", err)
	}
}
