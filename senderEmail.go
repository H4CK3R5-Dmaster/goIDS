package main

import (
	"fmt"
	"log"
	"os"

	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

//sendEmail nous permet d'envoyer un mail en cas d'intrusion
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
	client := sendgrid.NewSendClient(os.Getenv("API"))

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