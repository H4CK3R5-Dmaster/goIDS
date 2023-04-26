package main

import (
	"fmt"
	"log"
	"os"

	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)


func sendEmail() {
	from := mail.NewEmail("INTRUSION DETECTION SYSTEM", "sfekaier@gmail.com")
	subject := "CODE RED ALERT : INTRUSION DETECTED"
	to := mail.NewEmail("IDS DEVELOPPERS", "sfekaier@gmail.com")
	plainTextContent := "Warning : check ids logs now"
	htmlContent := "<strong>It's a important message !</strong>"
	message := mail.NewSingleEmail(from, subject, to, plainTextContent, htmlContent)
	client := sendgrid.NewSendClient(os.Getenv("API"))
	response, err := client.Send(message)

	if err != nil {
        log.Println(err)
    } else {
        fmt.Println(response.StatusCode)
        fmt.Println(response.Body)
        fmt.Println(response.Headers)
    }
}