package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func isSuspectLine(line string) bool {
	
	if strings.Contains(line, "POST /auth/login/") && strings.Contains(line, "401") {
		return true
	}

	if strings.Contains(line, "sqlmap") {
		return true
	}
	if strings.Contains(line, "gobuster") {
		return true
	}

	return false
}

func main()  {
	accessLog, err := os.Open("/var/log/apache2/access.log")
	if err != nil {
		fmt.Println("Erreur de l'ouverture des logs apache2")
		return
	}
	defer accessLog.Close()
	
	scanlog := bufio.NewScanner(accessLog)

	for scanlog.Scan() {
		line := scanlog.Text()

		if isSuspectLine(line) {
			fmt.Println("Intrusion détéctée dans les logs : ", line)

		}
	}

	if err := scanlog.Err(); err != nil {
		fmt.Println("Erreur lors de la lecture du fichier de logs : ", err)
	}
}