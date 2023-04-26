package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

//isSuspectLine est une fonction qui lorsque l'on lui donne un string il vérifie si le string contient des mots suspect si c'est le cas il retourne vrai sinon faux
func isSuspectLine(line string) bool {

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

func main()  {
	
	//accessLog est notre variable qui contient le fichier log et err sera la variable d'erreur
	accessLog, err := os.Open("/var/log/apache2/access.log")

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

		//si la fonction isSuspectLine retourne vrai cela affiche la line d'intrusion suspecté avec l'ip et etc
		if isSuspectLine(line) {
			fmt.Println("Intrusion détéctée dans les logs : ", line)

		}
	}

	//en cas d'erreur cela affiche une erreur
	if err := scanlog.Err(); err != nil {
		fmt.Println("Erreur lors de la lecture du fichier de logs : ", err)
	}
}