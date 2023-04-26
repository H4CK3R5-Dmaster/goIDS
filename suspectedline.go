package main

import "strings"

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