# Système de détection d'intrusion développé en intégralité en golang

<p align="center">
    <img src="https://miro.medium.com/v2/resize:fit:1400/1*Ifpd_HtDiK9u6h68SZgNuA.png" title="golang img">
</p>
Le système de détection d'intrusion a été créée dans un but d'un projet cybersec. 
Munie d'un expéditeur de mail l'utilisateur pourra       recevoir une alerte depuis ses mails. 
<br>
Contient les systèmes suivants :
+Lecture d'access.log 
+Retrouve les lignes suspectes en cas de brute force ou autres
+Ipgéolocalisation
+Envoies des mails 
<br>
Cependant le système n'est qu'une mvp et aura d'autres versions par la suite.
<br>

## DEMARRAGE :

Avant toutes choses veuillez mettre votre email dans la fonction sendEmail à la place de (Mettez votre email ici) :

```golang
	//to est la variable du receveur
	to := mail.NewEmail("IDS DEVELOPPERS", "(METTEZ VOTRE EMAIL ICI)")

	//message est la variable qui utilise la v3 de sendgrid
	message := mail.NewV3Mail()
	//on set l'expediteur
	message.SetFrom(from)
```
--------------------------------------------------------------------------------

Afin d'utiliser le programme veuillez à ce que setup.sh soit installé et fait pour cela suivez les étapes :

1. Executez chmod +x afin de lui donner les droits
```bash
sudo chmod +x setup.sh
```
2. Puis executez setup.sh :
```bash
sudo bash setup.sh
```

## RESOURCES :

- [pkg.go.dev (gopacket)](https://pkg.go.dev/github.com/google/gopacket)
- [devdungeon](https://www.devdungeon.com/content/packet-capture-injection-and-analysis-gopacket)
- [cameronroberts (API)](https://cameronroberts.dev/posts/consuming-restapi-golang/)
