#!/bin/bash

GREEN="\033[0;32m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
NC="\033[0m"
printf "${YELLOW}===================================================\n${NC}"
printf "${YELLOW}||          SETUP Intrusion detect system        ||\n${NC}"
printf "${YELLOW}===================================================\n${NC}"

if ! command -v go &> /dev/null
then
    printf "${YELLOW}Golang n'est pas installé. Installation en cours...\n${NC}"
    sudo apt-get update
    sudo apt-get install -y golang-go
    printf "${GREEN}Golang a été installé avec succès.\n${NC}"
fi
if ! command -v firewalld &> /dev/null
then
    printf "${YELLOW}Firewalld n'est pas installé. Installation en cours...\n${NC}"
    sudo apt-get update
    sudo apt-get install -y firewalld
    printf "${GREEN}Firewalld a été installé avec succès.\n${NC}"
fi

mkdir /etc/IDS
cp -r goIDS/ /etc/IDS
printf "${YELLOW}Démarrage de /etc/IDS/goIDS/main.go...\n${NC}"
printf "${YELLOW}Configuration du démarrage automatique de /etc/IDS/goIDS/main.go...\n${NC}"
sudo tee /etc/systemd/system/IDSmain.service <<EOF
[Unit]
Description=IDSmain service

[Service]
Type=simple
WorkingDirectory=/etc/IDS/goIDS/
Environment=GO111MODULE=on
Environment="GOPATH=${HOME}/go"
Environment="GOMODCACHE=${HOME}/go/pkg/mod"

Environment="GOCACHE=${HOME}/go"

Restart=always
RestartSec=5s
ExecStartPre=/usr/bin/go mod download
ExecStart=/usr/bin/go run /etc/IDS/goIDS/main.go

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable IDSmain.service
sudo systemctl start IDSmain.service
printf "${GREEN}Le démarrage automatique de /etc/IDS/goIDS/main.go a été configuré avec succès.\n${NC}"
