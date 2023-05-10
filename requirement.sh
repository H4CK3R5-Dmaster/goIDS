#!/bin/bash


if ! command -v go &> /dev/null
then
    
    sudo apt-get update
    sudo apt-get install -y golang-go
    echo "Golang a été installé avec succès."
fi

mkdir /etc/IDS
cp main.go /etc/IDS

go run /etc/IDS/main.go


sudo tee /etc/systemd/system/IDSmain.service <<EOF
[Unit]
Description=IDSmain service

[Service]
Type=simple
Restart=always
RestartSec=5s
ExecStart=/usr/bin/go run /etc/IDS/main.go

[Install]
WantedBy=multi-user.target
EOF


sudo systemctl daemon-reload
sudo systemctl enable IDSmain.service
sudo systemctl start IDSmain.service
