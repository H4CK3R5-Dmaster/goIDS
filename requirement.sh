#!/bin/bash


if ! command -v go &> /dev/null
then
    
    sudo apt-get update
    sudo apt-get install -y golang-go
    echo "Golang a été installé avec succès."
else
    
    echo "Golang est déjà installé sur votre système."
fi
