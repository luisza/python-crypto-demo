#!/bin/bash 

mkdir -p db
mkdir -p ca

/bin/echo -n '01' > db/serial.txt
touch db/index.txt
touch db/index.txt.attr

openssl req -days 2922 -config openssl.cnf -newkey rsa:4096 -nodes -out ca/cert.pem -x509 -keyout ca/key.pem
openssl x509 -outform der -in ca/cert.pem -out ca/cert.crt
