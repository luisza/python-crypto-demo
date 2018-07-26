# python-crypto-demo
Demostración de uso de criptografía en python

Este es un repositorio de demostración creado especialmente para el meetup pythonCR, en él se muestran algunos conceptos básicos de 
criptográfía.

# El proyecto

Se realizará un chat (servidor y cliente) por donde se transmitirán mensajes, los cuales serán encriptados de diferentes formas.

- Usando XOR
- Usando AES_EAX
- Usando RSA + AES_EAX 

Se utilizan las bibliotecas Pycrypto, PyOpenSSL, pycryptodome, que pueden encontrarse en el archivo requirements.txt en cada paso.

# Composición del repositorio

Cada paso del taller tiene asociado un tag (release)

- v0.1  Simple chat server
- v0.2  Generate hashsum from string (sha256, sha384, sha512)
- v0.3  Encryption with XOR
- v0.4  AES_EAX example
- v0.5  Build openssl CA
- v0.6  Create certificates from CA in disc
- v0.7  Encrypt and Decrypt with RSA and AES_EAX

Happy hacking..
