import socket
from cryptoManager import CryptoManager

HOST="127.0.0.1"
PORT=12345

crypto = CryptoManager('server_cert.pem', 'client_key.pem')
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as soc:
    soc.connect((HOST, PORT))
    finished=False
    while not finished:
        clients_input = input("client: ")
        if clients_input ==  "exit":
            finished=True
        clients_input =  crypto.encrypt(clients_input)
        print("send: ", repr(clients_input))
        soc.send(clients_input) # we must encode the string to bytes  
        result_bytes = soc.recv(4096) # the number means how the response can be in bytes  
        result_string = crypto.decrypt(result_bytes) # the return will be in bytes, so decode
        print("server: %s"%(result_string))

