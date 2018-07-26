import socket
HOST="127.0.0.1"
PORT=12345
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as soc:
    soc.connect((HOST, PORT))
    finished=False
    while not finished:
        clients_input = input("client: ")
        if clients_input ==  "exit":
            finished=True
        soc.send(clients_input.encode("utf8")) # we must encode the string to bytes  
        result_bytes = soc.recv(4096) # the number means how the response can be in bytes  
        result_string = result_bytes.decode("utf8") # the return will be in bytes, so decode
        print("server: %s"%(result_string))

