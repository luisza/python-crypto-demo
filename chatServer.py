import socket
from threading import Thread
from cryptoManager import CryptoManager
HOST="127.0.0.1"
PORT=12345
MAX_BUFFER_SIZE = 4096

def client_thread(conn, ip, port):
    finished=False
    cryptomanager = CryptoManager('client_cert.pem', 'server_key.pem')
    print("Start comunication with %s : %s" %( ip , port))
    while not finished:
        input_from_client_bytes = conn.recv(MAX_BUFFER_SIZE)
        print("antes: ", repr(input_from_client_bytes))
        input_from_client = cryptomanager.decrypt(input_from_client_bytes)
        
        print("despues: ", repr(input_from_client))
        if input_from_client == "exit":
            finished=True
            conn.sendall(cryptomanager.encrypt("Bye"))
            break
        elif input_from_client == "hello":
            conn.sendall(cryptomanager.encrypt("hello word"))
        else:
            conn.sendall(cryptomanager.encrypt("sorry not hello"))
    conn.shutdown(1)
    conn.close()  # close connection
    print("Close connection with " + ip + ':' + port)


soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# this is for easy starting/killing the app
soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
print('Socket created')

try:
    soc.bind((HOST, PORT))
    print('Socket bind complete')
except socket.error as msg:
    import sys
    print('Bind failed. Error : ' + str(sys.exc_info()))
    sys.exit()

#Start listening on socket
soc.listen(10)
print('Socket now listening')

while True:
    conn, addr = soc.accept()
    ip, port = str(addr[0]), str(addr[1])
    print('Accepting connection from %s : %s'%( ip , port))

    try:
        Thread(target=client_thread, args=(conn, ip, port)).start()
    except:
        print("Terible error!")
        import traceback
        traceback.print_exc()
soc.close()

start_server()  
