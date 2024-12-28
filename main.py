import socket, threading
from time import sleep
from cryptidy import asymmetric_encryption as ae

# guess what this does
def run_client(privateKey, publicKey):
    # prompt user for host and port
    host = input("host: ")
    port = int(input("port: "))

    # setup client socket
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clientSocket.connect((host, port))

    serverKey = clientSocket.recv(4069).decode('utf-8')

    print(serverKey)

    # encrypt public key and send it to the server
    send_server(clientSocket, publicKey, serverKey)
    print(publicKey)

    # tell the server we are ready to start sending messages
    send_server(clientSocket, "START_CONNECTION", serverKey)

    # start sending messages
    threading.Thread(target=recieve_messages, args=(clientSocket, privateKey,), daemon=True).start()
    send_messages(clientSocket, serverKey)


# listen for messages from the server
def recieve_messages(client, privateKey):
    while 1:
        # recieve a 4096 bit block of data and decrypt it
        time, message = recv_server(client, privateKey)
        # print it to the screen
        print(time, message)


# keep asking for and sending messages to server
def send_messages(client, serverKey):
    while 1:
        # get input and encrypt it using the servers public key
        message = input()

        # send the message to the server
        send_server(client, message, serverKey)


# Send the specified message to the server, using its key as encryption
def send_server(socket, message, serverKey):
    message = ae.encrypt_message(message, serverKey)
    socket.send(message)


# get and decrypt a message from the server
def recv_server(socket, privateKey):
    message = socket.recv(4096)
    time, message = ae.decrypt_message(message, privateKey)
    return time, message


if __name__ == "__main__":
    print("starting client...")
    # generate the keypair
    print("generating keypairs...")

    privateKey, publicKey = ae.generate_keys(4096)

    print("succes!")
    run_client(privateKey, publicKey)
