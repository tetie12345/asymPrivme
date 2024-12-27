import socket, threading
from cryptidy import asymmetric_encryption as ae

# Some server constants
HOST = "0.0.0.0"
PORT = 5556
SERVER_VERSION = 0.0

# Server variables
clients = []      # These variables are synced
keys = []       # This means users[1] corresponds to keys[1]


# Send a message to all clients except the sender
def send_message(sender, message):
    # Loop over all of the connected clients
    for i in range(len(clients)):
        # Check if the current client is the sender, if it is, skip it
        if clients[i] == sender:
            continue

        # Send the message to the client with their respective key
        msg = ae.encrypt_message(message, keys[i])
        clients[i].send(msg)


# Handle the clients
# This function is run for every connected client
def handle_client(client, publicKey, privateKey, clientKey):

    # Start the handshake
    Recieving = False

    try:
        while not Recieving:
            # Setup the connection as per the clients requests
            message = client.recv(4096)
            time, message = ae.decrypt_message(message, privateKey)

            if message == "START_CONNECTION":
                # Start recieving messages from client
                Recieving = True

            print(message)

        # Recieve messages from the client
        while 1:
            message = client.recv(4096)

            if message == b'':
                remove_client(client)
                return

            time, message = ae.decrypt_message(message, privateKey)

            print(time, message)
            send_message(client, f"{message}")


            # This next part should self-explanetory

    except Exception as error:
        print(f"Error: {error}")


# Removes a client
def remove_client(client):
    clientId = clients.index(client)
    clients.pop(clientId)
    keys.pop(clientId)

    client.close()


# Guess what this does
def run_server():
    print("starting server...")

    # Initialise the keys
    print("creating keypair...")
    privateKey, publicKey = ae.generate_keys(4096)
    print(publicKey, privateKey)

    print("setting up socket...")
    # Initialise the server
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSocket.bind((HOST, PORT))
    serverSocket.listen()

    print("succes!")

    print(f"started server on {HOST}:{PORT}")

    while 1:
        # Recieve clients
        client, address = serverSocket.accept()

        # Register the user
        clients.append(client)

        # Send public key to the client
        client.send(publicKey.encode())

        # Recieve clients public key and decrypt it
        clientKey = client.recv(4096)
        time, clientKey = ae.decrypt_message(clientKey, privateKey)

        # Add the key to the list of keys
        keys.append(clientKey)

        # Start a worker thread that will handle this client
        threading.Thread(target=handle_client, args=(client, publicKey, privateKey, clientKey)).start()



if __name__ == "__main__":
    run_server()
