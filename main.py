# Copyright 2024, 2025 Floris Tabak
#
# This file is part of PrivMe
# PrivMe is a free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public Licence as published by the
# Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# PrivMe is distributed in the hope taht it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
# License for more details.
#
# You should have recieved a copy of the GNU General Public License
# along with PrivMe. If not, see <https://www.gnu.org/licenses/>.

import socket, threading
from time import sleep
import asymmetric_encryption as ae

# guess what this does
def run_client(privateKey, publicKey):
    # prompt user for host and port
    host = input("host: ")
    port = int(input("port: "))

    # setup client socket
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clientSocket.connect((host, port))

    # recieve the server Key
    serverKey = clientSocket.recv(4069).decode('utf-8')

    # From this point onwards we only use asymmetrical encryption
    # Messages must be encrypted with the servers public key

    # send the public key to the server
    send_server(clientSocket, publicKey, serverKey)

    # Wait for the server to ping us
    recv_server(clientSocket, privateKey)

    username_transfer(clientSocket, privateKey, serverKey)

    group_transfer(clientSocket, privateKey, serverKey)

    # tell the server we are ready to start sending messages
    send_server(clientSocket, "START_CONNECTION", serverKey)

    # start sending messages
    threading.Thread(target=recieve_messages, args=(clientSocket, privateKey,), daemon=True).start()
    send_messages(clientSocket, serverKey)


def username_transfer(clientSocket, privateKey, serverKey):
    # start the username transfer
    send_server(clientSocket, "START_NAME_TRANSFER", serverKey)

    # Recieve the max length for usernames
    time, maxUserLength = recv_server(clientSocket, privateKey)

    usernameStatus = "INVALID"

    #continue prompting for username until it meets server requirements
    while usernameStatus != "VALID":

        print(f"username must be less than {maxUserLength} chars")

        #prompt the user for their name
        username = input("username: ")

        # Send the username to the server
        send_server(clientSocket, username, serverKey)

        time, usernameStatus = recv_server(clientSocket, privateKey)
        print(usernameStatus)


def group_transfer(clientSocket, privateKey, serverKey):
    send_server(clientSocket, "START_GROUP_SELECT", serverKey) # 1

    time, groups = recv_server(clientSocket, privateKey) # 2

    print(f"there are {len(groups)} groups:")
    print(groups)

    while 1:
        action = input("do you want to [join] or [create] a group (join): ")
        if action != "create":
            send_server(clientSocket, "join", serverKey) # 3

            time, status = recv_server(clientSocket, privateKey) # 4

            try:
                group = input("which group would you like to join?: ")
            except KeyboardInterrupt:
                send_server(clientSocket, 0x01, serverKey) # 5
                recv_server(clientSocket, privateKey) # 6
                print('\n')
                continue

            send_server(clientSocket, group, serverKey) # 5

            time, status = recv_server(clientSocket, privateKey) # 6
            if status == "BAD":
                print(f"invalid group {group}")
                continue

            elif status == "NO PASSWORD":
                print("this server does not have a password")
                print("proceed with caution")

            else:
                password = input("password: ")
                password = ae.generate_hash(password)
                send_server(clientSocket, password, serverKey)# 7

                time, status = recv_server(clientSocket, privateKey) # 8
                if status == "INCORRECT":
                    print("password is incorrect")
                    continue

            break

        else:
            send_server(clientSocket, "create", serverKey) # 3

            recv_server(clientSocket, privateKey) # 4

            try:
                group = input("enter name of group: ")
            except KeyboardInterrupt:
                send_server(clientSocket, 0x01, serverKey) # 5
                recv_server(clientSocket, privateKey) # 6
                print('\n')
                continue

            send_server(clientSocket, group, serverKey) # 5

            time, status = recv_server(clientSocket, privateKey) # 6
            if status == "BAD":
                print("group already exists")
                continue

            password = input("password: ")
            if password != "":
                password = ae.generate_hash(password)
            send_server(clientSocket, password, serverKey)# 7

            break



# listen for messages from the server
def recieve_messages(client, privateKey):
    while 1:
        # recieve a 4096 bit block of data and decrypt it
        time, message = recv_server(client, privateKey)

        if message == "SPAM":
            raise Exception("stop spamming nerd")
            quit()

        # print it to the screen
        print(time, message)


# keep asking for and sending messages to server
def send_messages(client, serverKey):
    while 1:
        # get input and encrypt it using the servers public key
        message = input()
        if bytes(message, 'utf-8') == b'':
            print("your message has been blocked because it is empty")

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
