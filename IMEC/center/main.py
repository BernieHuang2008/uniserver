import threading
import json
import socket

import enc


def start():
    # start a TCP server
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 5005))  # Bind to localhost:5005
    # Start listening for connections, allow a maximum of 100 pending connections
    server.listen(100)

    while True:
        client, address = server.accept()  # Accept a client connection
        # change to a different thread
        thread = threading.Thread(target=handle_client, args=(client, address))
        thread.start()


def handshake(client, address):
    """
    Error Codes:
      -1: Failed to receive data
      -2: Failed to decode json
      -3: Failed to get specified data

    """
    # send welcome message
    client.send(b'{"type": "welcome"}')

    data = client.recv(1024)  # Receive 1024 bytes of data from the client

    # check data
    if not data:
        print(
            '\033[93m' + f'  [{address}] [!] Failed to the response from {address}, Disconnect.' + '\033[0m')
        client.close()
        return -1

    # welcome response
    try:
        json_data = json.loads(data.decode('utf-8'))

        # check if the data is welcome response
        if json_data['type'] != 'welcome' or json_data['addr'] != address:
            print(
                f'\033[93m  [{address}] [!] Failed to recv welcome response, Disconnect.\033[0m')
            client.close()
            return -3
    except json.decoder.JSONDecodeError:
        print(
            f'\033[93m  [{address}] [!] Failed to decode the response (Not JSON), Disconnect.\033[0m')
        client.close()
        return -2
    except KeyError:
        print(
            f'\033[93m  [{address}] [!] Failed to recv welcome response, Disconnect.\033[0m')
        client.close()
        return -3

    # generate encryption key
    key = enc.generate_key()

    # send handshake
    client.send(b'{"type": "handshake", "key": "' +
                key.get_public_key().save_pkcs1() + b'"}')

    # receive handshake response
    data = client.recv(1024)
    json_data = json.loads(data.decode('utf-8'))
    if json_data['type'] == 'handshake':
        client_key = enc.EncryptionKey.load_public_key(json_data['key'])

    return key, client_key


def get_identity(recv, send):
    send(b'{"type": "ok"}')
    data = recv()
    if data['type'] == 'identity':
        service_name = data['name']
        pass  # TODO: check if the service is registered
    else:
        0/0


def get_duty(recv, send):
    send(b'{"type": "ok"}')
    data = recv()
    if data['type'] == 'duty':
        if data['duty'] == 'subscribe':
            return 'subscribe'
        elif data['duty'] == 'send':
            return 'send'
    else:
        0/0


def handle_client(client, address):
    print('\033[93m' + f' [*] New connection from {address}' + '\033[0m')

    mykey, ckey = handshake(client, address)

    def send(data):
        client.send(ckey.encrypt(data))

    def recv(maximun=1024):
        return json.loads(mykey.decrypt(client.recv(maximun).decode('utf-8')))

    identity = get_identity(recv, send)
    duty = get_duty(recv, send)


if __name__ == '__main__':
    start()
