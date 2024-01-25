import threading
import json
import socket
import hashlib

import enc


services = {
    'service_name': {
        'name': 'service_name',
        'addr': '',
        'socket': None,
        'key': [None, None],    # [my key, client key]
        'send': None,
        'recv': None,
    }
}


def getref(msg):
    return hashlib.sha256(msg).hexdigest()[:6]


def start():
    # start a TCP server
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 5005))  # Bind to localhost:5005
    # Start listening for connections, allow a maximum of 100 pending connections
    server.listen(100)

    while True:
        client, address = server.accept()  # Accept a client connection
        address = address[0]+':'+str(address[1])
        # change to a different thread
        thread = threading.Thread(target=handle_client, args=(client, address))
        thread.start()


def handshake(client, address):
    """
      IMEC Server (this)                  IMEC Client
    1.        --------- Welcom Message --------> 
    2.        <-------- Welcom Response --------
    3.        --------- Handshake Message ----->
    4.        <-------- Handshake Response -----
    5.        --------------- OK -------------->
    6.        <-------- Identity Response ------


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
                enc.base64(key.get_public_key().save_pkcs1()) + b'"}')

    # receive handshake response
    data = client.recv(1024)
    json_data = json.loads(data.decode('utf-8'))
    if json_data['type'] == 'handshake':
        client_key = enc.EncryptionKey.load_public_key(enc.invbase64(json_data['key']))

    return key, client_key


def get_identity(recv, send):
    send('{"type": "ok", "msg": "starting identify progress", "code": 0}')
    data = recv()
    if data['type'] == 'identity':
        service_name = data['name']
        # TODO: check if the service is registered
        send('{"type": "ok", "msg": "identify success", "code": 0}')
        return service_name
    else:
        0/0


def handle_client(client, address):
    """
    Error Codes:
      * 0: OK
      * 404: Target service not found

    """
    print('\033[93m' + f' [*] New connection from {address}' + '\033[0m')

    mykey, ckey = handshake(client, address)

    def send(data):
        client.send(ckey.encrypt(data))

    def recv(maximun=1024*1024):
        raw_data = mykey.decrypt(client.recv(maximun))
        return json.loads(raw_data)

    identity = get_identity(recv, send)

    services[identity] = {
        'name': identity,
        'addr': address,
        'socket': client,
        'key': [mykey, ckey],
        'send': send,
        'recv': recv,
    }

    print('\033[92m' + f' [+] {address} is now registed as "{identity}"' + '\033[0m')

    while True:
        data = recv()
        if data['type'] == 'msg':
            if 'to' in data and 'msg' in data:
                if data['to'] not in services:
                    ref = getref(data['msg'])
                    msg = '{"type": "error", "reply": "'+ref+'", "msg": "Target service not found", code: 404}'
                    send(msg)
                    continue
                else:
                    t_send = services[data['to']]['send']
                    data['from'] = identity     # just ensure
                    msg = json.dumps(data)
                    t_send(msg)


if __name__ == '__main__':
    start()
