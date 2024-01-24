import socket
import enc
import json


def start(identity):
    # start a TCP socket, connect to localhost:5005
    IMECserver = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    IMECserver.connect(('localhost', 5005))

    # Stage 1: Welcome
    data = IMECserver.recv(1024)  # Receive 1024 bytes of data from the server
    if not data:
        print('\033[93m' + f'  [!] Failed to receive data from the server, Disconnect.' + '\033[0m')
        IMECserver.close()
        return -1
    data = json.loads(data.decode('utf-8'))  # decode json
    if data['type'] != 'welcome':
        print('\033[93m' + f'  [!] Failed to receive welcome message, Disconnect.' + '\033[0m')
        IMECserver.close()
        return -1
    address = IMECserver.getsockname()
    address = address[0]+':'+str(address[1])
    IMECserver.send(b'{"type": "welcome", "addr": "'+address.encode('utf-8')+b'"}')  # send welcome response

    # Stage 2: Handshake
    data = IMECserver.recv(1024)  # Receive 1024 bytes of data from the server
    data = json.loads(data.decode('utf-8'))  # decode json
    if data['type'] != 'handshake':
        print('\033[93m' + f'  [!] Failed to receive handshake message, Disconnect.' + '\033[0m')
        IMECserver.close()
        return -1
    server_key = enc.EncryptionKey.load_public_key(enc.invbase64(data['key']))  # load server public key
    mykey = enc.generate_key()  # generate client key
    IMECserver.send(b'{"type": "handshake", "key": "' + enc.base64(mykey.get_public_key().save_pkcs1()) + b'"}')  # send handshake response

    # Stage 2.5: go into encrypted mode
    def send(data):
        IMECserver.send(server_key.encrypt(data))
    def recv(maximum=1024):
        return json.loads(mykey.decrypt(IMECserver.recv(maximum)))

    # Stage 3: Identity
    data = recv()
    if data['type'] != 'ok':
        print('\033[93m' + f'  [!] Failed to receive ok message, Disconnect.' + '\033[0m')
        IMECserver.close()
        return -1
    send('{"type": "identity", "identity": "'+identity+'"}')  # send identity response
    data = recv()
    if data['type'] != 'ok':
        print('\033[93m' + f'  [!] Failed to receive ok message, Disconnect.' + '\033[0m')
        IMECserver.close()
        return -1
    
    return send, recv


if __name__ == '__main__':
    send, recv = start('test')


