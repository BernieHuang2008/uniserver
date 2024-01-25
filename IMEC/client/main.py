import socket
import enc
import json
import threading
import hashlib
import random


def jreplace(s, key, value):
    j = json.loads(s)
    j[key] = value
    return json.dumps(j)

def getref(msg):
    return hashlib.sha256(msg).hexdigest()[:6]


def randmsg():
    return getref(str(random.random()))


def start(identity):
    # start a TCP socket, connect to localhost:5005
    IMECserver = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    IMECserver.connect(('localhost', 5005))

    # Stage 1: Welcome
    data = IMECserver.recv(1024)  # Receive 1024 bytes of data from the server
    if not data:
        print(
            '\033[93m' + f'  [!] Failed to receive data from the server, Disconnect.' + '\033[0m')
        IMECserver.close()
        return -1
    data = json.loads(data.decode('utf-8'))  # decode json
    if data['type'] != 'welcome':
        print(
            '\033[93m' + f'  [!] Failed to receive welcome message, Disconnect.' + '\033[0m')
        IMECserver.close()
        return -1
    address = IMECserver.getsockname()
    address = address[0]+':'+str(address[1])
    # send welcome response
    IMECserver.send(b'{"type": "welcome", "addr": "' +
                    address.encode('utf-8')+b'"}')

    # Stage 2: Handshake
    data = IMECserver.recv(1024)  # Receive 1024 bytes of data from the server
    data = json.loads(data.decode('utf-8'))  # decode json
    if data['type'] != 'handshake':
        print(
            '\033[93m' + f'  [!] Failed to receive handshake message, Disconnect.' + '\033[0m')
        IMECserver.close()
        return -1
    server_key = enc.EncryptionKey.load_public_key(
        enc.invbase64(data['key']))  # load server public key
    mykey = enc.generate_key()  # generate client key
    IMECserver.send(b'{"type": "handshake", "key": "' + enc.base64(
        mykey.get_public_key().save_pkcs1()) + b'"}')  # send handshake response

    # Stage 2.5: go into encrypted mode
    def send(data):
        IMECserver.send(server_key.encrypt(data))

    def recv(maximum=1024):
        return json.loads(mykey.decrypt(IMECserver.recv(maximum)))

    def guess_size(data):
        return len(server_key.encrypt(data))

    # Stage 3: Identity
    data = recv()
    if data['type'] != 'ok':
        print(
            '\033[93m' + f'  [!] Failed to receive ok message, Disconnect.' + '\033[0m')
        IMECserver.close()
        return -1
    # send identity response
    send('{"type": "identity", "name": "'+identity+'"}')
    data = recv()
    if data['type'] != 'ok':
        print(
            '\033[93m' + f'  [!] Failed to receive ok message, Disconnect.' + '\033[0m')
        IMECserver.close()
        return -1

    return wrap(send, recv, guess_size, identity)


def wrap(send, recv, guess_size, identity):
    """Receive"""
    def final_recv(maxsize=10240):
        data = recv(maxsize)
        if data['type'] == 'msg':
            # special options
            if 'spec' in data:
                # enlarge message window
                if data['spec'] == 'enlarge':
                    msg = randmsg()
                    send('{"type": "ok", "msg": "'+msg+'"}')
                    return final_recv(data['size'])
                
            # normal receive
            else:
                return data['from'], data['msg']
    add_listener = start_listen(final_recv)

    """Send"""
    def raw_send(to, request, reply='ORIGIN'):
        size = guess_size(request)
        if size < 10240:
            send(request)
        else:
            # send a 'spec-enlarge' message first
            msg = randmsg()
            request2 = '{"type": "msg", "from": "'+identity+'", "to": "'+to+'", "reply": "'+reply+'", "msg": "'+msg+'", "spec": "enlarge", "size": '+str(size+100)+'}'
            raw_send(to, request2, reply)

            def then(ref, from_, response):
                if response['type'] != 'ok':
                    raise Exception('Failed to receive enlarge message window: "{}" responed with fatal.'.format(to))
                request = jreplace(request, 'reply', getref(response['msg']))
                # send the real message
                send(request)

            # add a response listener
            add_listener(getref(msg), then)

    def final_send(to, msg, reply='ORIGIN'):
        request = '{"type": "msg", "from": "'+identity+'", "to": "'+to+'", "reply": "'+reply+'", "msg": "'+msg+'"}'
        raw_send(to, request, reply)

    return final_send, add_listener


def start_listen(frecv):
    listeners = {
        'ref_hash': 'function(ref, from_, data)',
    }

    def add_listener(ref, func):
        listeners[ref] = func

    def listen(frecv):
        while True:
            from_, msg = frecv()
            ref = getref
            if ref in listeners:
                func = listeners.pop(ref)
                t = threading.Thread(target=func, args=(ref, from_, msg))
                t.start()
            else:
                pass

    thread = threading.Thread(target=listen, args=(frecv))
    thread.start()  # start listening
    return add_listener, getref


if __name__ == '__main__':
    send, add_listener = start('test')
