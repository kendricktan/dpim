from __future__ import print_function

import os
import address
import pickle
import threading
import argparse
import crypto
import dag
import socket
import json

from pprint import pprint

parser = argparse.ArgumentParser(
    description='DPIM - Decentralized Private Instant Messaging')
parser.add_argument('--port', required=True, type=int,
                    help='Port daemon is going to operate on')
parser.add_argument(
    '--sk', type=str, default=str(address.generate_key_pair()[0]), help='Set a secret key')

args = parser.parse_args()

if __name__ == '__main__':
    # Peer ports
    peer_ports = []

    # DAG initial state
    dag_state = dag.DAG()

    # Secret and public key
    user_sk = args.sk
    user_pk = address.derive_public_key(user_sk)

    # Socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('localhost', args.port))

    # Verbose
    print('Welcome to DPIN - Decentralized Private Instant Messaging!')
    print('\t pk: {}'.format(user_pk))
    print('\t port: {}'.format(args.port))
    print('Commands:')
    print('\tlistpk')
    print('\taddpeer <port>')
    print('\tlistpeers')
    print('\tgetmessage <hash>')
    print('\tgetmessages')
    print('\tgethash <hash>')
    print('\topen <pk>')
    print('\tsend <pk> <msg (maximum 256 bytes)>')

    def send_to_server(data, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('localhost', port))
        s.send(data)

    def listen_thread():
        sock.listen(5)
        while True:
            sc, sa = sock.accept()
            sc.settimeout(60)
            threading.Thread(target=listen_to_client,
                             args=(sc, sa)).start()

    def listen_to_client(client, _):
        size = 4096

        try:
            data = client.recv(size)
            if data:
                # Set the response to echo back the received data
                response = data

                # Reconstruct tx
                resp_dict = pickle.loads(response)

                tx = resp_dict['tx']
                pk = resp_dict['pk']

                # Check if we have received the tx or not
                # If we have then don't do anything
                if dag_state.hash_received(tx.hash):
                    client.close()
                    return

                # If we haven't received them then add them to state
                # and broadcast it to our peers
                dag_state.insert_tx(pk, tx)

                list(map(lambda x: threading.Thread(
                    target=send_to_server, args=(data, x)).start(), peer_ports))

                if type(tx) == dag.SendTx:
                    # Get source tx
                    source_tx = tx

                    # Get random pk and target pk
                    r_pk = source_tx.rpk
                    t_pk = source_tx.destination

                    [constructed_t_pk, f_sk] = address.retrieve_stealth_address(
                        user_sk, r_pk
                    )

                    # If t_pk matches then its for the user
                    if t_pk == constructed_t_pk:
                        print("[!] Message received")
                        print(">: ", end='')
                        msg_raw = crypto.decrypt(f_sk, source_tx.msg)
                        dag_state.add_message(source_tx.hash, msg_raw)

        except:
            pass

        client.close()

    # Start socket threading
    tid = threading.Thread(target=listen_thread).start()

    while True:
        cmd = raw_input('[{}] >: '.format(args.port))

        cmd_arr = cmd.split(' ')

        try:
            if cmd_arr[0] == 'send':
                pk = cmd_arr[1]
                msg = ' '.join(cmd_arr[2:])

                if len(pk) != 128:
                    print('Invalid public key')
                    continue

                [target_pk, f_sk, r_pk] = address.generate_stealth_address(pk)

                # Get last tx to construct sendtx
                last_tx = dag_state.get_latest(user_pk)

                # Open account if isn't open
                if last_tx is None:
                    last_tx = dag.mine_tx(
                        dag.OpenTx(user_pk, None, 0)
                    )
                    dag_state.insert_tx(user_pk, last_tx)

                    last_data = pickle.dumps({'pk': user_pk, 'tx': last_tx})
                    list(map(lambda x: threading.Thread(
                        target=send_to_server, args=(last_data, x)).start(), peer_ports))

                # Encrypt message
                encrypted_msg = crypto.encrypt(f_sk, msg)

                # Send tx
                send_tx = dag.mine_tx(
                    dag.sign_sendtx(
                        user_sk,
                        dag.SendTx(last_tx.hash, None, r_pk,
                                   target_pk, None, encrypted_msg, 0)
                    )
                )
                dag_state.insert_tx(user_pk, send_tx)

                print('Hash (send): {}'.format(send_tx.hash))

                # Broadcast tx
                send_data = pickle.dumps({'pk': user_pk, 'tx': send_tx})
                list(map(lambda x: threading.Thread(target=send_to_server,
                                                    args=(send_data, x)).start(), peer_ports))

                # Receive tx
                # Open stealth address account
                open_tx = dag.mine_tx(
                    dag.OpenTx(target_pk, None, 0)
                )
                dag_state.insert_tx(target_pk, open_tx)

                open_data = pickle.dumps({'pk': target_pk, 'tx': open_tx})
                list(map(lambda x: threading.Thread(target=send_to_server,
                                                    args=(open_data, x)).start(), peer_ports))

                # Construct send tx
                recv_tx = dag.mine_tx(
                    dag.ReceiveTx(open_tx.hash, None, send_tx.hash, 0)
                )
                dag_state.insert_tx(target_pk, recv_tx)

                print('Hash (receive): {}'.format(recv_tx.hash))

                recv_data = pickle.dumps({'pk': target_pk, 'tx': recv_tx})
                list(map(lambda x: threading.Thread(target=send_to_server,
                                                    args=(recv_data, x)).start(), peer_ports))

            if cmd_arr[0] == 'open':
                pk = cmd_arr[1]
                tx = dag.mine_tx(
                    dag.OpenTx(pk, None, 0)
                )

                dag_state.insert_tx(pk, tx)

                # Print out stuff
                print('Hash: {}'.format(tx.hash))

                # Broadcast data
                data = pickle.dumps({'pk': pk, 'tx': tx})
                list(map(lambda x: threading.Thread(
                    target=send_to_server, args=(data, x)).start(), peer_ports))

            if cmd_arr[0] == 'getaccount':
                pprint(dag_state.get_account(cmd_arr[1]))

            if cmd_arr[0] == 'getmessages':
                pprint(dag_state.get_messages())

            if cmd_arr[0] == 'getmessage':
                h = cmd_arr[1]
                m = dag_state.get_message(h)

                if m is None:
                    print('Message not found or message is encrypted')

                else:
                    print(m)

            if cmd_arr[0] == 'gethash':
                tx = dag_state.get_hash(cmd_arr[1])

                if tx == None:
                    print('Not found!')
                else:
                    d = tx._asdict()
                    d['type'] = type(tx).__name__
                    print(json.dumps(d, indent=4))

            if cmd_arr[0] == 'addpeer':
                port = int(cmd_arr[1])
                peer_ports.append(port)

            if cmd_arr[0] == 'listpeers':
                pprint({'peers': peer_ports})

            if cmd_arr[0] == 'clear':
                os.system('clear')

            if cmd_arr[0] == 'listpk':
                pprint(user_pk)

            if cmd_arr[0] == 'quit':
                quit()

        except KeyboardInterrupt:
            quit()

        except Exception as e:
            print('Invalid command')
