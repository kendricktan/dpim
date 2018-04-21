from __future__ import print_function
from Tkinter import *

import os
import address
import pickle
import threading
import argparse
import crypto
import dag
import socket
import json
import tkFont


class ChatApplication(Frame):
    def __init__(self, port, user_sk, user_pk, *args, **kwargs):
        # DAG state, sk, pk, and DAG state
        self.port = port
        self.user_pk = user_pk
        self.user_sk = user_sk

        self.dag_state = dag.DAG()
        self.peer_ports = []

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('localhost', port))

        threading.Thread(target=self.listen_thread).start()

        # GUI Stuff below
        self.window = Tk()
        self.window.grid_rowconfigure(0, weight=1)
        self.window.grid_rowconfigure(3, weight=1)

        Frame.__init__(self, self.window, *args, **kwargs)

        # Font
        self.font_large = tkFont.Font(
            family='Helvetica', size=28, weight='bold')
        self.font_medium = tkFont.Font(
            family='Helvetica', size=20, weight='bold')
        self.font_small = tkFont.Font(
            family='sans-serif', size=16)

        # Label
        self.info_string = StringVar()
        self.info_string.set(
            'port: {} | address: {}'.format(port, self.user_pk))
        self.info_entry = Entry(self.window, text=self.info_string)
        self.info_entry['font'] = self.font_small        
        self.info_entry.grid(row=0, column=0, sticky=N+S+E+W)

        # Command textbox window
        self.xscrollbar = Scrollbar(self.window, orient=HORIZONTAL)
        self.xscrollbar.grid(row=2, column=0, sticky=N+S+E+W)

        self.yscrollbar = Scrollbar(self.window)
        self.yscrollbar.grid(row=1, column=1, sticky=N+S+E+W)

        self.cmd_txtbox = Text(self.window, width=60, height=15, wrap=NONE,
                               xscrollcommand=self.xscrollbar.set,
                               yscrollcommand=self.yscrollbar.set)
        self.cmd_txtbox['font'] = self.font_medium
        self.cmd_txtbox.see(END)
        self.cmd_txtbox.grid(row=1, column=0)

        # Input string
        self.input_user = StringVar()
        self.input_field = Entry(self.window, text=self.input_user)
        self.input_field.bind("<Return>", self.send_cmd)
        self.input_field['font'] = self.font_large
        self.input_field.grid(row=3, column=0, sticky=N+S+E+W)

    def send_to_server(self, data, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('localhost', port))
        s.send(data)

    def listen_thread(self):
        self.sock.listen(5)
        while True:
            sc, sa = self.sock.accept()
            sc.settimeout(60)
            threading.Thread(target=self.listen_to_client,
                             args=(sc, sa)).start()

    def listen_to_client(self, client, _):
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
                if self.dag_state.hash_received(tx.hash):
                    client.close()
                    return

                # If we haven't received them then add them to state
                # and broadcast it to our peers
                self.dag_state.insert_tx(pk, tx)

                list(map(lambda x: threading.Thread(
                    target=self.send_to_server, args=(data, x)).start(), self.peer_ports))

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
                        self.cmd_txtbox.insert(END, "[!] Message received!\n")
                        self.cmd_txtbox.see(END)
                        msg_raw = crypto.decrypt(f_sk, source_tx.msg)
                        self.dag_state.add_message(source_tx.hash, msg_raw)

        except Exception as e:
            print(e)
            pass

        client.close()

    def send_cmd(self, e):
        cmd = self.input_field.get()

        # Clear inputs
        self.input_user.set('')
        
        cmd_arr = cmd.split(' ')

        try:
            if cmd_arr[0] == 'send':
                pk = cmd_arr[1]
                msg = ' '.join(cmd_arr[2:])

                if len(pk) != 128:
                    self.cmd_txtbox.insert(END, '[!] Invalid public key\n')
                    self.cmd_txtbox.see(END)
                    return

                [target_pk, f_sk, r_pk] = address.generate_stealth_address(pk)

                # Get last tx to construct sendtx
                last_tx = self.dag_state.get_latest(self.user_pk)

                # Open account if isn't open
                if last_tx is None:
                    last_tx = dag.mine_tx(
                        dag.OpenTx(self.user_pk, None, 0)
                    )
                    self.dag_state.insert_tx(self.user_pk, last_tx)

                    last_data = pickle.dumps({'pk': self.user_pk, 'tx': last_tx})
                    list(map(lambda x: threading.Thread(
                        target=self.send_to_server, args=(last_data, x)).start(), self.peer_ports))

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
                self.dag_state.insert_tx(self.user_pk, send_tx)

                self.cmd_txtbox.insert(END, 'Hash (send): {}\n'.format(send_tx.hash))

                # Broadcast tx
                send_data = pickle.dumps({'pk': self.user_pk, 'tx': send_tx})
                list(map(lambda x: threading.Thread(target=self.send_to_server,
                                                    args=(send_data, x)).start(), self.peer_ports))

                # Receive tx
                # Open stealth address account
                open_tx = dag.mine_tx(
                    dag.OpenTx(target_pk, None, 0)
                )
                self.dag_state.insert_tx(target_pk, open_tx)

                open_data = pickle.dumps({'pk': target_pk, 'tx': open_tx})
                list(map(lambda x: threading.Thread(target=self.send_to_server,
                                                    args=(open_data, x)).start(), self.peer_ports))

                # Construct send tx
                recv_tx = dag.mine_tx(
                    dag.ReceiveTx(open_tx.hash, None, send_tx.hash, 0)
                )
                self.dag_state.insert_tx(target_pk, recv_tx)

                self.cmd_txtbox.insert(END, 'Hash (receive): {}\n'.format(recv_tx.hash))

                recv_data = pickle.dumps({'pk': target_pk, 'tx': recv_tx})
                list(map(lambda x: threading.Thread(target=self.send_to_server,
                                                    args=(recv_data, x)).start(), self.peer_ports))

            elif cmd_arr[0] == 'open':
                pk = cmd_arr[1]
                tx = dag.mine_tx(
                    dag.OpenTx(pk, None, 0)
                )

                self.dag_state.insert_tx(pk, tx)

                # Print out stuff
                self.cmd_txtbox.insert(END, 'Hash: {}\n'.format(tx.hash))

                # Broadcast data
                data = pickle.dumps({'pk': pk, 'tx': tx})
                list(map(lambda x: threading.Thread(
                    target=self.send_to_server, args=(data, x)).start(), self.peer_ports))

            elif cmd_arr[0] == 'getaccount':
                self.cmd_txtbox.insert(END, json.dumps(self.dag_state.get_account(cmd_arr[1]), indent=4) + "\n")

            elif cmd_arr[0] == 'getmessages':
                self.cmd_txtbox.insert(END, json.dumps(self.dag_state.get_messages(), indent=4) + "\n")

            elif cmd_arr[0] == 'getmessage':
                h = cmd_arr[1]
                m = self.dag_state.get_message(h)

                if m is None:
                    self.cmd_txtbox.insert(END, 'Message not found or message is encrypted\n')

                else:
                    self.cmd_txtbox.insert(END, '{}\n'.format(m))

            elif cmd_arr[0] == 'gethash':
                tx = self.dag_state.get_hash(cmd_arr[1])

                if tx == None:
                    self.cmd_txtbox.insert(END, 'Not found!\n')
                else:
                    d = tx._asdict()
                    d['type'] = type(tx).__name__
                    self.cmd_txtbox.insert(END, json.dumps(d, indent=4) + "\n")

            elif cmd_arr[0] == 'addpeer':
                port = int(cmd_arr[1])
                self.peer_ports.append(port)
                self.cmd_txtbox.insert(END, 'Added peer: localhost:{}\n'.format(port))

            elif cmd_arr[0] == 'listpeers':
                self.cmd_txtbox.insert(END, json.dumps({'peers': self.peer_ports}, indent=4) + "\n")

            elif cmd_arr[0] == 'clear':
                self.cmd_txtbox.delete('1.0', END)

            elif cmd_arr[0] == 'listpk':
                self.cmd_txtbox.insert(END, '{}\n'.format(self.user_pk))

            elif cmd_arr[0] == 'quit':
                quit()
            
            else:
                self.cmd_txtbox.insert(END, "[!] Unknown command\n")
        
        except Exception as e:
            print(e)
            self.cmd_txtbox.insert(END, "[!] Invalid command\n")

        # Scroll to the end
        self.cmd_txtbox.see(END)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='DPIM - Decentralized Private Instant Messaging')
    parser.add_argument('--port', required=True, type=int,
                        help='Port daemon is going to operate on')
    parser.add_argument(
        '--sk', type=str, default=str(address.generate_key_pair()[0]), help='Set a secret key')

    args = parser.parse_args()

    user_sk = args.sk
    user_pk = address.derive_public_key(user_sk)

    window = ChatApplication(args.port, user_sk, user_pk)
    window.mainloop()
