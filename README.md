# DPIM - Decentrzlied, Private, Instant Messaging.

```bash
# Only supports python 2.7

# Use miniconda
pip install -r requirements.txt

# On terminal one
python main.py --port 8081

# On another terminal
python main.py --port 8081
```

## API

```
listpk
    - lists public key
addpeer <port>
    - acknowledges localhost@<port> as peer
listpeers
    - list acknowledged peers
getmessage <hash>
    - Gets the decrypted message of <hash> sendtx (should it exist)
getmessages
    - Get all received decrypted messages
gethash <hash>
    - Get tx of hash
open <pk>
    - Opens account for <pk>
send <pk> <msg (maximum 256 bytes)>
    - Sends <msg> to <pk>
```
