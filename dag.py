import hashlib
import crypto

from collections import namedtuple

MIN_WORK = '000'

# directed acyclic graph primitives

# OpenTx
# params:
# account => which blockchain account you trying to open
# hash => hash of the opentx
# work => work done to get the 'valid' txid (starts with X amount of zeros)
OpenTx = namedtuple("OpenTx", "account hash work")

# SendTx
# params:
# prev => previous hash
# hash => hash of the sendtx
# rpk => random pk (for stealth address)
# signature => signature to verify that the sender authorized it
# msg => msg type
# work => work done to get the 'valid' hash (starts with X amount of zeros)
SendTx = namedtuple("SendTx", "prev hash rpk destination signature msg work")

# ReceiveTx
# params:
# prev => previous hash
# hash => hash of the receive tx
# source => source of the receiveTx (hash of the sendtx)
# work => work done to get the 'valid' hash (starts with X amount of zeros)
ReceiveTx = namedtuple("ReceiveTx", "prev hash source work")

# DAG


class DAG:
    def __init__(self, usedtxids={}, cachehash={}, cachedmessages={}, accounts={}):
        """
        params:

        usedtxids => {}
        cachehash => {}
        cachedmessages => {}
        accounts => {}        

        usedtxids is a dictionary containing used send txids
        cachehash is a dictionary where key: hash value: tx
        cachedmessages is a dictionary where key: hash, value: message
        accounts is a dictionary where each key is an address e.g.

        accounts = {
            'abcdefgh': {
                'latest': 5,
                1: tx(),
                2: tx(),
                3: tx()
            }
        }
        """
        self.usedtxids = usedtxids
        self.accounts = accounts
        self.cachehash = cachehash
        self.cachedmessages = cachedmessages

    def insert_tx(self, pk, tx):
        t = type(tx)

        if t == OpenTx:
            self._insert_open(pk, tx)
        elif t == SendTx:
            self._insert_send(pk, tx)
        elif t == ReceiveTx:
            self._insert_receive(pk, tx)

        self.cachehash[tx.hash] = tx

    def _insert_open(self, pk, tx):
        if not valid_work(tx):
            return

        # Don't overwrite existing account
        if self.accounts.get(pk, None) is not None:
            return

        self.accounts[pk] = {
            'latest': 0,
            0: tx
        }         

    def _insert_send(self, pk, tx):
        if not (valid_signature(pk, tx) and valid_work(tx)):
            return

        if not (self.get_latest(pk).hash == tx.prev):
            return

        new_latest = self.accounts[pk]['latest'] + 1

        self.accounts[pk]['latest'] = new_latest
        self.accounts[pk][new_latest] = tx

    def _insert_receive(self, pk, tx):
        if not valid_work(tx):
            return

        if not (self.get_latest(pk).hash == tx.prev):
            return

        new_latest = self.accounts[pk]['latest'] + 1

        self.accounts[pk]['latest'] = new_latest
        self.accounts[pk][new_latest] = tx

    def get_message(self, h):
        return self.cachedmessages.get(h, None)

    def get_messages(self):
        return self.cachedmessages

    def add_message(self, h, decrypted_msg):
        self.cachedmessages[h] = decrypted_msg

    def get_latest(self, pk):
        pk_dict = self.accounts.get(pk, {})

        if pk_dict == {}:
            return None

        latest_no = pk_dict['latest']
        return pk_dict[latest_no]

    def get_account(self, pk):
        return self.accounts.get(pk, {})

    def get_hash(self, h):
        if self.hash_received(h):
            return self.cachehash[h]
        return None

    def hash_received(self, h):
        return h in self.cachehash


# Hashes an opentx


def hash_opentx(opentx):
    bytestr = str.encode("account:{},work:{}".format(
        opentx.account, opentx.work))
    h = hashlib.sha256(bytestr).hexdigest()
    return h

# Hashes a send tx


def hash_sendtx(sendtx):
    bytestr = str.encode(
        "prev:{},destination:{},rpk:{},signature:{},msg:{},work:{}".format(
            sendtx.prev, sendtx.destination, sendtx.rpk, sendtx.signature, sendtx.msg, sendtx.work
        )
    )
    h = hashlib.sha256(bytestr).hexdigest()
    return h

# Hashes a receive tx


def hash_receivetx(receivetx):
    bytestr = str.encode(
        "prev:{},source:{},work:{}".format(
            receivetx.prev, receivetx.source, receivetx.work
        )
    )
    h = hashlib.sha256(bytestr).hexdigest()
    return h

# Hashes tx


def hash_tx(tx):
    t = type(tx)

    if t != OpenTx and t != SendTx and t != ReceiveTx:
        return -1

    if t == OpenTx:
        h = hash_opentx(tx)
    elif t == SendTx:
        h = hash_sendtx(tx)
    elif t == ReceiveTx:
        h = hash_receivetx(tx)

    return h


def prep_signature(sendtx):
    s = "prev:{},destination:{},rpk:{},msg:{}".format(
        sendtx.prev, sendtx.destination, sendtx.rpk, sendtx.msg)
    return s


def sign_sendtx(sk, sendtx):
    sk = crypto.decodeint(sk[:64].decode('hex'))
    msg = prep_signature(sendtx)
    pk = crypto.publickey(sk)
    sig = crypto.signature(msg, sk, pk)

    # Reconstruct named tuple
    tx_dict = sendtx._asdict()
    tx_dict['signature'] = sig.encode('hex')
    return SendTx(**tx_dict)


def valid_work(tx):
    # Tx hash
    h = hash_tx(tx)
    return h[:len(MIN_WORK)] == MIN_WORK


def valid_signature(pk, sendtx):
    sig = sendtx.signature.decode('hex')
    msg = prep_signature(sendtx)
    return crypto.checkvalid(sig, msg, pk[:64].decode('hex'))


def mine_tx(tx):
    # Tx hash
    h = hash_tx(tx)

    # Tx type
    t = type(tx)

    if h == -1:
        return -1

    # Valid work done
    # Python and recursion doesn't work well
    # So i'll have to use a while loop
    while not valid_work(tx):
        d = tx._asdict()
        d['work'] = tx.work + 1
        tx = t(**d)
        h = hash_tx(tx)

    d = tx._asdict()
    d['hash'] = h
    return t(**d)
