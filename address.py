import crypto
import hashlib


def generate_key_pair():
    # Spend key pair
    sk1, pk1 = crypto.generate_key_pair()

    # View key pair
    sk2, pk2 = crypto.generate_key_pair()

    sk = '{}{}'.format(
        crypto.encodeint(sk1).encode('hex'),
        crypto.encodeint(sk2).encode('hex'),
    )

    pk = '{}{}'.format(
        pk1.encode('hex'), pk2.encode('hex')
    )

    return [sk, pk]


def derive_public_key(sk):
    if len(sk) != 128 and len(sk) != 64:
        raise Exception('Invalid secret key')

    def f(x): return crypto.publickey(crypto.decodeint(x.decode('hex')))

    if len(sk) == 64:
        return f(sk).encode('hex')

    # Spend key pair
    sk1 = sk[:64]

    # View key pair
    sk2 = sk[64:]    

    pk1 = f(sk1)
    pk2 = f(sk2)

    return '{}{}'.format(
        pk1.encode('hex'), pk2.encode('hex')
    )


def get_spend_key(k):
    if len(k) != 128:
        raise Exception('Invalid key')
    return k[:64]


def get_view_key(k):
    if len(k) != 128:
        raise Exception('Invalid key')
    return k[64:]


def generate_stealth_address(pk):
     # Generate random secret key
    r_sk, r_pk = crypto.generate_key_pair()

    # Get spend and view pk
    view_pk = get_view_key(pk).decode('hex')
    spend_pk = get_spend_key(pk).decode('hex')

    # d = ECDH(r_sk, a_pk)    
    d_partial = crypto.scalarmult(crypto.decodepoint(view_pk), r_sk)

    # This has to do with n==0 mod 8 by definition, c.f.
    # the top paragraph of page 5 of http://cr.yp.to/ecdh/curve25519-20060209.pdf
    d = crypto.scalarmult(d_partial, 8)

    # Hash d to make it unlinkable
    # f_sk = Hash(d)
    f_sk_hex = hashlib.sha256(
        crypto.encodepoint(d).encode('hex')
    ).hexdigest()
    f_sk = crypto.decodeint(
        f_sk_hex.decode('hex')
    )
    f_pk = crypto.publickey(f_sk)

    # Stealth address = f_pk + b_pk
    p_point = crypto.edwards(crypto.decodepoint(
        f_pk), crypto.decodepoint(spend_pk)
    )
    p = crypto.encodepoint(p_point).encode('hex')

    return [p, f_sk_hex, r_pk.encode('hex')]


def retrieve_stealth_address(sk, random_pk):
    # House keeping (checks if the stealth address is the same
    # Derives public key
    pk = derive_public_key(sk)

    spend_pk = get_spend_key(pk).decode('hex')

    r_pk = random_pk.decode('hex')

    # Get spend and view sk
    view_sk = get_view_key(sk).decode('hex')

    # ECDH
    r_pk_point = crypto.decodepoint(r_pk)
    view_sk_int = crypto.decodeint(view_sk)

    d_partial = crypto.scalarmult(r_pk_point, view_sk_int)

    # This has to do with n==0 mod 8 by definition, c.f.
    # the top paragraph of page 5 of http://cr.yp.to/ecdh/curve25519-20060209.pdf
    d = crypto.scalarmult(d_partial, 8)

    # Hash d to make it unlinkable
    # f_sk = Hash(d)
    f_sk_hex = hashlib.sha256(
        crypto.encodepoint(d).encode('hex')
    ).hexdigest()
    f_sk = crypto.decodeint(
        f_sk_hex.decode('hex')
    )
    f_pk = crypto.publickey(f_sk)

    # Stealth address = f_pk + b_pk
    p_point = crypto.edwards(crypto.decodepoint(
        f_pk), crypto.decodepoint(spend_pk)
    )
    p = crypto.encodepoint(p_point).encode('hex')

    return [p, f_sk_hex]


def get_one_time_sk(sk, stealth_address_pk, random_pk):
    [sa_pk, f_sk] = retrieve_stealth_address(sk, random_pk)

    # Derive one time key if stealth address belongs to user
    if not sa_pk == stealth_address_pk:
        return None
    
    spend_sk_int = crypto.decodeint(
        get_spend_key(sk).decode('hex')
    )
    f_sk_int = crypto.decodeint(
        f_sk.decode('hex')
    )

    return crypto.encodeint(
        crypto.scalaradd(spend_sk_int, f_sk_int)
    ).encode('hex')
