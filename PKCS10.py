from OpenSSL import crypto

def generate_key_pair():
    '''Generate a public/private RSA key pair'''
    key_pair = crypto.PKey()
    key_pair.generate_key(crypto.TYPE_RSA, 2048)
    return key_pair

key_pair = generate_key_pair()
csr = crypto.X509Req()
csr.get_subject().CN = "Phil Ratcliffe"
csr.set_pubkey(key_pair)


csr.sign(key_pair, "sha1")
print crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr)

