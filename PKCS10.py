from OpenSSL import crypto

def generate_key_pair():
    '''Generate a public/private RSA key pair'''
    key_pair = crypto.PKey()
    key_pair.generate_key(crypto.TYPE_RSA, 2048)
    return key_pair

# Generate the key pair
key_pair = generate_key_pair()

# Create a CSR object and populate it with a simple DN and the key
csr = crypto.X509Req()
csr.get_subject().CN = "Phil Ratcliffe"
csr.set_pubkey(key_pair)

# Now add a PoP signature to the CSR
csr.sign(key_pair, "sha1")

# Print out the CSR in PEM format
print crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr)

