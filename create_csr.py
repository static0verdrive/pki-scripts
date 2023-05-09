import ipaddress
from cryptography import x509
from cryptography.x509.oid import NameOID, AttributeOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# create_csr.py
## Author: static0verdrive
# Usage: edit the cert details as needed, then run "python create_csr.py"

# Cert Details
OID                      = x509.oid.ExtendedKeyUsageOID.SERVER_AUTH # Server Authentication
#OID                      = x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH # Client Authentication
#CHALLENGE                = "Enrollment_challenge"
PASSPHRASE               = "private_key_passphrase"
HOSTNAME                 = "myhost"      # Hostname without domain
DOMAIN                   = "example.com" # Domain name without leading period (.)
COMMON_NAME              = "{}.{}".format(HOSTNAME, DOMAIN) # FQDN
DOMAIN_COMPONENT         = "pki"
ORGANIZATIONAL_UNIT_NAME = "orgUnit"
ORGANIZATION_NAME        = "org"
COUNTRY_NAME             = "CA"

SUBJECT_ALT_NAMES = [
    x509.DNSName(u"www.example.com"),      # Edit/remove these lines as needed, but always keep the last line
    x509.DNSName(u"friendly.example.com"), # Copy/paste this line for more subAltName(DNS) entries
    x509.IPAddress(ipaddress.IPv4Address('192.168.1.5')), # Remove if IP isn't needed
    x509.DNSName(u"{}".format(COMMON_NAME)) # KEEP this line! It adds the "common name" FQDN as a subAltName(DNS)
]

# Defaults
KEY_SIZE = 2048

# Generate the RSA private key
private_key = rsa.generate_private_key(
    public_exponent = 65537,
    key_size        = KEY_SIZE,
    backend         = default_backend()
)
# Generate a CSR
csr_builder = x509.CertificateSigningRequestBuilder()
csr_builder = csr_builder.subject_name(x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"{}".format(COUNTRY_NAME)),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"{}".format(ORGANIZATION_NAME)),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"{}".format(ORGANIZATIONAL_UNIT_NAME)),
    x509.NameAttribute(NameOID.DOMAIN_COMPONENT, u"{}".format(DOMAIN_COMPONENT)),
    x509.NameAttribute(NameOID.COMMON_NAME, u"{}".format(COMMON_NAME)),
]))

csr_builder = csr_builder.add_extension(x509.SubjectAlternativeName(SUBJECT_ALT_NAMES), critical=False)
csr_builder = csr_builder.add_extension(x509.ExtendedKeyUsage([OID]), critical=False)

#if CHALLENGE is not None:
#    csr_builder = csr_builder.add_attribute(AttributeOID.CHALLENGE_PASSWORD, CHALLENGE.encode('utf-8'))

# Sign the CSR with the private key.
cert_signing_request = csr_builder.sign(private_key, hashes.SHA256(), default_backend())



##### __MAIN__ #####

# Write Private key to PKCS#8 encrypted PEM file
with open("{}.key".format(COMMON_NAME), "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8, # Worst-case use TraditionalOpenSSL here
        encryption_algorithm=serialization.BestAvailableEncryption(bytes(PASSPHRASE, 'utf-8')),
    ))
f.close()

# Write Cert Signing Request to PKCS#10 PEM file
with open("{}.csr".format(COMMON_NAME), "wb") as f:
    f.write(cert_signing_request.public_bytes(serialization.Encoding.PEM))
f.close()
