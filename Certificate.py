from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime

# Fungsi untuk membuat kunci privat
def create_private_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

# Fungsi untuk membuat sertifikat root CA
def create_root_ca(private_key):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ID"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Indonesia"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Ariekany.Inc"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"CA-Ariekany"),
    ])
    return x509.CertificateBuilder()\
        .subject_name(subject)\
        .issuer_name(issuer)\
        .public_key(private_key.public_key())\
        .serial_number(x509.random_serial_number())\
        .not_valid_before(datetime.datetime.utcnow())\
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))\
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)\
        .sign(private_key=private_key, algorithm=hashes.SHA256())

# Fungsi untuk membuat sertifikat server yang ditandatangani oleh CA
def create_server_certificate(ca_cert, ca_key, server_key, common_name):
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ID"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Indonesia"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Ariekany.Inc"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    return x509.CertificateBuilder()\
        .subject_name(subject)\
        .issuer_name(ca_cert.subject)\
        .public_key(server_key.public_key())\
        .serial_number(x509.random_serial_number())\
        .not_valid_before(datetime.datetime.utcnow())\
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))\
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)\
        .sign(private_key=ca_key, algorithm=hashes.SHA256())

# Fungsi untuk menyimpan kunci atau sertifikat ke file
def save_to_file(data, filename, is_key=False):
    with open(filename, "wb") as f:
        if is_key:
            f.write(data.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        else:
            f.write(data.public_bytes(encoding=serialization.Encoding.PEM))

# Eksekusi
# 1. Membuat Root CA
ca_key = create_private_key()
ca_cert = create_root_ca(ca_key)

# Simpan Root CA
save_to_file(ca_key, "ca-key.pem", is_key=True)
save_to_file(ca_cert, "ca-cert.pem")

# 2. Membuat Sertifikat Server
server_key = create_private_key()
server_cert = create_server_certificate(ca_cert, ca_key, server_key, "Ariekany.com")

# Simpan Sertifikat Server
save_to_file(server_key, "server-key.pem", is_key=True)
save_to_file(server_cert, "server-cert.pem")

print("CA dan Sertifikat Server berhasil dibuat!")
