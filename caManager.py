import hashlib
import os
from OpenSSL import crypto
from OpenSSL.SSL import Context, TLSv1_METHOD

class CAManager:
    ca_crt = "CA/ca/cert.pem"
    ca_key = "CA/ca/key.pem"

    def generate_certificate(self, domain, name, unit):  # , ca_crt=None, ca_key=None
        """This function takes a domain name as a parameter and then creates a certificate and key with the
        domain name(replacing dots by underscores), finally signing the certificate using specified CA and 
        returns the path of key and cert files. If you are yet to generate a CA then check the top comments"""


        # Serial Generation - Serial number must be unique for each certificate,
        # so serial is generated based on domain name
        md5_hash = hashlib.md5()
        md5_hash.update(domain.encode('utf-8'))
        serial = int(md5_hash.hexdigest(), 36)

        # The CA stuff is loaded from the same folder as this script
        ca_cert = crypto.load_certificate(
            crypto.FILETYPE_PEM, open(self.ca_crt).read())
        # The last parameter is the password for your CA key file
        ca_key = crypto.load_privatekey(
            crypto.FILETYPE_PEM, open(self.ca_key).read(), None)

        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)

        cert = crypto.X509()
        cert.get_subject().C = "CR"
        cert.get_subject().ST = "San Jose"
        cert.get_subject().L = "Costa Rica"
        cert.get_subject().O =  name
        cert.get_subject().OU = unit
        cert.get_subject().CN = domain  # This is where the domain fits
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
        cert.set_serial_number(serial)
        cert.set_issuer(ca_cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(ca_key, "sha1")
        cert.sign(ca_key, "sha256")

        with open(name+"_key.pem", 'wb') as arch:
            arch.write(crypto.dump_privatekey(
            crypto.FILETYPE_PEM, key))
        with open(name+"_cert.pem", "wb") as arch:
            arch.write( crypto.dump_certificate(
            crypto.FILETYPE_PEM, cert))


    def check_certificate(self, certificate):
        dev = False
        try:
            dev = self._check_certificate(certificate)
        except Exception as e:
            dev = False
        
        return dev

    def _check_certificate(self, certificate):
        certificate = crypto.load_certificate(
            crypto.FILETYPE_PEM, certificate)
        serialnumber=certificate.get_serial_number()
        context = Context(TLSv1_METHOD)
        context.load_verify_locations(self.ca_crt)
        dev=False
        try:
            store = context.get_cert_store()

            # Create a certificate context using the store and the downloaded
            # certificate
            store_ctx = crypto.X509StoreContext(store, certificate)

            # Verify the certificate, returns None if it can validate the
            # certificate
            store_ctx.verify_certificate()

            dev=True
        except Exception as e:
            dev=False

        return dev


if __name__ == "__main__":
    ca = CAManager()
    ca.generate_certificate("server.python.cr", "server", "development")
    ca.generate_certificate("client.python.cr", "client", "development")
