import click
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64


def convert_to_pem(base64_input):
    der_data = base64.b64decode(base64_input)
    try:
        # Decode the base64 input

        # Try to load as a DER-encoded X.509 certificate
        cert = x509.load_der_x509_certificate(der_data, default_backend())
        print("Converted from DER to PEM:")
        return cert.public_bytes(serialization.Encoding.PEM).decode()

    except ValueError:
        # If it fails, try loading as a PKCS7 certificate
        try:
            from cryptography.hazmat.primitives.serialization.pkcs7 import load_der_pkcs7_certificates
            certs = load_der_pkcs7_certificates(der_data)
            print("Converted from P7B to PEM:")
            return "\n".join(cert.public_bytes(serialization.Encoding.PEM).decode() for cert in certs)

        except ValueError:
            # If that fails, try to check if it's already PEM
            try:
                cert = x509.load_pem_x509_certificate(der_data, default_backend())
                print("Input is already in PEM format:")
                return der_data.decode()

            except ValueError:
                return "Failed to convert; input format is not recognized."


@click.command()
@click.argument('base64_input')
def main(base64_input):
    pem_output = convert_to_pem(base64_input)
    print(pem_output)


if __name__ == "__main__":
    main()
