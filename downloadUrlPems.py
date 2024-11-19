import ssl
import socket
from OpenSSL import SSL, crypto
from urllib.parse import urlparse
import click
import ssl
import socket


def download_certificate(url):
    # Parse the hostname and port from the URL
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname
    port = parsed_url.port or 443

    # Establish an SSL connection
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            # Get the certificate in DER format and convert it to PEM
            der_cert = ssock.getpeercert(binary_form=True)
            pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)

            # Save to disk with <hostname>.pem filename
            cert_filename = f"{hostname}.pem"
            with open(cert_filename, "w") as cert_file:
                cert_file.write(pem_cert)

            print(f"Certificate for {hostname} saved as {cert_filename}")


def download_cert_chain(url):
    # Parse the URL to extract the hostname and port
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname
    port = parsed_url.port if parsed_url.port else 443  # Default to 443 if no port is specified

    # Set up an SSL context that allows untrusted certificates
    context = SSL.Context(SSL.TLS_CLIENT_METHOD)
    context.set_verify(SSL.VERIFY_NONE, lambda conn, cert, errno, depth, ok: True)

    # Create a socket and establish a connection
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((hostname, port))

    # Wrap the socket with SSL using the OpenSSL library
    conn = SSL.Connection(context, sock)
    conn.set_tlsext_host_name(hostname.encode())
    conn.set_connect_state()
    conn.do_handshake()

    # Get the certificate chain
    cert_chain_pem = ""
    for i, cert in enumerate(conn.get_peer_cert_chain()):
        # Convert each certificate to PEM format
        cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8")
        cert_chain_pem += cert_pem

    # Save the full chain to a single .crt file
    file_name = f"{hostname}.crt"
    with open(file_name, 'w') as f:
        f.write(cert_chain_pem)
    print(f"Full certificate chain saved to {file_name}")

    # Clean up the connection
    conn.close()
    sock.close()


@click.command()
@click.argument('urls', nargs=-1)
def main(urls):
    for url in urls:
        try:
            print(f"Downloading certificate for {url}")
            download_cert_chain(url)
        except Exception as e:
            print(f"Failed to download certificate for {url}: {e}")
            continue

if __name__ == '__main__':
    main()