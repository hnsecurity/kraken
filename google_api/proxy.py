from mitm import MITM, protocol, crypto, middleware
from base64 import b64encode
import subprocess
from hashlib import sha256
import OpenSSL
from mitm.core import Connection, Middleware
import re


def getTokenFromChrome():

    while True:
        ans = input('''Using the reverse engineered Google api requires a valid token.
We need to launch Google Chrome to extract a token from your browser, the browser will be closed as soon as we get the token.
Type Y to continue or N to exit: ''')
        if ans.lower() == 'y':
            break
        if ans.lower() == 'n':
            exit(1)
        
    ca = crypto.CertificateAuthority()

    # pk = ca.cert.get_pubkey()
    # der = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_ASN1, pk)
    # fingerprint = b64encode(sha256(der).digest()).decode()

    mitm_server = None

    class GetRefreshToken(Middleware):
        def __init__(self):
            self.connection: Connection = None

        async def mitm_started(self, host: str, port: int):
            # print(f"MITM server started on {host}:{port}.")
            pass

        async def client_connected(self, connection: Connection):
            pass

        async def server_connected(self, connection: Connection):
            pass

        async def client_data(self, connection: Connection, data: bytes) -> bytes:
            m = re.search(b'refresh_token=([^&]+)&', data)
            if m:
                global refresh_token
                refresh_token = m[1].decode()
                mitm_server.stop()

            return data

        async def server_data(self, connection: Connection, data: bytes) -> bytes:
            return data

        async def client_disconnected(self, connection: Connection):
            pass

        async def server_disconnected(self, connection: Connection):
            pass

    mitm = MITM(
        host="127.0.0.1",
        port=8899,
        protocols=[protocol.HTTP],
        middlewares=[GetRefreshToken],
        certificate_authority=ca
    )

    p = subprocess.Popen(
        ['google-chrome', '--proxy-server=localhost:8899', '--ignore-certificate-errors', 'https://account.google.com'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    mitm_server = mitm

    try:
        mitm.run()
    except:
        pass

    p.kill()
    return refresh_token


if __name__ == '__main__':
    print(getTokenFromChrome())
