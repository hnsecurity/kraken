import requests
from hashlib import sha256, scrypt
import google_api.leak_detection_api_pb2 as LookupSingleLeakRequest
from google_api.get_token import get_token
from google_api.ECCommutativeCipher import ECCommutativeCipher


def username_hash_prefix(username):
    username_salt = b'\xC4\x94\xA3\x95\xF8\xC0\xE2\x3E\xA9\x23\x04\x78\x70\x2C\x72\x18\x56\x54\x99\xB3\xE9\x21\x18\x6C\x21\x1A\x01\x22\x3C\x45\x4A\xFA'
    hash = sha256(username.encode()+username_salt).hexdigest()[:8]
    x = bytes.fromhex(hash)
    x = x[:3] + bytes([x[3] & 0b11000000])
    return x


def scrypt_hash_username_and_password(username, password):
    password_salt = b'\x30\x76\x2A\xD2\x3F\x7B\xA1\x9B\xF8\xE3\x42\xFC\xA1\xA7\x8D\x06\xE6\x6B\xE4\xDB\xB8\x4F\x81\x53\xC5\x03\xC8\xDB\xBd\xDE\xA5\x20'
    username_password = username.encode() + password.encode()
    salt = username.encode() + password_salt
    hash = scrypt(username_password, salt=salt, n=4096, r=8, p=1)[:32]
    return hash


class GoogleApi():

    def __init__(self):
        self.access_token = get_token()
        self.cipher = ECCommutativeCipher()

    def lookup_request(self, username, password):
        lookup_hash = scrypt_hash_username_and_password(username, password)

        req = LookupSingleLeakRequest.LookupSingleLeakRequest()

        req.username_hash_prefix = username_hash_prefix(username)
        req.username_hash_prefix_length = 26
        req.encrypted_lookup_hash = self.cipher.encrypt(lookup_hash)

        serialized = req.SerializeToString()

        r = requests.post(
            'https://passwordsleakcheck-pa.googleapis.com/v1/leaks:lookupSingle',
            headers={'authorization': 'Bearer ' + self.access_token, 'content-type': 'application/x-protobuf', 'sec-fetch-site': 'none', 'sec-fetch-mode': 'no-cors', 'sec-fetch-dest': 'empty',
                     'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36'},
            data=serialized)

        if (r.status_code != 200):
            print(r)
            print(r.text)
            raise "Request failed"

        res = LookupSingleLeakRequest.LookupSingleLeakResponse()
        res.ParseFromString(r.content)

        return res

    def is_leaked(self, username, password):
        res = self.lookup_request(username, password)

        dec = self.cipher.decrypt(res.reencrypted_lookup_hash)

        hash1 = sha256(b'\x02' + dec[1:]).digest()
        hash2 = sha256(b'\x03' + dec[1:]).digest()

        for x in res.encrypted_leak_match_prefix:
            if (hash1.startswith(x) or hash2.startswith(x)):
                return True

        return False
