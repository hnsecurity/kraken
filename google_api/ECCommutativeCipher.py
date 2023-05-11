
from ecpy.curves import Curve, Point
from math import ceil
from hashlib import sha256
from Crypto.Util.number import inverse
from libnum import sqrtmod_prime_power
import random


class ECCommutativeCipher:

    cv = Curve.get_curve("NIST-P256")

    p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
    a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
    b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
    order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

    def __init__(self, private_key=None):
        if (private_key is None):
            self.key = random.randint(1, self.order)
        else:
            self.key = int.from_bytes(private_key, 'big')

    def random_oracle(self, x, max_value):

        hash_output_length = 256
        output_bit_length = max_value.bit_length() + hash_output_length
        iter_count = ceil(output_bit_length / hash_output_length)
        assert (iter_count * hash_output_length < 130048)
        excess_bit_count = (
            iter_count * hash_output_length) - output_bit_length
        hash_output = 0

        for i in range(1, iter_count+1):
            hash_output = hash_output << hash_output_length
            bignum_bytes = i.to_bytes(ceil(i.bit_length()/8), 'big')
            bignum_bytes += x
            # print('  bytes: ', bignum_bytes.hex())
            hashed_string = sha256(bignum_bytes).digest()
            hash_output = hash_output + int.from_bytes(hashed_string, 'big')
            #print('  ', hash_output)
        return (hash_output >> excess_bit_count) % max_value

    def hashToTheCurve(self, m):
        m = m.split(b'\x00')[0]
        x = self.random_oracle(m, self.p)
        while True:
            # print('x: ', x)
            mod_x = x % self.p
            y2 = (mod_x**3 + self.a*mod_x + self.b) % self.p
            try:
                sqrt = list(sqrtmod_prime_power(y2, self.p, 1))[0]
                if (sqrt & 1 == 1):
                    return Point(mod_x, (-sqrt) % self.p, self.cv)
                return Point(mod_x, sqrt, self.cv)
            except:
                pass
            x = self.random_oracle(x.to_bytes(
                ceil(x.bit_length()/8), 'big'), self.p)

    def encrypt(self, plaintext):
        point = self.hashToTheCurve(plaintext)
        ep = self.key*point

        ser_x = ep.x.to_bytes(32, 'big')
        ser_y = ep.y.to_bytes(32, 'big')
        return bytes([2 + (ser_y[-1] & 1)]) + ser_x

    def decrypt(self, ciphertext):
        assert (ciphertext[0] == 2 or ciphertext[0] == 3)

        x = int.from_bytes(ciphertext[1:], 'big')
        y = self.cv.y_recover(x)

        point = Point(x, y, self.cv)

        dp = inverse(self.key, self.order) * point

        ser_x = dp.x.to_bytes(32, 'big')
        ser_y = dp.y.to_bytes(32, 'big')

        return bytes([2 + (ser_y[-1] & 1)]) + ser_x


if (__name__ == '__main__'):

    x = b'\x39\x4f\xf8\x31\x41\xc4\xaf\x41\xbd\x3b\x5e\xf9\x1d\xeb\x72\x9d\xab\x98\x9e\x72\x31\xfe\xd8\x20\xd2\x22\xb3\xbc\xec\x89\x14\x8e'

    cipher = ECCommutativeCipher()

    c = cipher.encrypt(x)

    print(c.hex())

    with open('reencrypted_lookup_hash', 'rb') as f:
        reencrypted_lookup_hash = f.read()

    d = cipher.decrypt(reencrypted_lookup_hash)

    print(d.hex())
