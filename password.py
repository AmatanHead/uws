import hashlib
import random
import string
import base64
import codecs


class Password:
    def __init__(
        self,
        encoded: bytes,
        salt: bytes,
        iterations: int,
        algorithm: str
    ):
        self.encoded = encoded
        self.salt = salt
        self.iterations = iterations
        self.algorithm = algorithm

    def __eq__(self, other):
        if not isinstance(other, Password):
            return NotImplemented

        # Let's pretend we care about timing attacks
        return (
            all(a == b for a, b in zip(self.encoded, other.encoded)) and
            len(self.encoded) == len(other.encoded) and
            all(a == b for a, b in zip(self.salt, other.salt)) and
            len(self.salt) == len(other.salt) and
            self.iterations == other.iterations
        )

    def to_string(self) -> str:
        return base64.b64encode(b'\0'.join([
            self.encoded.replace(b'\\', b'\\\\').replace(b'\0', b'\\0'),
            bytes(str(self.iterations), 'ascii'),
            self.salt.replace(b'\\', b'\\\\').replace(b'\0', b'\\0'),
            bytes(self.algorithm, 'ascii')
        ]))

    @classmethod
    def from_string(cls, raw: str):
        raw = base64.b64decode(raw)

        print(raw)

        encoded, iterations, salt, algorithm = raw.split(b'\0')
        encoded = codecs.escape_decode(encoded)[0]
        iterations = int(iterations)
        salt = codecs.escape_decode(salt)[0]
        algorithm = str(algorithm)

        return cls(encoded, salt, iterations, algorithm)


class PasswordManager:
    default_salt_length = 10
    default_iterations = 10000
    salt_symbols = string.printable

    def __init__(self):
        self.random = random.SystemRandom()

    def salt(self, length: int=None) -> bytes:
        length = length or self.default_salt_length
        symbols = [self.random.choice(self.salt_symbols) for _ in range(length)]
        return b''.join(map(lambda x: bytes(x, 'ascii'), symbols))

    def make_password(
        self,
        user_password: str,
        *,
        salt: bytes=None,
        iterations: int=None
    ) -> Password:

        raise NotImplementedError()

    def check_password(
        self,
        user_password: str,
        password: Password
    ) -> bool:

        user_password = self.make_password(
            user_password, salt=password.salt, iterations=password.iterations
        )

        return password == user_password


class Sha256PasswordManager(PasswordManager):
    default_iterations = 5  # e.g. fast hash function

    def make_password(
        self,
        user_password: str,
        *,
        salt: bytes=None,
        iterations: int=None
    ) -> Password:

        iterations = iterations or self.default_iterations
        if salt is None:
            salt = self.salt()

        password = bytes(user_password, 'utf-8')
        for i in range(iterations):
            password = hashlib.sha256(password).digest()

        return Password(
            hashlib.sha256(password + salt).digest(),
            salt,
            iterations,
            'sha256'
        )


class PBKDF2PasswordManager(PasswordManager):
    def make_password(
        self,
        user_password: str,
        *,
        salt: bytes=None,
        iterations: int=None
    ) -> Password:

        iterations = iterations or self.default_iterations
        if salt is None:
            salt = self.salt()

        password = bytes(user_password, 'utf-8')

        return Password(
            hashlib.pbkdf2_hmac('sha256', password, salt, iterations),
            salt,
            iterations,
            'pbkdf2'
        )
