from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta, timezone
import base64
import uuid
import jwt


class KeyGenerator:
    def __init__(self):
        self.keys = {}  # Initialize dictionary to store the keys

    # Method that generates ssh keys
    def generate_keys(self):
        """
            Generate valid private and public key pair with kid1
            Step 1: generate private and public key pair and serialize each key in PEM format
            Step 2: Create a random string for the kid variable and a valid expiry timestamp
            Step 3: Store the keys in the keys dictionary with kid1
        """
        # Step 1
        private_key1 = rsa.generate_private_key(
            public_exponent = 65537,
            key_size=2048,
        )
        public_key1 = private_key1.public_key()

        private_pem1 = private_key1.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem1 = public_key1.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Step 2
        kid1 = str(uuid.uuid4())
        expiry_timestamp = datetime.now(timezone.utc) + timedelta(seconds=30)

        # Step 3
        self.keys[kid1] = {
            "private_key": private_pem1,
            "public_key": public_pem1,
            "expiry": expiry_timestamp,
        }

        # ----------------------------------------------------------------------------

        """
            Generate expired private and public key pair with kid1
            Step 4: Generate private and public key pair and serialize each key in PEM format
            Step 5: Create a random string for the kid variable and a valid expiry timestamp
            Step 6: Store the keys in the keys dictionary with kid2
        """

        # Step 4
        private_key2 = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key2 = private_key2.public_key()

        private_pem2 = private_key2.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem2 = public_key2.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Step 5
        kid2 = str(uuid.uuid4())
        expiry_timestamp = datetime.now(timezone.utc) - timedelta(seconds=60)

        # Step 6
        self.keys[kid2] = {
            "private_key": private_pem2,
            "public_key": public_pem2,
            "expiry": expiry_timestamp,
        }

        # return kid1 for valid keys
        return kid1

    # Method to generate JSON Web Token
    def create_jwt(self, kid, expiry=False):
        if kid not in self.keys:
            raise ValueError("Invalid kid")

        # Expiration based on key's expiry timestamp
        expiry_time = datetime.now(timezone.utc) - timedelta(seconds=30) if expiry \
            else datetime.now(timezone.utc) + timedelta(seconds=30)

        # Headers and payload data for private key
        header_data = {
            "typ": "JWT",
            "alg": "RS256",
            "kid": kid,
        }
        payload_data = {
            "exp": expiry_time,
            "iat": datetime.now(timezone.utc),
        }

        # Load private key from PEM format
        private_key = serialization.load_pem_private_key(
            self.keys[kid]["private_key"],
            password=None,
        )
        # Encode and sign a token
        token = jwt.encode(payload_data, private_key, algorithm="RS256", headers=header_data,)
        return token

    # Get public keys
    def get_public_jwk(self, kid):
        if kid not in self.keys:
            raise ValueError("Invalid kid")

        # Load public key from PEM format and get their public numbers
        public_key = serialization.load_pem_public_key(self.keys[kid]["public_key"])
        public_numbers = public_key.public_numbers()

        # Function to perform base64 encoding on public key
        def base64url_encoding(number):
            return base64.urlsafe_b64encode(number.to_bytes(
                (number.bit_length() + 7) // 8, byteorder="big")
            ).rstrip(b"=").decode("utf-8")
        """
        Return public keys with appropriate parameters
        """
        return {
            "kid": kid,
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "n": base64url_encoding(public_numbers.n),
            "e": base64url_encoding(public_numbers.e),
        }

    # Delete expired keys
    def del_expired(self):
        """
        Remove expired keys from dictionary
        """
        expired_kids = [kid for kid, key_data in self.keys.items()\
                        if key_data["expiry"] < datetime.now(timezone.utc)
        ]
        for kid in expired_kids:
            del self.keys[kid]