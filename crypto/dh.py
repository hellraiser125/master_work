# Простий Diffie-Hellman (MODP group 14 RFC3526, 2048-bit prime)
# Не залежить від зовнішніх бібліотек.
import secrets

# 2048-bit MODP prime (group 14) from RFC 3526
# (рядок великий — це стандартне значення)
DH_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD"
    "3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6"
    "F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F241"
    "17C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16
)
DH_GENERATOR = 2


class DiffieHellman:
    def __init__(self, prime=DH_PRIME, generator=DH_GENERATOR, private_key=None):
        self.prime = prime
        self.generator = generator
        # приватний ключ (випадкове велике число)
        self.private_key = private_key or secrets.randbelow(prime - 2) + 2
        self.public_key = pow(self.generator, self.private_key, self.prime)

    def get_public_bytes(self) -> int:
        return self.public_key

    def compute_shared_secret(self, other_public: int) -> int:
        """
        Обчислює загальний секрет (ціле число).
        """
        return pow(other_public, self.private_key, self.prime)
