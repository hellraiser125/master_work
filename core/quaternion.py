class Quaternion:
    """
    A class to represent a quaternion and perform operations on quaternions.
    """

    def __init__(self, a, b, c, d):
        self.a = a
        self.b = b
        self.c = c
        self.d = d

    def __str__(self):
        return f"{self.a} + ({self.b})i + ({self.c})j + ({self.d})k"

    def __repr__(self):
        return self.__str__()

    def __eq__(self, value: object) -> bool:
        return (
            self.a == value.a
            and self.b == value.b
            and self.c == value.c
            and self.d == value.d
        )

    def __mul__(self, other):
        a1, b1, c1, d1 = self.a, self.b, self.c, self.d
        a2, b2, c2, d2 = other.a, other.b, other.c, other.d
        modulus = 2**64
        lower_64_bits_mask = (1 << 64) - 1

        a1a2_product = ((a1 * a2) & lower_64_bits_mask + (a1 * a2) >> 64) % modulus
        b1b2_product = ((b1 * b2) & lower_64_bits_mask + (b1 * b2) >> 64) % modulus
        c1c2_product = ((c1 * c2) & lower_64_bits_mask + (c1 * c2) >> 64) % modulus
        d1d2_product = ((d1 * d2) & lower_64_bits_mask + (d1 * d2) >> 64) % modulus

        a1b2_product = ((a1 * b2) & lower_64_bits_mask + (a1 * b2) >> 64) % modulus
        b1a2_product = ((b1 * a2) & lower_64_bits_mask + (b1 * a2) >> 64) % modulus
        c1d2_product = ((c1 * d2) & lower_64_bits_mask + (c1 * d2) >> 64) % modulus
        d1c2_product = ((d1 * c2) & lower_64_bits_mask + (d1 * c2) >> 64) % modulus

        a1c2_product = ((a1 * c2) & lower_64_bits_mask + (a1 * c2) >> 64) % modulus
        c1a2_product = ((c1 * a2) & lower_64_bits_mask + (c1 * a2) >> 64) % modulus
        d1b2_product = ((d1 * b2) & lower_64_bits_mask + (d1 * b2) >> 64) % modulus
        b1d2_product = ((b1 * d2) & lower_64_bits_mask + (b1 * d2) >> 64) % modulus

        a1d2_product = ((a1 * d2) & lower_64_bits_mask + (a1 * d2) >> 64) % modulus
        d1a2_product = ((d1 * a2) & lower_64_bits_mask + (d1 * a2) >> 64) % modulus
        b1c2_product = ((b1 * c2) & lower_64_bits_mask + (b1 * c2) >> 64) % modulus
        c1b2_product = ((c1 * b2) & lower_64_bits_mask + (c1 * b2) >> 64) % modulus

        a_temp = (((a1a2_product - b1b2_product) - c1c2_product) - d1d2_product)
        a = (a_temp + modulus) % modulus if a_temp < 0 else a_temp & lower_64_bits_mask

        b_temp = ((a1b2_product + b1a2_product) % modulus + c1d2_product % modulus - d1c2_product % modulus) % modulus
        b = (b_temp + modulus) % modulus if b_temp < 0 else b_temp & lower_64_bits_mask

        c_temp = ((a1c2_product + c1a2_product) % modulus + d1b2_product % modulus - b1d2_product % modulus) % modulus
        c = (c_temp + modulus) % modulus if c_temp < 0 else c_temp & lower_64_bits_mask

        d_temp = ((a1d2_product + d1a2_product) % modulus + b1c2_product % modulus - c1b2_product % modulus) % modulus
        d = (d_temp + modulus) % modulus if d_temp < 0 else d_temp & lower_64_bits_mask

        return Quaternion(a, b, c, d)
