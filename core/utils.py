from .quaternion import Quaternion


def sum_quaternion_parts_with_modulus(parts, modulus=2**64):
    result = []
    tmp = []
    for i in range(4):
        test = parts[0][i::4]
        tmp.append(sum_with_modulus(test))
    result.append(Quaternion(*tmp))
    return result


def sum_with_modulus(values, modulus=2**64):
    result = 0
    for value in values:
        result = (result + value) % modulus
    return result
