from collections import Counter
from crypto.matrix_stream_cipher import *
from scripts.nist_generate_sequence import generate_nist_sequence

# Зроби окремий тест: 1 послідовність, меншої довжини
K = generate_random_1024()
K0 = compress_1024_to_64(K)
w,x,y,z,_,_,_,_ = normalize_quaternion_from_k0(K0)
Gamma = gamma_from_quaternion(w,x,y,z)
pt = "\x00" * 20000
ct = encrypt(pt, K0, Gamma)

bits = ''.join(f"{w64 & ((1<<64)-1):064b}" for w64 in ct.stream)
print(Counter(bits))  # скільки '0' і '1'
