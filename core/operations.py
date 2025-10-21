from .quaternion import Quaternion
from .utils import sum_quaternion_parts_with_modulus


def multiply_quaternions(quaternions):
    mul = quaternions[0]
    result = []
    if isinstance(mul, list):
        mul = mul[0]
    for i in range(1, len(quaternions)):
        mul = mul * quaternions[i]
        result.append(mul)
    return result


def perform_operations(quaternions):
    """
    Perform a series of operations on a list of quaternions.

    This function calculates specific results based on the elements of the four quaternions and 
    their interactions according to the defined algorithm. The operations involve modular arithmetic 
    and bitwise operations to handle 64-bit constraints.

    Args:
        quaternions (list): A list of quaternions. Each quaternion is expected to have attributes a, b, c, and d.

    Returns:
        list: A list containing the results of the performed operations.
    """
    results = []
    lower_64_bits_mask = (1 << 64) - 1
    modulus = 2**64
    #print(f"Len: {len(quaternions)}")
    for i in range(len(quaternions)):
        a4, b4, c4, d4 = quaternions[i].a, quaternions[i].b, quaternions[i].c, quaternions[i].d
        
        # Перебираємо решту кватерніонів
        for j in range(i+1, len(quaternions)):
            a3, b3, c3, d3 = quaternions[j-1].a, quaternions[j-1].b, quaternions[j-1].c, quaternions[j-1].d
            a2, b2, c2, d2 = quaternions[j-2].a, quaternions[j-2].b, quaternions[j-2].c, quaternions[j-2].d
            a1, b1, c1, d1 = quaternions[j-3].a, quaternions[j-3].b, quaternions[j-3].c, quaternions[j-3].d
    
   
    result_a_1 = (((a1 * a3) & lower_64_bits_mask) + ((a1 * a3) >>64)) % modulus
    result_a_1 = (((result_a_1 * b3) & lower_64_bits_mask) + ((result_a_1 * b3) >> 64)) % modulus
    result_a_1 = (((result_a_1 * c3) & lower_64_bits_mask) + ((result_a_1 * c3) >> 64)) % modulus
    result_a_1 = (((result_a_1 * d3) & lower_64_bits_mask) + ((result_a_1 * d3) >> 64)) % modulus
    result_a_1 = (((result_a_1 * a4) & lower_64_bits_mask) + ((result_a_1 * a4) >> 64)) % modulus
    result_a_1 = (((result_a_1 * b4) & lower_64_bits_mask) + ((result_a_1 * b4) >> 64)) % modulus
    result_a_1 = (((result_a_1 * c4) & lower_64_bits_mask) + ((result_a_1 * c4) >> 64)) % modulus
    result_a_1 = (((result_a_1 * d4) & lower_64_bits_mask) + ((result_a_1 * d4) >> 64)) % modulus
    result_a_1 = (((result_a_1 * a2) & lower_64_bits_mask) + ((result_a_1 * a2) >> 64)) % modulus

    result_a_2 = (((a1 * a3) & lower_64_bits_mask) + ((a1 * a3) >> 64)) % modulus
    result_a_2 = (((result_a_2 * b3) & lower_64_bits_mask) + ((result_a_2 * b3) >> 64)) % modulus
    result_a_2 = (((result_a_2 * c3) & lower_64_bits_mask) + ((result_a_2 * c3) >> 64)) % modulus
    result_a_2 = (((result_a_2 * d3) & lower_64_bits_mask) + ((result_a_2 * d3) >> 64)) % modulus
    result_a_2 = (((result_a_2 * a4) & lower_64_bits_mask) + ((result_a_2 * a4) >> 64)) % modulus
    result_a_2 = (((result_a_2 * b4) & lower_64_bits_mask) + ((result_a_2 * b4) >> 64)) % modulus
    result_a_2 = (((result_a_2 * c4) & lower_64_bits_mask) + ((result_a_2 * c4) >> 64)) % modulus
    result_a_2 = (((result_a_2 * d4) & lower_64_bits_mask) + ((result_a_2 * d4) >> 64)) % modulus
    result_a_2 = (((result_a_2 * b2) & lower_64_bits_mask) + ((result_a_2 * b2) >> 64)) % modulus
    
    result_a_3 = (((a1 * a3) & lower_64_bits_mask) + ((a1 * a3) >> 64)) % modulus
    result_a_3 = (((result_a_3 * b3) & lower_64_bits_mask) + ((result_a_3 * b3) >> 64)) % modulus
    result_a_3 = (((result_a_3 * c3) & lower_64_bits_mask) + ((result_a_3 * c3) >> 64)) % modulus
    result_a_3 = (((result_a_3 * d3) & lower_64_bits_mask) + ((result_a_3 * d3) >> 64)) % modulus
    result_a_3 = (((result_a_3 * a4) & lower_64_bits_mask) + ((result_a_3 * a4) >> 64)) % modulus
    result_a_3 = (((result_a_3 * b4) & lower_64_bits_mask) + ((result_a_3 * b4) >> 64)) % modulus
    result_a_3 = (((result_a_3 * c4) & lower_64_bits_mask) + ((result_a_3 * c4) >> 64)) % modulus
    result_a_3 = (((result_a_3 * d4) & lower_64_bits_mask) + ((result_a_3 * d4) >> 64)) % modulus
    result_a_3 = (((result_a_3 * c2) & lower_64_bits_mask) + ((result_a_3 * c2) >> 64)) % modulus

    result_a_4 = (((a1 * a3) & lower_64_bits_mask) + ((a1 * a3) >> 64)) % modulus
    result_a_4 = (((result_a_4 * b3) & lower_64_bits_mask) + ((result_a_4 * b3) >> 64)) % modulus
    result_a_4 = (((result_a_4 * c3) & lower_64_bits_mask) + ((result_a_4 * c3) >> 64)) % modulus
    result_a_4 = (((result_a_4 * d3) & lower_64_bits_mask) + ((result_a_4 * d3) >> 64)) % modulus
    result_a_4 = (((result_a_4 * a4) & lower_64_bits_mask) + ((result_a_4 * a4) >> 64)) % modulus
    result_a_4 = (((result_a_4 * b4) & lower_64_bits_mask) + ((result_a_4 * b4) >> 64)) % modulus
    result_a_4 = (((result_a_4 * c4) & lower_64_bits_mask) + ((result_a_4 * c4) >> 64)) % modulus
    result_a_4 = (((result_a_4 * d4) & lower_64_bits_mask) + ((result_a_4 * d4) >> 64)) % modulus
    result_a_4 = (((result_a_4 * d2) & lower_64_bits_mask) + ((result_a_4 * d2) >> 64)) % modulus
    

    result_b_1 = (((b1 * a3) & lower_64_bits_mask) + ((b1 * a3) >> 64)) % modulus
    result_b_1 = (((result_b_1 * b3) & lower_64_bits_mask) + ((result_b_1 * b3) >> 64)) % modulus
    result_b_1 = (((result_b_1 * c3) & lower_64_bits_mask) + ((result_b_1 * c3) >> 64)) % modulus
    result_b_1 = (((result_b_1 * d3) & lower_64_bits_mask) + ((result_b_1 * d3) >> 64)) % modulus
    result_b_1 = (((result_b_1 * a4) & lower_64_bits_mask) + ((result_b_1 * a4) >> 64)) % modulus
    result_b_1 = (((result_b_1 * b4) & lower_64_bits_mask) + ((result_b_1 * b4) >> 64)) % modulus
    result_b_1 = (((result_b_1 * c4) & lower_64_bits_mask) + ((result_b_1 * c4) >> 64)) % modulus
    result_b_1 = (((result_b_1 * d4) & lower_64_bits_mask) + ((result_b_1 * d4) >> 64)) % modulus
    result_b_1 = (((result_b_1 * a2) & lower_64_bits_mask) + ((result_b_1 * a2) >> 64)) % modulus

    result_b_2 = (((b1 * a3) & lower_64_bits_mask) + ((b1 * a3) >> 64)) % modulus
    result_b_2 = (((result_b_2 * b3) & lower_64_bits_mask) + ((result_b_2 * b3) >> 64)) % modulus
    result_b_2 = (((result_b_2 * c3) & lower_64_bits_mask) + ((result_b_2 * c3) >> 64)) % modulus
    result_b_2 = (((result_b_2 * d3) & lower_64_bits_mask) + ((result_b_2 * d3) >> 64)) % modulus
    result_b_2 = (((result_b_2 * a4) & lower_64_bits_mask) + ((result_b_2 * a4) >> 64)) % modulus
    result_b_2 = (((result_b_2 * b4) & lower_64_bits_mask) + ((result_b_2 * b4) >> 64)) % modulus
    result_b_2 = (((result_b_2 * c4) & lower_64_bits_mask) + ((result_b_2 * c4) >> 64)) % modulus
    result_b_2 = (((result_b_2 * d4) & lower_64_bits_mask) + ((result_b_2 * d4) >> 64)) % modulus
    result_b_2 = (((result_b_2 * b2) & lower_64_bits_mask) + ((result_b_2 * b2) >> 64)) % modulus
    
    result_b_3 = (((b1 * a3) & lower_64_bits_mask) + ((b1 * a3) >> 64)) % modulus
    result_b_3 = (((result_b_3 * b3) & lower_64_bits_mask) + ((result_b_3 * b3) >> 64)) % modulus
    result_b_3 = (((result_b_3 * c3) & lower_64_bits_mask) + ((result_b_3 * c3) >> 64)) % modulus
    result_b_3 = (((result_b_3 * d3) & lower_64_bits_mask) + ((result_b_3 * d3) >> 64)) % modulus
    result_b_3 = (((result_b_3 * a4) & lower_64_bits_mask) + ((result_b_3 * a4) >> 64)) % modulus
    result_b_3 = (((result_b_3 * b4) & lower_64_bits_mask) + ((result_b_3 * b4) >> 64)) % modulus
    result_b_3 = (((result_b_3 * c4) & lower_64_bits_mask) + ((result_b_3 * c4) >> 64)) % modulus
    result_b_3 = (((result_b_3 * d4) & lower_64_bits_mask) + ((result_b_3 * d4) >> 64)) % modulus
    result_b_3 = (((result_b_3 * c2) & lower_64_bits_mask) + ((result_b_3 * c2) >> 64)) % modulus

    result_b_4 = (((b1 * a3) & lower_64_bits_mask) + ((b1 * a3) >> 64)) % modulus
    result_b_4 = (((result_b_4 * b3) & lower_64_bits_mask) + ((result_b_4 * b3) >> 64)) % modulus
    result_b_4 = (((result_b_4 * c3) & lower_64_bits_mask) + ((result_b_4 * c3) >> 64)) % modulus
    result_b_4 = (((result_b_4 * d3) & lower_64_bits_mask) + ((result_b_4 * d3) >> 64)) % modulus
    result_b_4 = (((result_b_4 * a4) & lower_64_bits_mask) + ((result_b_4 * a4) >> 64)) % modulus
    result_b_4 = (((result_b_4 * b4) & lower_64_bits_mask) + ((result_b_4 * b4) >> 64)) % modulus
    result_b_4 = (((result_b_4 * c4) & lower_64_bits_mask) + ((result_b_4 * c4) >> 64)) % modulus
    result_b_4 = (((result_b_4 * d4) & lower_64_bits_mask) + ((result_b_4 * d4) >> 64)) % modulus
    result_b_4 = (((result_b_4 * d2) & lower_64_bits_mask) + ((result_b_4 * d2) >> 64)) % modulus


    result_c_1 = (((c1 * a3) & lower_64_bits_mask) + ((c1 * a3) >> 64)) % modulus
    result_c_1 = (((result_c_1 * b3) & lower_64_bits_mask) + ((result_c_1 * b3) >> 64)) % modulus
    result_c_1 = (((result_c_1 * c3) & lower_64_bits_mask) + ((result_c_1 * c3) >> 64)) % modulus
    result_c_1 = (((result_c_1 * d3) & lower_64_bits_mask) + ((result_c_1 * d3) >> 64)) % modulus
    result_c_1 = (((result_c_1 * a4) & lower_64_bits_mask) + ((result_c_1 * a4) >> 64)) % modulus
    result_c_1 = (((result_c_1 * b4) & lower_64_bits_mask) + ((result_c_1 * b4) >> 64)) % modulus
    result_c_1 = (((result_c_1 * c4) & lower_64_bits_mask) + ((result_c_1 * c4) >> 64)) % modulus
    result_c_1 = (((result_c_1 * d4) & lower_64_bits_mask) + ((result_c_1 * d4) >> 64)) % modulus
    result_c_1 = (((result_c_1 * a2) & lower_64_bits_mask) + ((result_c_1 * a2) >> 64)) % modulus

    result_c_2 = (((c1 * a3) & lower_64_bits_mask) + ((c1 * a3) >> 64)) % modulus
    result_c_2 = (((result_c_2 * b3) & lower_64_bits_mask) + ((result_c_2 * b3) >> 64)) % modulus
    result_c_2 = (((result_c_2 * c3) & lower_64_bits_mask) + ((result_c_2 * c3) >> 64)) % modulus
    result_c_2 = (((result_c_2 * d3) & lower_64_bits_mask) + ((result_c_2 * d3) >> 64)) % modulus
    result_c_2 = (((result_c_2 * a4) & lower_64_bits_mask) + ((result_c_2 * a4) >> 64)) % modulus
    result_c_2 = (((result_c_2 * b4) & lower_64_bits_mask) + ((result_c_2 * b4) >> 64)) % modulus
    result_c_2 = (((result_c_2 * c4) & lower_64_bits_mask) + ((result_c_2 * c4) >> 64)) % modulus
    result_c_2 = (((result_c_2 * d4) & lower_64_bits_mask) + ((result_c_2 * d4) >> 64)) % modulus
    result_c_2 = (((result_c_2 * b2) & lower_64_bits_mask) + ((result_c_2 * b2) >> 64)) % modulus
    
    result_c_3 = (((c1 * a3) & lower_64_bits_mask) + ((c1 * a3) >> 64)) % modulus
    result_c_3 = (((result_c_3 * b3) & lower_64_bits_mask) + ((result_c_3 * b3) >> 64)) % modulus
    result_c_3 = (((result_c_3 * c3) & lower_64_bits_mask) + ((result_c_3 * c3) >> 64)) % modulus
    result_c_3 = (((result_c_3 * d3) & lower_64_bits_mask) + ((result_c_3 * d3) >> 64)) % modulus
    result_c_3 = (((result_c_3 * a4) & lower_64_bits_mask) + ((result_c_3 * a4) >> 64)) % modulus
    result_c_3 = (((result_c_3 * b4) & lower_64_bits_mask) + ((result_c_3 * b4) >> 64)) % modulus
    result_c_3 = (((result_c_3 * c4) & lower_64_bits_mask) + ((result_c_3 * c4) >> 64)) % modulus
    result_c_3 = (((result_c_3 * d4) & lower_64_bits_mask) + ((result_c_3 * d4) >> 64)) % modulus
    result_c_3 = (((result_c_3 * c2) & lower_64_bits_mask) + ((result_c_3 * c2) >> 64)) % modulus

    result_c_4 = (((c1 * a3) & lower_64_bits_mask) + ((c1 * a3) >> 64)) % modulus
    result_c_4 = (((result_c_4 * b3) & lower_64_bits_mask) + ((result_c_4 * b3) >> 64)) % modulus
    result_c_4 = (((result_c_4 * c3) & lower_64_bits_mask) + ((result_c_4 * c3) >> 64)) % modulus
    result_c_4 = (((result_c_4 * d3) & lower_64_bits_mask) + ((result_c_4 * d3) >> 64)) % modulus
    result_c_4 = (((result_c_4 * a4) & lower_64_bits_mask) + ((result_c_4 * a4) >> 64)) % modulus
    result_c_4 = (((result_c_4 * b4) & lower_64_bits_mask) + ((result_c_4 * b4) >> 64)) % modulus
    result_c_4 = (((result_c_4 * c4) & lower_64_bits_mask) + ((result_c_4 * c4) >> 64)) % modulus
    result_c_4 = (((result_c_4 * d4) & lower_64_bits_mask) + ((result_c_4 * d4) >> 64)) % modulus
    result_c_4 = (((result_c_4 * d2) & lower_64_bits_mask) + ((result_c_4 * d2) >> 64)) % modulus


    result_d_1 = (((d1 * a3) & lower_64_bits_mask) + ((d1 * a3) >> 64)) % modulus
    result_d_1 = (((result_d_1 * b3) & lower_64_bits_mask) + ((result_d_1 * b3) >> 64)) % modulus
    result_d_1 = (((result_d_1 * c3) & lower_64_bits_mask) + ((result_d_1 * c3) >> 64)) % modulus
    result_d_1 = (((result_d_1 * d3) & lower_64_bits_mask) + ((result_d_1 * d3) >> 64)) % modulus
    result_d_1 = (((result_d_1 * a4) & lower_64_bits_mask) + ((result_d_1 * a4) >> 64)) % modulus
    result_d_1 = (((result_d_1 * b4) & lower_64_bits_mask) + ((result_d_1 * b4) >> 64)) % modulus
    result_d_1 = (((result_d_1 * c4) & lower_64_bits_mask) + ((result_d_1 * c4) >> 64)) % modulus
    result_d_1 = (((result_d_1 * d4) & lower_64_bits_mask) + ((result_d_1 * d4) >> 64)) % modulus
    result_d_1 = (((result_d_1 * a2) & lower_64_bits_mask) + ((result_d_1 * a2) >> 64)) % modulus

    result_d_2 = (((d1 * a3) & lower_64_bits_mask) + ((d1 * a3) >> 64)) % modulus
    result_d_2 = (((result_d_2 * b3) & lower_64_bits_mask) + ((result_d_2 * b3) >> 64)) % modulus
    result_d_2 = (((result_d_2 * c3) & lower_64_bits_mask) + ((result_d_2 * c3) >> 64)) % modulus
    result_d_2 = (((result_d_2 * d3) & lower_64_bits_mask) + ((result_d_2 * d3) >> 64)) % modulus
    result_d_2 = (((result_d_2 * a4) & lower_64_bits_mask) + ((result_d_2 * a4) >> 64)) % modulus
    result_d_2 = (((result_d_2 * b4) & lower_64_bits_mask) + ((result_d_2 * b4) >> 64)) % modulus
    result_d_2 = (((result_d_2 * c4) & lower_64_bits_mask) + ((result_d_2 * c4) >> 64)) % modulus
    result_d_2 = (((result_d_2 * d4) & lower_64_bits_mask) + ((result_d_2 * d4) >> 64)) % modulus
    result_d_2 = (((result_d_2 * b2) & lower_64_bits_mask) + ((result_d_2 * b2) >> 64)) % modulus
    
    result_d_3 = (((d1 * a3) & lower_64_bits_mask) + ((d1 * a3) >> 64)) % modulus
    result_d_3 = (((result_d_3 * b3) & lower_64_bits_mask) + ((result_d_3 * b3) >> 64)) % modulus
    result_d_3 = (((result_d_3 * c3) & lower_64_bits_mask) + ((result_d_3 * c3) >> 64)) % modulus
    result_d_3 = (((result_d_3 * d3) & lower_64_bits_mask) + ((result_d_3 * d3) >> 64)) % modulus
    result_d_3 = (((result_d_3 * a4) & lower_64_bits_mask) + ((result_d_3 * a4) >> 64)) % modulus
    result_d_3 = (((result_d_3 * b4) & lower_64_bits_mask) + ((result_d_3 * b4) >> 64)) % modulus
    result_d_3 = (((result_d_3 * c4) & lower_64_bits_mask) + ((result_d_3 * c4) >> 64)) % modulus
    result_d_3 = (((result_d_3 * d4) & lower_64_bits_mask) + ((result_d_3 * d4) >> 64)) % modulus
    result_d_3 = (((result_d_3 * c2) & lower_64_bits_mask) + ((result_d_3 * c2) >> 64)) % modulus

    result_d_4 = (((d1 * a3) & lower_64_bits_mask) + ((d1 * a3) >> 64)) % modulus
    result_d_4 = (((result_d_4 * b3) & lower_64_bits_mask) + ((result_d_4 * b3) >> 64)) % modulus
    result_d_4 = (((result_d_4 * c3) & lower_64_bits_mask) + ((result_d_4 * c3) >> 64)) % modulus
    result_d_4 = (((result_d_4 * d3) & lower_64_bits_mask) + ((result_d_4 * d3) >> 64)) % modulus
    result_d_4 = (((result_d_4 * a4) & lower_64_bits_mask) + ((result_d_4 * a4) >> 64)) % modulus
    result_d_4 = (((result_d_4 * b4) & lower_64_bits_mask) + ((result_d_4 * b4) >> 64)) % modulus
    result_d_4 = (((result_d_4 * c4) & lower_64_bits_mask) + ((result_d_4 * c4) >> 64)) % modulus
    result_d_4 = (((result_d_4 * d4) & lower_64_bits_mask) + ((result_d_4 * d4) >> 64)) % modulus
    result_d_4 = (((result_d_4 * d2) & lower_64_bits_mask) + ((result_d_4 * d2) >> 64)) % modulus

    

    results.append((result_a_1,result_a_2,result_a_3,result_a_4,result_b_1,result_b_2,result_b_3,result_b_4,result_c_1,result_c_2,result_c_3,result_c_4,result_d_1,result_d_2,result_d_3,result_d_4))

    final_result = sum_quaternion_parts_with_modulus(results)
    #print(*final_result)

    return final_result

def convolution_three_elements(quaternions):
    """
    Perform a series of operations on a list of quaternions.

    This function calculates specific results based on the elements of the four quaternions and 
    their interactions according to the defined algorithm. The operations involve modular arithmetic 
    and bitwise operations to handle 64-bit constraints.

    Args:
        quaternions (list): A list of quaternions. Each quaternion is expected to have attributes a, b, c, and d.

    Returns:
        list: A list containing the results of the performed operations.
    """
    results = []
    lower_64_bits_mask = (1 << 64) - 1
    modulus = 2**64
    #print(f"Len: {len(quaternions)}")
    for i in range(len(quaternions)):
        a3, b3, c3, d3 = quaternions[i].a, quaternions[i].b, quaternions[i].c, quaternions[i].d
        
        # Перебираємо решту кватерніонів
        for j in range(i+1, len(quaternions)):
            a2, b2, c2, d2 = quaternions[j-1].a, quaternions[j-1].b, quaternions[j-1].c, quaternions[j-1].d
            a1, b1, c1, d1 = quaternions[j-2].a, quaternions[j-2].b, quaternions[j-2].c, quaternions[j-2].d
    
   
    result_a_1 = (((a1 * a3) & lower_64_bits_mask) + ((a1 * a3) >>64)) % modulus
    result_a_1 = (((result_a_1 * b3) & lower_64_bits_mask) + ((result_a_1 * b3) >> 64)) % modulus
    result_a_1 = (((result_a_1 * c3) & lower_64_bits_mask) + ((result_a_1 * c3) >> 64)) % modulus
    result_a_1 = (((result_a_1 * d3) & lower_64_bits_mask) + ((result_a_1 * d3) >> 64)) % modulus
    result_a_1 = (((result_a_1 * a2) & lower_64_bits_mask) + ((result_a_1 * a2) >> 64)) % modulus

    result_a_2 = (((a1 * a3) & lower_64_bits_mask) + ((a1 * a3) >> 64)) % modulus
    result_a_2 = (((result_a_2 * b3) & lower_64_bits_mask) + ((result_a_2 * b3) >> 64)) % modulus
    result_a_2 = (((result_a_2 * c3) & lower_64_bits_mask) + ((result_a_2 * c3) >> 64)) % modulus
    result_a_2 = (((result_a_2 * d3) & lower_64_bits_mask) + ((result_a_2 * d3) >> 64)) % modulus
    result_a_2 = (((result_a_2 * b2) & lower_64_bits_mask) + ((result_a_2 * b2) >> 64)) % modulus
    
    result_a_3 = (((a1 * a3) & lower_64_bits_mask) + ((a1 * a3) >> 64)) % modulus
    result_a_3 = (((result_a_3 * b3) & lower_64_bits_mask) + ((result_a_3 * b3) >> 64)) % modulus
    result_a_3 = (((result_a_3 * c3) & lower_64_bits_mask) + ((result_a_3 * c3) >> 64)) % modulus
    result_a_3 = (((result_a_3 * d3) & lower_64_bits_mask) + ((result_a_3 * d3) >> 64)) % modulus
    result_a_3 = (((result_a_3 * c2) & lower_64_bits_mask) + ((result_a_3 * c2) >> 64)) % modulus

    result_a_4 = (((a1 * a3) & lower_64_bits_mask) + ((a1 * a3) >> 64)) % modulus
    result_a_4 = (((result_a_4 * b3) & lower_64_bits_mask) + ((result_a_4 * b3) >> 64)) % modulus
    result_a_4 = (((result_a_4 * c3) & lower_64_bits_mask) + ((result_a_4 * c3) >> 64)) % modulus
    result_a_4 = (((result_a_4 * d3) & lower_64_bits_mask) + ((result_a_4 * d3) >> 64)) % modulus
    result_a_4 = (((result_a_4 * d2) & lower_64_bits_mask) + ((result_a_4 * d2) >> 64)) % modulus
    

    result_b_1 = (((b1 * a3) & lower_64_bits_mask) + ((b1 * a3) >> 64)) % modulus
    result_b_1 = (((result_b_1 * b3) & lower_64_bits_mask) + ((result_b_1 * b3) >> 64)) % modulus
    result_b_1 = (((result_b_1 * c3) & lower_64_bits_mask) + ((result_b_1 * c3) >> 64)) % modulus
    result_b_1 = (((result_b_1 * d3) & lower_64_bits_mask) + ((result_b_1 * d3) >> 64)) % modulus
    result_b_1 = (((result_b_1 * a2) & lower_64_bits_mask) + ((result_b_1 * a2) >> 64)) % modulus

    result_b_2 = (((b1 * a3) & lower_64_bits_mask) + ((b1 * a3) >> 64)) % modulus
    result_b_2 = (((result_b_2 * b3) & lower_64_bits_mask) + ((result_b_2 * b3) >> 64)) % modulus
    result_b_2 = (((result_b_2 * c3) & lower_64_bits_mask) + ((result_b_2 * c3) >> 64)) % modulus
    result_b_2 = (((result_b_2 * d3) & lower_64_bits_mask) + ((result_b_2 * d3) >> 64)) % modulus
    result_b_2 = (((result_b_2 * b2) & lower_64_bits_mask) + ((result_b_2 * b2) >> 64)) % modulus
    
    result_b_3 = (((b1 * a3) & lower_64_bits_mask) + ((b1 * a3) >> 64)) % modulus
    result_b_3 = (((result_b_3 * b3) & lower_64_bits_mask) + ((result_b_3 * b3) >> 64)) % modulus
    result_b_3 = (((result_b_3 * c3) & lower_64_bits_mask) + ((result_b_3 * c3) >> 64)) % modulus
    result_b_3 = (((result_b_3 * d3) & lower_64_bits_mask) + ((result_b_3 * d3) >> 64)) % modulus
    result_b_3 = (((result_b_3 * c2) & lower_64_bits_mask) + ((result_b_3 * c2) >> 64)) % modulus

    result_b_4 = (((b1 * a3) & lower_64_bits_mask) + ((b1 * a3) >> 64)) % modulus
    result_b_4 = (((result_b_4 * b3) & lower_64_bits_mask) + ((result_b_4 * b3) >> 64)) % modulus
    result_b_4 = (((result_b_4 * c3) & lower_64_bits_mask) + ((result_b_4 * c3) >> 64)) % modulus
    result_b_4 = (((result_b_4 * d3) & lower_64_bits_mask) + ((result_b_4 * d3) >> 64)) % modulus
    result_b_4 = (((result_b_4 * d2) & lower_64_bits_mask) + ((result_b_4 * d2) >> 64)) % modulus


    result_c_1 = (((c1 * a3) & lower_64_bits_mask) + ((c1 * a3) >> 64)) % modulus
    result_c_1 = (((result_c_1 * b3) & lower_64_bits_mask) + ((result_c_1 * b3) >> 64)) % modulus
    result_c_1 = (((result_c_1 * c3) & lower_64_bits_mask) + ((result_c_1 * c3) >> 64)) % modulus
    result_c_1 = (((result_c_1 * d3) & lower_64_bits_mask) + ((result_c_1 * d3) >> 64)) % modulus
    result_c_1 = (((result_c_1 * a2) & lower_64_bits_mask) + ((result_c_1 * a2) >> 64)) % modulus

    result_c_2 = (((c1 * a3) & lower_64_bits_mask) + ((c1 * a3) >> 64)) % modulus
    result_c_2 = (((result_c_2 * b3) & lower_64_bits_mask) + ((result_c_2 * b3) >> 64)) % modulus
    result_c_2 = (((result_c_2 * c3) & lower_64_bits_mask) + ((result_c_2 * c3) >> 64)) % modulus
    result_c_2 = (((result_c_2 * d3) & lower_64_bits_mask) + ((result_c_2 * d3) >> 64)) % modulus
    result_c_2 = (((result_c_2 * b2) & lower_64_bits_mask) + ((result_c_2 * b2) >> 64)) % modulus
    
    result_c_3 = (((c1 * a3) & lower_64_bits_mask) + ((c1 * a3) >> 64)) % modulus
    result_c_3 = (((result_c_3 * b3) & lower_64_bits_mask) + ((result_c_3 * b3) >> 64)) % modulus
    result_c_3 = (((result_c_3 * c3) & lower_64_bits_mask) + ((result_c_3 * c3) >> 64)) % modulus
    result_c_3 = (((result_c_3 * d3) & lower_64_bits_mask) + ((result_c_3 * d3) >> 64)) % modulus
    result_c_3 = (((result_c_3 * c2) & lower_64_bits_mask) + ((result_c_3 * c2) >> 64)) % modulus

    result_c_4 = (((c1 * a3) & lower_64_bits_mask) + ((c1 * a3) >> 64)) % modulus
    result_c_4 = (((result_c_4 * b3) & lower_64_bits_mask) + ((result_c_4 * b3) >> 64)) % modulus
    result_c_4 = (((result_c_4 * c3) & lower_64_bits_mask) + ((result_c_4 * c3) >> 64)) % modulus
    result_c_4 = (((result_c_4 * d3) & lower_64_bits_mask) + ((result_c_4 * d3) >> 64)) % modulus
    result_c_4 = (((result_c_4 * d2) & lower_64_bits_mask) + ((result_c_4 * d2) >> 64)) % modulus


    result_d_1 = (((d1 * a3) & lower_64_bits_mask) + ((d1 * a3) >> 64)) % modulus
    result_d_1 = (((result_d_1 * b3) & lower_64_bits_mask) + ((result_d_1 * b3) >> 64)) % modulus
    result_d_1 = (((result_d_1 * c3) & lower_64_bits_mask) + ((result_d_1 * c3) >> 64)) % modulus
    result_d_1 = (((result_d_1 * d3) & lower_64_bits_mask) + ((result_d_1 * d3) >> 64)) % modulus
    result_d_1 = (((result_d_1 * a2) & lower_64_bits_mask) + ((result_d_1 * a2) >> 64)) % modulus

    result_d_2 = (((d1 * a3) & lower_64_bits_mask) + ((d1 * a3) >> 64)) % modulus
    result_d_2 = (((result_d_2 * b3) & lower_64_bits_mask) + ((result_d_2 * b3) >> 64)) % modulus
    result_d_2 = (((result_d_2 * c3) & lower_64_bits_mask) + ((result_d_2 * c3) >> 64)) % modulus
    result_d_2 = (((result_d_2 * d3) & lower_64_bits_mask) + ((result_d_2 * d3) >> 64)) % modulus
    result_d_2 = (((result_d_2 * b2) & lower_64_bits_mask) + ((result_d_2 * b2) >> 64)) % modulus
    
    result_d_3 = (((d1 * a3) & lower_64_bits_mask) + ((d1 * a3) >> 64)) % modulus
    result_d_3 = (((result_d_3 * b3) & lower_64_bits_mask) + ((result_d_3 * b3) >> 64)) % modulus
    result_d_3 = (((result_d_3 * c3) & lower_64_bits_mask) + ((result_d_3 * c3) >> 64)) % modulus
    result_d_3 = (((result_d_3 * d3) & lower_64_bits_mask) + ((result_d_3 * d3) >> 64)) % modulus
    result_d_3 = (((result_d_3 * c2) & lower_64_bits_mask) + ((result_d_3 * c2) >> 64)) % modulus

    result_d_4 = (((d1 * a3) & lower_64_bits_mask) + ((d1 * a3) >> 64)) % modulus
    result_d_4 = (((result_d_4 * b3) & lower_64_bits_mask) + ((result_d_4 * b3) >> 64)) % modulus
    result_d_4 = (((result_d_4 * c3) & lower_64_bits_mask) + ((result_d_4 * c3) >> 64)) % modulus
    result_d_4 = (((result_d_4 * d3) & lower_64_bits_mask) + ((result_d_4 * d3) >> 64)) % modulus
    result_d_4 = (((result_d_4 * d2) & lower_64_bits_mask) + ((result_d_4 * d2) >> 64)) % modulus

    
    results.append((result_a_1,result_a_2,result_a_3,result_a_4,result_b_1,result_b_2,result_b_3,result_b_4,result_c_1,result_c_2,result_c_3,result_c_4,result_d_1,result_d_2,result_d_3,result_d_4))

    final_result = sum_quaternion_parts_with_modulus(results)
    #print(*final_result)

    return final_result
