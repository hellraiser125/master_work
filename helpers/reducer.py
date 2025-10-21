from core.operations import perform_operations, convolution_three_elements, multiply_quaternions


def reduce_data(data):
    tree = []
    tree.append(data.copy())

    if len(data) == 1:
        return tree

    while len(data) > 1:
        new_data = []
        i = 0
        while i < len(data):
            if i + 4 <= len(data):
                new_data.append(*perform_operations(data[i:i + 4]))
                i += 4
            elif i + 3 <= len(data):
                new_data.append(*convolution_three_elements(data[i:i + 3]))
                i += 3
            elif i + 2 <= len(data):
                new_data.append(*multiply_quaternions(data[i:i + 2]))
                i += 2
            else:
                new_data.append(data[i])
                i += 1
        data = new_data
        tree.append(data.copy())

    # if data:
    #     print(f"[+]Reduction complete. Root quaternion: {data[0]}[+]\n")

    return tree
