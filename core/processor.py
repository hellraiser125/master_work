from typing import Union, List
from .quaternion import Quaternion


class QuaternionProcessor:
    """
    A class to process chunk data and calculate quaternion values.
    """

    def __init__(self, chunk_dict: Union[dict, list]):
        self.chunk_data = chunk_dict

    def make_quaternion(self, final_version=True) -> List[Quaternion]:
        quaternion_parts = []
        quaternions = []

        if isinstance(self.chunk_data, list):
            for data in self.chunk_data:
                quaternion_parts.append(data)
                if len(quaternion_parts) == 4:
                    quaternions.append(Quaternion(*quaternion_parts))
                    quaternion_parts.clear()
            if quaternion_parts:
                while len(quaternion_parts) < 4:
                    quaternion_parts.append(0)
                quaternions.append(Quaternion(*quaternion_parts))
            return quaternions

        for decimal_values in self.chunk_data.values():
            quaternion = 0
            for index, data in enumerate(decimal_values):
                quaternion += data << (8 * index)
            quaternion_parts.append(quaternion)
            if len(quaternion_parts) == 4:
                quaternions.append(Quaternion(*quaternion_parts))
                quaternion_parts.clear()

        if quaternion_parts:
            while len(quaternion_parts) < 4:
                quaternion_parts.append(0)
            quaternions.append(Quaternion(*quaternion_parts))

        return quaternions
