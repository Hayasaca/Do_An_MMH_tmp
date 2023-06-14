import argparse
import json
import random
from ecdsa.numbertheory import inverse_mod

import ecdsa_lib

def same_k_attack(file_name):
    print("\n ----- Same nonce ECDSA Attack -----")
    print(f"Loading data from file {file_name}")
    try:
        with open(file_name, "r") as fdata:
            data = json.load(fdata)
    except FileNotFoundError:
        print(f"Data file '{file_name}' was not found.")
        return
    except IOError:
        print(f"Data file {file_name} can't be accessed.")
        return
    except json.JSONDecodeError:
        print("Data file content is not JSON compatible.")
        return
    message = data.get("message")
    msg1 = message[0]
    msg2 = message[1]
    hash_int_1 = ecdsa_lib.sha2_int(bytes(msg1))
    hash_int_2 = ecdsa_lib.sha2_int(bytes(msg2))
    curve_string = data["curve"]
    signature = data["signatures"]
    q_target = data["public_key"]
    n_mod = ecdsa_lib.curve_n(curve_string)
    if not ecdsa_lib.check_publickey(q_target, curve_string):
        print(
            f"Public key data invalid, not on the given {curve_string.upper()} curve."
        )
        return
    r = signature[0]["r"]
    s1 = signature[0]["s"]
    s2 = signature[1]["s"]
    numerator = (((s2 * hash_int_1) % n_mod - (s1 * hash_int_2) % n_mod) % n_mod)
    denominator = inverse_mod(r * ((s1 - s2) % n_mod), n_mod)
    d_key = numerator * denominator % n_mod
    print("Key found \\o/")
    print(hex(d_key))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ECDSA attack from JSON data file with same nonce")
    parser.add_argument(
        "-f",
        default="data_same_nonce.json",
        help="File name input",
        metavar="filein",
    )
    arg = parser.parse_args()
    same_k_attack(arg.f)