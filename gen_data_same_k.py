import argparse
import random
import json
import secrets

import ecdsa_lib

def generates_signatures(message1, message2, curve, k_nonce, n_mod):
    print("Preparing Data")
    d_key = random.randrange(ecdsa_lib.curve_n(curve))
    print("Private key to be found (as demo) :")
    print(hex(d_key))
    sigs = []
    sz_curve = ecdsa_lib.curve_size(curve)
    msg = message1.encode("utf-8")
    hash_int = ecdsa_lib.sha2_int(msg)
    r_sig = ecdsa_lib.scalar_mult_x(k_nonce, curve)
    s_sig = ecdsa_lib.inverse_mod(k_nonce, n_mod) * (hash_int + r_sig * d_key) % n_mod
    sigs.append(
        {
            "r": r_sig,
            "s": s_sig,
        }
    )
    msg = message2.encode("utf-8")
    hash_int = ecdsa_lib.sha2_int(msg)
    r_sig = ecdsa_lib.scalar_mult_x(k_nonce, curve)
    s_sig = ecdsa_lib.inverse_mod(k_nonce, n_mod) * (hash_int + r_sig * d_key) % n_mod
    sigs.append(
        {
            "r": r_sig,
            "s": s_sig,
        }
    )
    ret = {
        "curve": curve.upper(),
        "public_key": ecdsa_lib.privkey_to_pubkey(d_key, curve),
        "signatures": sigs,
    }
    msg_list = [list(message1.encode("utf-8")), list(message2.encode("utf-8"))]
    ret["message"] = msg_list
    return ret

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate random demo data for ECDSA attack (same nonce)"
    )
    parser.add_argument(
        "-f",
        default="data_same_k.json",
        help="File name output",
        metavar="fileout",
    )
    parser.add_argument(
        "-m1",
        help="Message string 1",
        metavar="msg1",
    )
    parser.add_argument(
        "-m2",
        help="Message string 2",
        metavar="msg2",
    )
    parser.add_argument(
        "-c",
        default="secp256k1",
        help="Elliptic curve name",
        metavar="curve",
    )
    arg = parser.parse_args()
    n_mod = ecdsa_lib.curve_n(arg.c)
    k_nonce = secrets.randbelow(n_mod)
    sigs_data = generates_signatures(arg.m1, arg.m2, arg.c, k_nonce, n_mod)
    with open(arg.f, "w") as fout:
        json.dump(sigs_data, fout)
    print(f"File {arg.f} written with all data.")