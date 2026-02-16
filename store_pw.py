import hashlib
import os

def salt_hash_auth_pw(pw, salt, limit=2):
    hashed_password = hashlib.pbkdf2_hmac('sha256', pw.encode('utf-8'), salt, 100000)
    if limit == 0:
        return salt+"$".encode('utf-8')+hashed_password
    return salt_hash_auth_pw(str(hashed_password), salt, limit=limit-1)


if __name__ == '__main__':
    hash = salt_hash_auth_pw('password', salt="6".encode('utf-8'))
    print(str(hash))