import hashlib
import os

def new_user(username, password):
    with open("storage/root_users.txt", "r") as f:
        text = f.read()
        if text == "":
            users = {}
        else:
            users = dict(text)
    if username in users.keys():
        return
    else:
        hashed_pw = salt_hash_auth_pw(password, os.urandom(32))
        users[username] = hashed_pw
        with open("storage/root_users.txt", "w") as f:
            f.write(str(users))


def salt_hash_auth_pw(pw, salt, limit=2):
    hashed_password = hashlib.pbkdf2_hmac('sha256', pw.encode('utf-8'), salt, 100000)
    if limit == 0:
        return salt+"$".encode('utf-8')+hashed_password
    return salt_hash_auth_pw(str(hashed_password), salt, limit=limit-1)

def check_password(pw, value):
    verify_salt = ""
    i = 0
    while value[i] != ord("$"):
        verify_salt += chr(value[i])
        i+=1
    verify_hash = value[i+1:]
    claimant_hash = salt_hash_auth_pw(pw, verify_salt.encode('utf-8'))
    return value == claimant_hash

if __name__ == '__main__':
    new_user("test", "password")