import hashlib
import os
import json

def new_user(username, password):
    with open("storage/root_users.txt", "r", encoding='latin-1') as f:
        text = f.read()
        if text == "":
            users = {}
        else:
            users = json.loads(text)
    if username in users.keys():
        return
    else:
        hashed_pw = salt_hash_auth_pw(password, os.urandom(32))
        users[username] = hashed_pw.decode('latin-1')
        with open("storage/root_users.txt", "w", encoding='latin-1') as f:
            f.write(json.dumps(users))

def login(username, password):
    with open("storage/root_users.txt", "r", encoding='latin-1') as f:
        text = f.read()
        if text == "":
            return False
        else:
            users = json.loads(text)
    if not username in users.keys():
        return False
    else:
        value = users[username].encode('latin-1')
        return check_password(password, value)


def salt_hash_auth_pw(pw, salt, limit=2):
    hashed_password = hashlib.pbkdf2_hmac('sha256', pw.encode('latin-1'), salt, 100000)
    if limit == 0:
        return salt+"$".encode('latin-1')+hashed_password
    return salt_hash_auth_pw(str(hashed_password), salt, limit=limit-1)

def check_password(pw, value):
    verify_salt = ""
    i = 0
    while value[i] != ord("$"):
        verify_salt += chr(value[i])
        i+=1
    claimant_hash = salt_hash_auth_pw(pw, verify_salt.encode('latin-1'))
    return value == claimant_hash

if __name__ == '__main__':
    new_user("test", "password")
    print(login("test", "password"))