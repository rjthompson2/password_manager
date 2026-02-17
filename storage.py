import hashlib
import random
import os
import json

def add_login_info(user, username, password, website):
    filename = "storage/"+user+".txt"
    if not os.path.exists(filename):
        return
    with open(filename, "r", encoding='latin-1') as f:
        text = f.read()
        if text == "":
            return
        data = json.loads(text)
    if website in data.keys():
        return
    data[website] = {'username': username, 'password': password}
    with open(filename, "w", encoding='latin-1') as f:
        f.write(json.dumps(data))
    
def new_root_user(username, password):
    with open("storage/root_users.txt", "r", encoding='latin-1') as f:
        text = f.read()
        if text == "":
            users = {}
        else:
            users = json.loads(text)
    if username in users.keys():
        return
    else:
        hashed_pw = salt_hash_auth_pw(password, random.randint(0, 10000).to_bytes(5, byteorder='little'))
        users[username] = hashed_pw.decode('latin-1')
        with open("storage/root_users.txt", "w", encoding='latin-1') as f:
            f.write(json.dumps(users))
        new_user_file(username)

def new_user_file(username):
    path = "storage/"+username+".txt"
    if os.path.exists(path):
        os.remove(path)
    with open(path, "x") as f:
        f.write("{}")

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


def salt_hash_auth_pw(pw, salt, cycles=2):
    hashed_password = hashlib.pbkdf2_hmac('sha256', pw.encode('latin-1'), salt, 100000)
    if cycles == 0:
        return salt+"$".encode('latin-1')+hashed_password
    return salt_hash_auth_pw(str(hashed_password), salt, cycles=cycles-1)

def check_password(pw, value):
    verify_salt = ""
    i = 0
    while value[i] != ord("$"):
        verify_salt += chr(value[i])
        i+=1
    claimant_hash = salt_hash_auth_pw(pw, verify_salt.encode('latin-1'))
    return value == claimant_hash

if __name__ == '__main__':
    new_root_user("test", "password")
    print(login("test", "password"))
    add_login_info("test", "test123@gmail.com", "password", "https://test.url.com/login")