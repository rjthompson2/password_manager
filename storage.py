import hashlib
import os
import json
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES

class AESCipher:
    def __init__(self, key):
        self.bs = AES.block_size
        self.key = self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, data:str):
        data = self._pad(data)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(data.encode())).decode('latin-1')
    
    def decrypt(self, ciphertext):
        ciphertext = base64.b64decode(ciphertext)
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return AESCipher._unpad(cipher.decrypt(ciphertext[AES.block_size:])).decode('latin-1')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)
    
    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]


def add_login_info(root_user, root_pw, username, password, website):
    if not login(root_user, root_pw):
        return
    filename = "storage/"+root_user+".txt"
    if not os.path.exists(filename):
        return

    data = get_login_info(root_user, root_pw)
    if website in data.keys():
        return
    data[website] = {'username': username, 'password': password}

    aes = AESCipher(root_pw)
    data = aes.encrypt(json.dumps(data))
    with open(filename, "w", encoding='latin-1') as f:
        f.write(data)
    


def get_login_info(root_user, root_pw):
    if not login(root_user, root_pw):
        return
    filename = "storage/"+root_user+".txt"
    if not os.path.exists(filename):
        return
    
    with open(filename, "r", encoding='latin-1') as f:
        text = f.read()
        if text == "":
            return
    text = text.encode('latin-1')

    aes = AESCipher(root_pw)
    text = aes.decrypt(text)
    return json.loads(text)

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
        salt = os.urandom(16) 
        hashed_pw = salt_hash_auth_pw(password, salt)
        users[username] = hashed_pw.decode('latin-1')
        with open("storage/root_users.txt", "w", encoding='latin-1') as f:
            f.write(json.dumps(users))
        aes = AESCipher(password)
        ciphertext = aes.encrypt("{}")
        print(ciphertext)
        new_user_file(username, ciphertext)

def new_user_file(username, input="{}"):
    path = "storage/"+username+".txt"
    if os.path.exists(path):
        os.remove(path)
    with open(path, "x") as f:
        f.write(input)

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


def salt_hash_auth_pw(pw, salt, length=30):
    hashed_password = hashlib.pbkdf2_hmac('sha256', pw.encode('latin-1'), salt, length)
    return salt+"$".encode('latin-1')+hashed_password

def check_password(pw, value):
    verify_salt = get_salt(value)
    claimant_hash = salt_hash_auth_pw(pw, verify_salt.encode('latin-1'))
    return value == claimant_hash

def get_salt(value:bytes):
    salt = ""
    i = 0
    while value[i] != ord("$"):
        salt += chr(value[i])
        i+=1
    return salt

if __name__ == '__main__':
    new_root_user("test", "password")
    print(login("test", "password"))
    add_login_info("test", "password", "test123@gmail.com", "password", "https://test.url.com/login")
    add_login_info("test", "password", "test123@gmail.com", "password", "https://test.url.com/login")
    print(get_login_info("test", "password"))