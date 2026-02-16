import random

def generate(length=64, pw=""):
    if length == 0:
        return pw
    
    pw += chr(random.randint(32, 126))
    return generate(length-1, pw)

if __name__ == '__main__':
    print(generate())