import os

def run(**args):
    print("[*] W module dirlistener.")
    files = os.listdir(".")
    return str(files)
