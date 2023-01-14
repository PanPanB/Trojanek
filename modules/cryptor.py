from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from io import BytesIO

import base64
import zlib

def generate():
    new_key = RSA.generate(2048)
    private_key = new_key.exportKey()
    public_key = new_key.publickey().exportKey()

    with open('key.pri', 'wb') as f:
        f.write(private_key)

    with open('key.pub', 'wb') as f:
        f.write(public_key)

def get_rsa_cipher(keytype): #podajemy pri lub pub
    with open(f'key.{keytype}') as f:
        key = f.read()
    rsakey = RSA.importKey(key)
    return (PKCS1_OAEP.new(rsakey), rsakey.size_in_bytes()) # Funkcja zwraca obiekt reprezentujacy algorytm szyfrujacy oraz wielkosc klucza RSA w bajtach.


#Funkcja kompresuje tekst podany w jej argumencie. Nastepenie generuje losowy klucz sesji na potrzeby AES za pomoca ktorego szyfruje skompresowany tekst.
#Zwracanym wynikiem jest klucz sessji polaczony z zaszyfrowanymi danymi, aby mozna je bylo powniej odszyfrowac. Aby dolaczyc ten klucz szyfrujemy go za pomoca algorytmu RSA i publicznego klucza. Nastepnie laczymy w calosc dane i zwracamy w postaci zakodowanego ciagu znakow.
def encrypt(plaintext):
    compressed_text = zlib.compress(plaintext)

    session_key = get_random_bytes(16)
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(compressed_text)

    cipher_rsa, _ = get_rsa_cipher('pub')
    encrypted_session_key = cipher_rsa.encrypt(session_key)

    msg_payload = encrypted_session_key + cipher_aes.nonce + tag + ciphertext

    encrypted = base64.encodebytes(msg_payload)
    return(encrypted)



# Aby odszyfrowac dane wykonujemy te same opracje co w funkcji szyfrujacej ale w odwrotenj kolejnosci. Najpierw dekodujemy zapisany w formacie base64 ciag znakow. Nastepnie odczytujemy z niego zaszyfrowany klucz sesji i inne niezbedne informacje. Wykorzystujac prywatny klucz RSA deszyfrujemy klucz sesji za pomoca ktorego odtwarzamy dane zaszyfrowane za pomoca algorytmu AES. Na koniec rozpakowujemy dane i zwracamy je w postaci zwyklego tekstu.
def decrypt(encrypted):
    encrypted_bytes = BytesIO(base64.decodebytes(encrypted))
    cipher_rsa, keysize_in_bytes = get_rsa_cipher('pri')

    encrypted_session_key = encrypted_bytes.read(keysize_in_bytes)
    nonce = encrypted_bytes.read(16)
    tag = encrypted_bytes.read(16)
    ciphertext = encrypted_bytes.read()

    session_key = cipher_rsa.decrypt(encrypted_session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    decrypted = cipher_aes.decrypt_and_verify(ciphertext, tag)

    plaintext = zlib.decompress(decrypted)
    return plaintext


if __name__ == '__main__':
    plaintext = b'abcdefghij'
    print(decrypt(encrypt(plaintext)))
