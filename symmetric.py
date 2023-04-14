import cryptography
from cryptography.fernet import Fernet

key = Fernet.generate_key()
#print(key.decode('utf-8'))

fernet = Fernet(key)
encrypted = fernet.encrypt(b"data")
print(encrypted.decode('utf-8'))

decrypted = fernet.decrypt(encrypted)
print(decrypted.decode('utf-8'))