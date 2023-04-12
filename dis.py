import requests
import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import json
import base64
from cryptography.hazmat.primitives import serialization

#This generatres the key pair
def generateKeyPair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key

#Takes the channel id, private_key and public_key and wrties it to the json file
#TODO: A new json obj should be added at the end of the file. The json obj should contain [] at start and end.
def WriteKeyPairToFile(channel, private_key, public_key):
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    private_key_pem_base64 = base64.b64encode(private_key_pem).decode("utf-8")
    public_key_pem_base64 = base64.b64encode(public_key_pem).decode("utf-8")

    keys_json_string = '{"channelid":"'+channel+'", "private_key":"'+private_key_pem_base64+'","public_key":"'+public_key_pem_base64+'"}'
    keys_json = json.loads(keys_json_string)

    with open('keys.json', 'w') as f:
        json.dump(keys_json, f)

#Takes the private key in base64 form and converts it into the correct type.
def loadPrivateKey(private):
    private_key = serialization.load_pem_private_key(
        base64.b64decode(private),
        password=None,
        backend=default_backend()
    )
    return private_key

#Takes the public key in base64 form and converts it into the correct type.
def loadPublicKey(public):
    public_key = serialization.load_pem_public_key(
        base64.b64decode(public),
        backend=default_backend()
    )
    return public_key

#Takes the message and encrypts it.
#TODO: The public key should be the public key of the message partner.
def encryptMessage(message,public_key):
    encrypted = public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    return encrypted

#TODO: This private key should be your own key.
def decryptMessage(en_message,private_key):
    de_message = private_key.decrypt(
            en_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    return de_message

#Sends the message to the right resipian.
def sendMessage(token, message, resip, public_key):
    url = f"https://discord.com/api/v9/channels/{resip}/messages"
    header = {"authorization": token}
    data = {"content":b"disenc: "+base64.b64encode(encryptMessage(message,public_key))}
    statuscode = requests.post(url, data=data, headers=header)
    print(statuscode.status_code)

#Gets a specific amount of messages from the chat.
def GetMessage(token, num, resip):
    url = f"https://discord.com/api/v9/channels/{resip}/messages?limit={num}"
    header = {"authorization": token}
    response = requests.get(url, headers=header)
    response_json = response.json()
    return response_json

#Loads the json file from the file system.
def loadJson():
    with open("keys.json", "rb") as string:
        json_bytes = string.read().rstrip()
    return json.loads(json_bytes.decode("utf-8"))

#private_key = generateKeyPair()
#public_key = private_key.public_key()
#WriteKeyPairToFile("357149392588898304",private_key,public_key)

json_obj = loadJson()
print(json_obj)

#public_key = loadPublicKey()
private_key = loadPrivateKey(json_obj["private_key"])
public_key = loadPublicKey(json_obj["public_key"])
res = json_obj["channelid"]

token = "MjkwMTgwMDU5MjMzMzg2NDk2.G19Dz6.7HBKjL_Q6gsinj5lqAPomZZzuf9-YpOAAVB1Ck"

#Sends a message.
sendMessage(token, b'Du', res, public_key)

#Gest 2 chat messages and loops trough them
response = GetMessage(token,2,clem)
for messages in response:
    #Checks if the message is a encrypted one and decryptes it. These messages are markted with "disenc :"
    if 'disenc: ' in messages['content']:
        print(messages['author']['username']+":")
        base64string = messages['content'].replace('disenc: ','')
        print(decryptMessage(base64.b64decode(base64string),private_key))
    #If the message is not encrypted the message is displayed normaly.
    else:
        print(messages['author']['username']+":")
        print(messages['content'])
