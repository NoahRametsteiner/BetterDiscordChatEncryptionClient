import requests
import os
import time
import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import json
import base64
from cryptography.hazmat.primitives import serialization
from termcolor import colored

#This generatres the key pair
def generateKeyPair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key

#Takes the channel id, private_key and public_key and wrties it to the json file
def appendNewChatToJson(username, channel, private_key, public_key):

    oldjson = loadJson()

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

    keys_json_string = '{"username":"'+username+'","channelid":"'+channel+'", "private_key":"'+private_key_pem_base64+'","public_key":"'+public_key_pem_base64+'","chat_public_key":""}'
    keys_json = json.loads(keys_json_string)

    oldjson.append(keys_json)

    with open('keys.json', 'w') as f:
        json.dump(oldjson, f)

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
def encryptMessage(message,chat_public_key):
    encrypted = chat_public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    return encrypted

def decryptMessage(en_message,private_key):
    try:
        de_message = private_key.decrypt(
                en_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
    except:
        de_message = colored("The decryption failed!", 'yellow').encode('utf-8')
    return de_message

#Sends the message to the right resipian.
def sendMessage(token, message, resip, chat_public_key):
    url = f"https://discord.com/api/v9/channels/{resip}/messages"
    header = {"authorization": token}
    data = {"content":b"disenc: "+base64.b64encode(encryptMessage(message,chat_public_key))}
    statuscode = requests.post(url, data=data, headers=header)
    if statuscode.status_code != 200:
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
    try:
        return json.loads(json_bytes.decode("utf-8"))
    except:
        initJson()
        loadJson()

#Gest 2 chat messages and loops trough them
#TODO: How can i read the messages i sent when i dont have the key to decrypt them
def printMessages(num,resipient):
    cleanTerminal()
    response = GetMessage(token,num,resipient)
    response = response[::-1]
    for messages in response:
        #Checks if the message is a encrypted one and decryptes it. These messages are markted with "disenc :" 
        if 'disenc: ' in messages['content']:
            base64string = messages['content'].replace('disenc: ','')
            if(messages['author']['username'] == own_username):
                print(colored(messages['author']['username'], 'green')+": "+decryptMessage(base64.b64decode(base64string),private_key).decode("utf-8") )
            else:
                print("")
                #print(colored(messages['author']['username'], 'green')+": "+decryptMessage(base64.b64decode(base64string),private_key).decode("utf-8") )
        #If the message is not encrypted the message is displayed normaly.
        else:
            print(colored(messages['author']['username'], 'red')+": "+messages['content'])
    input()

def sendMessageScreen(token, res, chat_public_key):
    cleanTerminal()
    printMessages(chatSize,res)
    textintput = input()
    if '/e' not in textintput:
        if '/c' not in textintput:
            sendMessage(token, bytes(textintput, 'utf-8'), res, chat_public_key)
            printMessages(chatSize,res)
        else:
            terminal()
    else:
        initTerminal()

def cleanTerminal():
    os.system('cls||clear')

def initJson():
    with open('keys.json', 'w') as f:
        f.write('[{"username": "username", "channelid": "channelid", "private_key": "", "public_key": "=="}]')

def initTerminal():
    global selectedChat 
    selectedChat = -1
    cleanTerminal()
    print(colored("select chat or /a to add new chat:", 'yellow'))
    i=0
    for line in json_obj:
        print(i,line['username'],line['channelid'])
        i=i+1

def terminal():
    cleanTerminal()
    print(colored("/e", 'yellow'),"exit",colored("/r", 'yellow'),"read chat",colored("/s", 'yellow'),"send message",colored("/a", 'yellow'),"add new chat",colored("/c", 'yellow'),"exit selected")
    print(colored("/k", 'yellow'),"display public key")

def addNewChat():
    cleanTerminal()
    private_key = generateKeyPair()
    public_key = private_key.public_key()

    print("name of chat (username or group name)")
    username = input()
    print("channel id")
    channelid = input()
    appendNewChatToJson(username,channelid,private_key,public_key)
    global selectedChat
    selectedChat = -1

def addChatPublicKey(selectedChat, chat_public_key):
    oldjson = loadJson()
    oldjson[int(selectedChat)]["chat_public_key"] = chat_public_key
    with open('keys.json', 'w') as f:
        json.dump(oldjson, f)
    terminal()

def displayPublicKey(selectedChat):
    cleanTerminal()
    print("your public key:")
    print(colored(json_obj[int(selectedChat)]["public_key"], 'yellow')+'\n')

    print(colored("input public key of the other user or exit with /e:", 'red'))
    chat_public_key = input()

    if '/e' not in chat_public_key:
        addChatPublicKey(selectedChat,chat_public_key)
    else:
        initTerminal()

def checkForChatPublicKey(selectedChat):
    if json_obj[int(selectedChat)]["chat_public_key"] == '':
        displayPublicKey(selectedChat)
    



#Global Settings
json_obj = loadJson()
chatSize = 50
selectedChat = -1
token = "MjkwMTgwMDU5MjMzMzg2NDk2.G19Dz6.7HBKjL_Q6gsinj5lqAPomZZzuf9-YpOAAVB1Ck"

while True:
    if(selectedChat != -1):
        checkForChatPublicKey(selectedChat)
        if(selectedChat == -1):
            continue

        terminal()
        textintput = input()

        match textintput:
            case "/e": initTerminal()
            case "/r": printMessages(chatSize,res)
            case "/s": sendMessageScreen(token, res, public_key)
            case "/c": terminal()
            case "/k": displayPublicKey(selectedChat)
            case _: terminal()
    else:
        initTerminal()
        selectedChat = input()
        if selectedChat == "/a":
            addNewChat()
            json_obj = loadJson()
        elif selectedChat != 0:
            try:
                private_key = loadPrivateKey(json_obj[int(selectedChat)]["private_key"])
                public_key = loadPublicKey(json_obj[int(selectedChat)]["public_key"])
                #chat_public_key = loadPublicKey(json_obj[int(selectedChat)]["chat_public_key"])
                res = json_obj[int(selectedChat)]["channelid"]

                url = f"https://discord.com/api/v9/users/@me"
                header = {"authorization": token}
                response = requests.get(url, headers=header)
                response_json = response.json()
                own_username = response_json["username"]

            except:
                selectedChat = -1