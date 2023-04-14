import requests
import os
import json
import base64
from termcolor import colored
from cryptography.fernet import Fernet

def generateKey():
    return Fernet.generate_key()

def appendNewChatToJson(username, chat_id):

    oldjson = loadJson()

    keys_json_string = '{"username":"'+username+'","chat_id":"'+chat_id+'", "symmetric_chat_key":""}'
    keys_json = json.loads(keys_json_string)

    oldjson.append(keys_json)

    with open('keys.json', 'w') as f:
        json.dump(oldjson, f)
    global json_obj
    json_obj = loadJson()

def encryptMessage(plain_message):
    return fernet_loaded_key.encrypt(plain_message)

def decryptMessage(encrypted_message):
    try:
        decrypted_message = fernet_loaded_key.decrypt(encrypted_message)
    except:
        decrypted_message = colored("The decryption failed!", 'yellow').encode('utf-8')
    return decrypted_message

def sendMessage(token, plain_message, chat_id):
    url = f"https://discord.com/api/v9/channels/{chat_id}/messages"
    header = {"authorization": token}
    data = {"content":b"disenc: "+encryptMessage(plain_message)}
    statuscode = requests.post(url, data=data, headers=header)
    if statuscode.status_code != 200:
        print(statuscode.status_code)

def getMessagesFromChat(token, nummer_of_messages, chat_id):
    url = f"https://discord.com/api/v9/channels/{chat_id}/messages?limit={nummer_of_messages}"
    header = {"authorization": token}
    http_response = requests.get(url, headers=header)
    response_json = http_response.json()
    return response_json

def loadJson():
    with open("keys.json", "rb") as string:
        json_bytes = string.read().rstrip()
    try:
        return json.loads(json_bytes.decode("utf-8"))
    except:
        initJson()
        loadJson()

def printMessages(nummer_of_messages,chat_id):
    cleanTerminal()
    response = getMessagesFromChat(token,nummer_of_messages,chat_id)
    response = response[::-1]
    username = getUsermaneFromToken()
    for messages in response:
        #Checks if the message is a encrypted one and decryptes it. These messages are markted with "disenc :" 
        if 'disenc: ' in messages['content']:
            encryptedMessage = messages['content'].replace('disenc: ','')
            print(colored(messages['author']['username'], 'green')+": "+decryptMessage(encryptedMessage).decode("utf-8") )
        #If the message is not encrypted the message is displayed normaly.
        else:
            print(colored(messages['author']['username'], 'red')+": "+messages['content'])

def sendMessageScreen(token, chat_id):
    cleanTerminal()
    printMessages(nummer_of_messages,chat_id)
    textintput = input()
    if '/e' not in textintput:
        if '/c' not in textintput:
            sendMessage(token, bytes(textintput, 'utf-8'), chat_id)
            printMessages(nummer_of_messages,chat_id)
        else:
            chatInterface()
    else:
        initTerminal()

def cleanTerminal():
    os.system('cls||clear')

def initJson():
    with open('keys.json', 'w') as f:
        f.write('[{"username": "username", "chat_id": "chat_id", "symmetric_chat_key": ""}]')

def initTerminal():
    global selectedChat 
    selectedChat = -1
    cleanTerminal()
    print(colored("select chat or /a to add new chat:", 'yellow'))
    i=0
    for line in json_obj:
        print(i,line['username'],line['chat_id'])
        i=i+1
    
    selectedChat = input()
    if selectedChat == "/a":
        addNewChat()
    elif selectedChat != 0:
        try:
            symmetric_chat_key = json_obj[int(selectedChat)]["symmetric_chat_key"]
            global chat_id
            global fernet_loaded_key
            chat_id = json_obj[int(selectedChat)]["chat_id"]
            fernet_loaded_key = Fernet(symmetric_chat_key)
        except:
            selectedChat = -1

def chatInterface():
    cleanTerminal()
    print(colored("/e", 'yellow'),"exit",colored("/r", 'yellow'),"read chat",colored("/s", 'yellow'),"send message",colored("/c", 'yellow'),"exit selected")
    print(colored("/k", 'yellow'),"display public key")

    textintput = input()

    match textintput:
        case "/e": initTerminal()
        case "/r":
            printMessages(nummer_of_messages,chat_id)
            input()
        case "/s":
            sendMessageScreen(token, chat_id)
            input()
        case "/c": chatInterface()
        case "/k": displaysymmetricKey(selectedChat)
        case _: chatInterface()

def addNewChat():
    cleanTerminal()

    print("name of chat (username or group name)")
    username = input()
    print("chat id")
    chat_id = input()
    appendNewChatToJson(username,chat_id)
    global selectedChat
    selectedChat = -1

def addsymmetricKeyToChat(symmetric_chat_key, selectedChat):
    oldjson = loadJson()
    oldjson[int(selectedChat)]["symmetric_chat_key"] = symmetric_chat_key.decode("utf-8")
    with open('keys.json', 'w') as f:
        json.dump(oldjson, f)

def displaysymmetricKey(selectedChat):
    cleanTerminal()
    print("your symmetric key:")
    print(colored(json_obj[int(selectedChat)]["symmetric_chat_key"], 'yellow')+'\n')
    input()

def symmetricKeyHandling(selectedChat):
    cleanTerminal()
    print(colored("/g", 'yellow'),"generate new symmetric key",colored("/r", 'yellow'),"enter existing symmetric key",colored("/e", 'yellow'),"exit")
    textintput = input()
    if textintput == '/g':
        symmetric_chat_key = generateKey()
        addsymmetricKeyToChat(symmetric_chat_key, selectedChat)
        print("your symmetric key:")
        print(colored(symmetric_chat_key.decode('utf-8'), 'yellow')+'\n')
        input()
    elif textintput == '/r':
        print("enter existing symmetric key:")
        symmetric_chat_key = input()
        addsymmetricKeyToChat(symmetric_chat_key.encode('utf-8'), selectedChat)
    else:
        initTerminal()

def checkIfsymmetricKeyIsPressent(selectedChat):
    if json_obj[int(selectedChat)]["symmetric_chat_key"] == '':
        symmetricKeyHandling(selectedChat)
    
def getUsermaneFromToken():
    url = f"https://discord.com/api/v9/users/@me"
    header = {"authorization": token}
    response = requests.get(url, headers=header)
    response_json = response.json()
    return response_json["username"]

def loadTokenFromFile():
    with open("f", "rb") as string:
        json_bytes = string.read().rstrip()
    return json_bytes.decode('utf-8')

#Global Settings
json_obj = loadJson()
nummer_of_messages = 50
selectedChat = -1
token = loadTokenFromFile()
chat_id = ""
fernet_loaded_key = ""

while True:
    if(selectedChat != -1):
        checkIfsymmetricKeyIsPressent(selectedChat)
        if(selectedChat == -1):
            continue
        chatInterface()
    else:
        initTerminal()