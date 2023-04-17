# PythonDiscordEncryptionApp

This small project uses Python and the discord api to send and read messages that a are encrypted befor beeing sent.

## Installation and setup

Run the installation script. This will install the packages needed. The packages may chnage in the futur so please always run this if you download the program.

Packages that are installed:
- requests
- json
- termcolor
- cryptography

After that you can start the program with the run script.
It will promt you to enter your discord token. [Here](https://www.google.com/search?q=how+to+get+discord+token) is how to get your token.

You can add new channels with /a. It will promted for a name. This should be a username or a group name.
Now you need your channel-id. To get the channel-id you need to open discord in the browser. Go to the channel, group or user you want to write to. The url contains the channel-id. Copy it and past it in the program.   
![channel id](https://user-images.githubusercontent.com/77678379/232425088-f7315204-d956-4cbd-ab69-287bea35a35e.png)

Now you need to generate a key or enter an existing one. 

**TODO:**
Add a way to securly exchange the key.

Copy the key and give it to your partner.

## Use

The program will give you a overview of what commands are supported and what they do. To exit and add a new channel or switch to a different one write /e. To go back to the overview write /c. This works from every menu.
Messages that are not encrypted are marked red. Messages that are encryped are displayed green.


## TODO
- Add a way to securly exchange the key.
- Interface upgrade. (Read chat whit input at the same time)
