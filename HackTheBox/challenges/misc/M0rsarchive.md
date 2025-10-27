### challenge
Just unzip the archive ... several times ...

---
- `solution.py`
```python
from PIL import Image
from zipfile import ZipFile
import os

morse = {
    ".-": "a",
    "-...": "b",
    "-.-.": "c",
    "-..": "d",
    ".": "e",
    "..-.": "f",
    "--.": "g",
    "....": "h",
    "..": "i",
    ".---": "j",
    "-.-": "k",
    ".-..": "l",
    "--": "m",
    "-.": "n",
    "---": "o",
    ".--.": "p",
    "--.-": "q",
    ".-.": "r",
    "...": "s",
    "-": "t",
    "..-": "u",
    "...-": "v",
    ".--": "w",
    "-..-": "x",
    "-.--": "y",
    "--..": "z",
    "-----": "0",
    ".----": "1",
    "..---": "2",
    "...--": "3",
    "....-": "4",
    ".....": "5",
    "-....": "6",
    "--...": "7",
    "---..": "8",
    "----.": "9"
}

def password(passwordfile):
    with Image.open(passwordfile) as im:
        px = im.load()
        size = im.size
        # print("[+] Image size: {}".format(size))
        base_pixel = px[0,0]
        morse_pixel = px[1,1]
        # print("[+] Base pixel: {}".format(base_pixel))
        # print("[+] Morse Pixel: {}".format(morse_pixel))
        # Start from below
        pixelrow = []
        password = []
        for i in range(1,size[1],2):
            for j in range(size[0]):
                if px[j,i] == base_pixel:
                    pixelrow.append('0')
                else:
                    pixelrow.append('1')
            morsecode = "".join(pixelrow).strip('0').replace("111","-").replace("1",".").replace("0","")
            print(morsecode)
            password.append(morse[morsecode])
            pixelrow = []
        passw = "".join(password)
        print()
        return passw

def getzipname():
    for files in os.listdir():
        if ".zip" in files:
            return files


def unzip(filename,passwordfilename):
    with ZipFile(filename) as zipf:
        passs = password(passwordfilename)
        print("opening zip file {} with {}".format(filename,passs))
        zipf.extractall(pwd=bytes(passs,'utf-8'))
        os.remove(filename)
        os.remove(passwordfilename)
        os.system("mv flag/*.zip flag/*.png .")
    zipname = getzipname()
    unzip(zipname,passwordfilename)

zipname = getzipname()
unzip(zipname,"pwd.png")
```