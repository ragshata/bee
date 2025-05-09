import requests
import json
import base64


def check_license(key):
    url = "https://beeclick.io/checkuserdata"
    data = {"serial": key}
    r = requests.post(url=url, data=data)
    if r.text == "ok":
        return True
    else:
        return False

def cprint_heck_license(key):
    url = "https://beeclick.io/checkuserdata"
    data = {"serial": key}
    r = requests.post(url=url, data=data)
    return r.text

def decrypt(a):
    a = a.replace("=", "")
    a = a[::-1]
    a = a.replace("1EwCyIsInF1cXVlYjoqUTFEf0QDNXg0MG", "")
    first = "e" + a[-26:]
    last = a[1:-26]
    full = first + last + "="
    return full


def ex_key(key):
    key = base64.b64decode(key)
    key = key.decode("utf-8")
    key = json.loads(key)
    key = key["queue"]
    return key


def ex_login(key):
    login = json.loads(base64.b64decode(key).decode("utf-8"))
    return login["timing"]
