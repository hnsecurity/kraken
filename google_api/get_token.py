import requests
import subprocess
from google_api.proxy import getTokenFromChrome


def refresh_token(old_token):
    r = requests.post('https://www.googleapis.com/oauth2/v4/token', headers={'sec-fetch-site': 'none', 'sec-fetch-mode': 'no-cors', 'sec-fetch-dest': 'empty',
                                                                             'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36'},
                      data={"scope": "https://www.googleapis.com/auth/identity.passwords.leak.check",
                            "grant_type": "refresh_token",
                            "refresh_token": old_token,
                            "client_id": "77185425430.apps.googleusercontent.com",
                            "client_secret": "OTJgUOQcT7lO7GsGZq2G4IlT"})

    return r.json()['access_token']


def get_token():
    try:
        with open('refresh_token', 'r') as f:
            rt = f.read()
            return refresh_token(rt)
    except:
        rt = getTokenFromChrome()

        with open('refresh_token', 'w') as f:
            f.write(rt)

        return refresh_token(rt)
