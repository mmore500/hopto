#!/usr/bin/python3

from pbkdf2 import PBKDF2
import pyaes
import secrets
import os, sys
from base64 import b64encode
from getpass import getpass
import binascii
import inspect

def main():
  # sanitize input
  if len(sys.argv) < 2:
    print("Usage:\n%s filename [password]"%sys.argv[0])
    exit(0)
  plaintext = sys.argv[1]

  if len(sys.argv) > 2:
    password = sys.argv[2]
  else:
    while True:
      password = getpass(prompt='Password: ')
      if password == getpass(prompt='Confirm: '):
        break
      print("Passwords don\'t match, try again.")

  salt = os.urandom(32)
  key = PBKDF2(
        password,
        salt
    ).read(32)

  iv = secrets.randbits(128)

  aes = pyaes.AESModeOfOperationCTR(
    key,
    pyaes.Counter(iv)
  )
  payload = aes.encrypt(plaintext)

  print(inspect.cleandoc(f'''
        salt: "{b64encode(salt).decode("utf-8")}"
        iv: "{format(iv,'x')}"
        payload: "{b64encode(payload).decode("utf-8")}"
    '''))

if __name__ == '__main__':
  main()
