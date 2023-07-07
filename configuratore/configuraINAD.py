import base64
import re
import json
import sys
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pwinput
import pyinputplus as pyip

salt = b"parlaConINAD"
def kdf():
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
        )

def ottieni_chiave(stringa):
    '''Ottiene la chiave crittografica a partire da una stringa'''
    x = base64.urlsafe_b64encode(kdf().derive(stringa))
    return x

def imposta_password():
    '''Chiede all'utente di impostare una password sicura
    e restituisce la chiave crittografica derivata'''
    RE_PASSWORD = "^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!#$%&@.,\[\]-_?].*)(?=.*[\W]).{8,20}$"
    password_1 = ""
    while bool(re.match(RE_PASSWORD, password_1)) is False:
        print("Scegli una password. Fra 8 e 20 caratteri con una maiuscola, "\
              "una minuscola, un numero e un carattere speciale.")
        password_1 = pwinput.pwinput(prompt = "Scegli una password: ")
        password_2 = pwinput.pwinput(prompt= "Ripeti la password: ")
        while password_1 != password_2:
            print("Le password non coincidono. Ripeti.")
            password_1 = pwinput.pwinput(prompt = "Scegli una password: ")
            password_2 = pwinput.pwinput(prompt= "Ripeti la password: ")
        if bool(re.match(RE_PASSWORD, password_1)) is False:
            print("Password debole. Ripeti.")
    parola = password_1.encode()
    x = base64.urlsafe_b64encode(kdf().derive(parola))
    password_1 = ""
    password_2 = ""
    parola = b""
    return x

def cifra_file(file_da_cifrare, chiave, output_file = ""):
    '''Cifra un file in un altro file'''
    if output_file == "":
        output_file = file_da_cifrare
    with open(file_da_cifrare, "rb") as f:
        originale = f.read()
    fernet = Fernet(chiave)
    cifrato = fernet.encrypt(originale)
    with open(output_file, "wb") as f:
        f.write(cifrato)

def cifra_dizionario(diz, chiave, output_file):
    '''Salva un dizionario diz nel file output_file cifrato con la chiave "chiave" '''
    fernet = Fernet(chiave)
    a = json.dumps(diz, indent=4).encode()
    b =fernet.encrypt(a)
    with open(output_file, "wb") as f:
        f.write(b)

def decifra_dizionario(input_file, chiave):
    '''Decifra un dizionario memorizzato in un file JSON'''
    fernet = Fernet(chiave)
    with open(input_file, "rb") as f:
        a = f.read()
        b = fernet.decrypt(a)
        c = b.decode()
        d = json.loads(c)
    return d

BASE_URL_AUTH = "https://auth.interop.pagopa.it/token.oauth2" #Ambiente PDND di produzione
BASE_URL_INAD = "https://api.inad.gov.it/rest/inad/v1/domiciliodigitale"
AUD_INTEROP = "auth.interop.pagopa.it/client-assertion"

chiave = imposta_password()

print("Configuriamo i dati del client e-service di INAD. Li trovi nel back-office della PDND.")
print("Puoi confermare alcuni dati, preconfigurati per l'ambiente PDND/INAD di produzione.")
INAD = {
              "kid" : "",
              "typ" : "JWT",
              "iss" : "",
              "sub" : "",
              "aud" : AUD_INTEROP,
              "alg" : "RS256",
              "PurposeID" : "",
              "Client_id" : "",
              "Client_assertion_type" : "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
              "Grant_type" : "client_credentials",
              "baseURL" : BASE_URL_INAD
             }
for i in INAD:
    if INAD[i] == "":
        value = pyip.inputStr(prompt = i+": ", blank = False)
        INAD[i] = value
    else:
        confirm = pyip.inputYesNo(prompt = i + " = " + INAD[i] +". Confermi? [Y/N]: ")
        if confirm == "no":
            value = pyip.inputStr(prompt = i+": ", blank = False)
            INAD[i] = value
cifra_dizionario(INAD, chiave, "INAD.master.cfg")
INAD = {}

nome_file_chiave = input("Configuriamo la chiave privata. Nome del file della chiave privata (es.: key.priv): ")
CHIAVE_TROVATA = False
while CHIAVE_TROVATA is False:
    if os.path.exists(nome_file_chiave):
        CHIAVE_TROVATA = True
        print("File trovato.")
        cifra_file(nome_file_chiave, chiave, "chiave.master.priv")
        print("Ho configurato la chiave in un file cifrato. "\
              "Cancella il file " + nome_file_chiave + " dalla cartella del programma.")
    else:
        nome_file_chiave = input(
            "File "+ nome_file_chiave + "non trovato. Verifica e "\
            "inserisci di nuovo il nome del file della chiave privata: "
            )
print("Fatto!")
print("Ricordati la password master per configurare le installazioni di parlaConINAD.\n")
x = input ("Premi INVIO/ENTER per terminare.")

