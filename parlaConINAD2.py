'''Script per l'interrogazione di INAD (Indice Nazionale dei Domicili Digitali) tramite API.
Per l'autenticazione si fa riferimento alla PDND (Piattaforma Digitale Nazionale Dati), secondo il ModI.
Autore: Francesco Del Castillo'''
import datetime
import sys
import uuid
import os
import base64
import socket
import json
import csv
import re
import logging  #per log di requests
from jose import jwt
from jose.constants import Algorithms
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import requests
#from http.client import HTTPConnection  # py3 #per log di requests
import pwinput
import pyinputplus as pyip

# URL delle API da chiamare
baseURL_auth = "https://auth.uat.interop.pagopa.it/token.oauth2" #Ambiente PDND di collaudo
baseURL_INAD = "https://domiciliodigitaleapi.oscl.infocamere.it/rest/inad/v1/domiciliodigitale"

#nome del file di log generale
logFileName="INAD.log"

#Regole per il logging delle chiamate requests (si loggano solo le chiamate per estrazioni massive)
#logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger("urllib3")
log.setLevel(logging.DEBUG)

## Funzioni che servono per l'interazione con l'utente
def getIPAddress():
    '''Recupera e restituisce l'indirizzo IP dell'utente'''
    return socket.gethostbyname(socket.gethostname())

callingIP = getIPAddress()
callingUser = os.getlogin()

def timestamp():
    '''Restituisce il timestamp attuale in formato %Y%m%d-%H%M%S-%f'''
    return datetime.datetime.now().strftime("%Y%m%d-%H%M%S-%f")

def attendi():
    '''Richiede un'interazione dell'utente per proseguire'''
    q = input("Premi INVIO/ENTER per proseguire.")

def termina():
    '''Richiede un'interazione dell'utente per terminare il programma
    Utile anche a fine srpt per evitare di perdere quanto scritto a video'''
    q = input("Premi INVIO/ENTER per terminare.")
    sys.exit()

reCF = "^([0-9]{11})|([A-Za-z]{6}[0-9]{2}[A-Za-z]{1}[0-9]{2}[A-Za-z]{1}[0-9]{3}[A-Za-z]{1})$"
reMail = "^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"

def chiediCF():
    '''Chiede di inserire un codice fiscale / partita IVA e valida il formato.'''
    ottieniCF = False
    while ottieniCF is False:
        x = input("Inserisci il codice fiscale per cui verificare il domicilio digitale: ")
        if re.match(reCF, x):
            ottieniCF = True
        else:
            print("Codice fiscale non valido.")
    return x
        
def chiediMail():
    '''Chiede di inserire un indirizzo e-mail e valida il formato.'''
    ottieniMail = False
    while ottieniMail is False:
        x = input("Inserisci l\'indirizzo PEC da verificare: ")
        if re.match(reMail, x):
            ottieniMail = True
        else:
            print("Formato indirizzo PEC non valido.")
    return x

def chiediData():
    '''Chiede di inserire una data G/M/A o G-M-A e la restituisce AAAA-MM-GG'''
    x = pyip.inputDate(prompt = "Inserisci la data alla quale verificare: ", formats=["%d/%m/%y", "%d/%m/%Y", "%d-%m-%y", "%d-%m-%Y"])
    y = x.strftime("%Y-%m-%d")
    return y
    
# elenco di parole da interpretare come risposta affermativa in caso di domanda
listaOK = ["sì", "SI", "S", "s", "Sì", "OK", "si"]

## Funzioni che servono per la manipolazione di file di input e output
def crea_cartella(suffisso, dataeora=timestamp()):
    '''Crea una sottocartella nella cartella di esecuzione dello script
    Se l'argomento dataeora è nullo, usa un timestamp al suo posto.
    (Quindi si può modificare con un dataeora=timestamp :)'''
    #x = timestamp() if dataeora=="" else dataeora
    path="./" + dataeora + "-" + suffisso + "/"
    if not os.path.isdir(path):
        os.mkdir(path)
    return path

## Funzioni che servono per il logging
def logRequest(logFile, requestTime, verbo, metodo, info):
    '''Aggiunge una riga al file logFile, con gli argomenti divisi da un ;
    Si usa per annotare nel log le request di requests'''
    rigaDiLog=[requestTime, callingIP, callingUser, verbo, metodo, info]
    logFile.write(";".join(rigaDiLog))
    logFile.write("\n")
    logFile.flush()

def logResponse(logFile, responseTime, requestTime, status_code, info):
    '''Aggiunge una riga al file logFile, con gli argomenti divisi da un ;
    Si usa per annotare nel log le request di requests'''
    rigaDiLog=[responseTime, callingIP, requestTime, str(status_code), info]
    logFile.write(";".join(rigaDiLog))
    logFile.write("\n")
    logFile.flush()

def clear():
    '''Cancella la schermo'''
    os.system("cls" if os.name == "nt" else "clear")

## Funzioni crittografiche
def cifraStringa(stringa, chiave):
    '''Cifra una stringa con la chiave indicata'''
    fernet = Fernet(chiave)
    fernet.encrypt(stringa.encode())

def decifraStringa(stringa, chiave):
    '''Decifra una stringa cifrata tramite la chiave indicata'''
    fernet = Fernet(chiave)
    fernet.decrypt(stringa).decode()

def cifraDizionario(diz, chiave, outputFile):
    '''Salva un dizionario diz nel file outputFile cifrato con la chiave "chiave" '''
    fernet = Fernet(chiave)
    a = json.dumps(diz, indent=4).encode()
    b =fernet.encrypt(a)
    with open(outputFile, "wb") as f:
        f.write(b)

def decifraDizionario(inputFile, chiave):
    '''Decifra un dizionario memorizzato in un file JSON'''
    fernet = Fernet(chiave)
    with open(inputFile, "rb") as f:
        a = f.read()
        b = fernet.decrypt(a)
        c = b.decode()
        d = json.loads(c)
    return d

def cifraFile(fileDaCifrare, chiave, outputFile = ""):
    '''Cifra un file in un altro file'''
    if outputFile == "":
        outputFile = fileDaCifrare
    with open(fileDaCifrare, "rb") as f:
        originale = f.read()
    fernet = Fernet(chiave)
    cifrato = fernet.encrypt(originale)
    with open(outputFile, "wb") as f:
        f.write(cifrato)

def decifraFile(fileDaDecifrare, chiave, outputFile = ""):
    '''Decifra un file in un altro file'''
    if outputFile == "":
        outputFile = fileDaDecifrare
    with open(fileDaDecifrare, "rb") as f:
        cifrato = f.read()
    fernet = Fernet(chiave)
    originale = fernet.decrypt(cifrato)
    with open(outputFile, "wb") as f:
        f.write(originale)

def recuperaChiave(fileCifrato, chiave):
    '''Recupera la chiave privata da un file cifrato con cifraChiave.
    In realtà decifra qualsiasi file cifrato e lo restituisce come risultato.'''
    with open(fileCifrato, "rb") as f:
        fernet = Fernet(chiave)
        a = f.read()
        b = fernet.decrypt(a)
    return b

salt = b"parlaConINAD"
def kdf():
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
        )

def ottieniChiave(stringa):
    '''Ottiene la chiave crittografica a partire da una stringa'''
    x = base64.urlsafe_b64encode(kdf().derive(stringa))
    return x

def impostaPassword():
    '''Chiede all'utente di impostare una password sicura
    e restituisce la chiave crittografica derivata'''
    rePassword = "^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!#$%&?].*)(?=.*[\W]).{8,20}$"
    passw = ""
    while bool(re.match(rePassword, passw)) is False:
        print("Scegli una password. Fra 8 e 20 caratteri con una maiuscola, una minuscola, un numero e un carattere speciale.")
        passw = pwinput.pwinput(prompt = "Scegli una password: ")
        passw2 = pwinput.pwinput(prompt= "Ripeti la password: ")
        while passw != passw2:
            print("Le password non coincidono. Ripeti.")
            passw = pwinput.pwinput(prompt = "Scegli una password: ")
            passw2 = pwinput.pwinput(prompt= "Ripeti la password: ")
        if bool(re.match(rePassword, passw)) is False:
            print("Password debole. Ripeti.")
    password = passw.encode()
    x = base64.urlsafe_b64encode(kdf().derive(password))
    passw = ""
    password = b""
    return x

## Funzioni che servono per interazione con PDND per staccare il token
def get_private_key(key_path):
    '''Recupera la chiave privata dal file in cui è memorizzata.'''
    with open(key_path, "rb") as private_key:
        encoded_string = private_key.read()
        return encoded_string

def get_key(key_path):
    '''Recupera una chiave dal file in cui è memorizzata (non usata).'''    
    with open(key_path, "rb") as key:
        encoded_string = key.read()
        return encoded_string

def create_m2m_client_assertion(kid, alg, typ, iss, sub, aud, key, purposeID = ""):
    '''Crea l'asserzione JWT e la firma, per ottenere il token da PDND.'''
    issued = datetime.datetime.utcnow()
    delta = datetime.timedelta(minutes=2)
    expire_in = issued + delta
    jti = uuid.uuid4()
    headers_rsa = {
        "kid": kid,
        "alg": alg,
        "typ": typ
    }
    payload = {
        "iss": iss,
        "sub": sub,
        "aud": aud,
        "jti": str(jti),
        "iat": issued,
        "exp": expire_in,
        "purposeId" : purposeID
    }
    client_assertion = jwt.encode(payload, key, algorithm=Algorithms.RS256, headers=headers_rsa)
    return client_assertion

def token_request(client_id, client_assertion, client_assertion_type, grant_type):
    '''Invia l'asserzione firmata a PDND e recupea il token di autenticazione per INAD.'''
    #client_assertion_type = datiINAD.Client_assertion_type
    #grant_type = datiINAD.Grant_type
    body = {
        "client_id" : client_id,
        "client_assertion" : client_assertion,
        "client_assertion_type" : client_assertion_type,
        "grant_type" : grant_type
    }
    headers = {"Content-Type" : "application/x-www-form-urlencoded"}
    with open(logFileName, "a+") as logFile:
        requestTime=timestamp()
        logRequest(logFile, requestTime, "POST", "token_request", client_id)
        r = requests.post(baseURL_auth, headers = headers, timeout=100, data=body)
        responseTime=timestamp()
        info = str(r.status_code)
        logResponse(logFile, responseTime, requestTime, r.status_code, info)
    return r

## Funzioni per l'interazione con INAD (autoesplicative)
def estrai(token, cf, ref):
    '''Interroga INAD per estrarre un domicilio digitale a partire dal codice fiscale cf
    ref è il practicalReference cioè il riferimento al procedimento amministrativo
    per il quale si richiede l'estrazione'''
    url = baseURL_INAD+"/extract/"+cf
    headers = {"Authorization": "Bearer "+token}
    #parameters = {"codice_fiscale" : cf, "practicalReference" : ref}
    parametri = {"practicalReference" : ref}
    with open(logFileName, "a+") as logFile:
        requestTime=timestamp()
        logRequest(
            logFile, requestTime, "GET", "estrai", "richiesto domicilio digitale per "+cf[:2]+"***"
            )
        r = requests.get(url, headers = headers, params = parametri, timeout=100)
        responseTime=timestamp()
        info = str(r.status_code)
        logResponse(logFile, responseTime, requestTime, r.status_code, info)
    return r

def verificaDomicilio(token, cf, ref, mail, data):
    '''Verifica la validità di un domicilio digitale per un certo codice fiscale a una certa data
    ref è il practicalReference cioè il riferimento al procedimento amministrativo 
    per il quale si richiede l'estrazione'''
    url = baseURL_INAD+"/verify/"+cf
    headers = {"Authorization": "Bearer "+token}
    parametri = {"practicalReference" : ref, "digital_address" : mail, "since" : data}
    #parametri = {"practicalReference" : ref, "since" : data} #parametri incompleti per test
    with open(logFileName, "a+") as logFile:
        requestTime=timestamp()
        logRequest(
            logFile, requestTime, "GET", "verifica", 
            "richiesta verifica del domicilio digitale "+mail[:3]+"***"
            )
        r = requests.get(url, headers = headers, params = parametri, timeout=100)
        responseTime=timestamp()
        info = str(r.status_code)
        logResponse(logFile, responseTime, requestTime, r.status_code, info)
    return r

def caricaLista(token, lista, ref):
    '''Invia a INAD una lista di codici fiscali di cui ottenere il domicilio digitale'''
    url = baseURL_INAD+"/listDigitalAddress"
    headers = {"Authorization": "Bearer "+token}
    payload = {
                "codiciFiscali" : lista,
                "practicalReference" : ref
              }
    with open(logFileName, "a+") as logFile:
        requestTime=timestamp()
        logRequest(
            logFile, requestTime, "POST", "carica lista di CF", 
            "richiesta verifica massiva per "+ref
            )
        r = requests.post(url, headers = headers, json = payload, timeout=100)
        responseTime=timestamp()
        info = str(r.status_code)
        logResponse(logFile, responseTime, requestTime, r.status_code, info)
    return r

def statoLista(token, idLista):
    '''Interroga INAD sullo stato di elaborazione di una lista precedentemente inviata''' 
    url = baseURL_INAD+"/listDigitalAddress/state/"+idLista
    headers = {"Authorization": "Bearer "+token}
    with open(logFileName, "a+") as logFile:
        requestTime=timestamp()
        logRequest(
            logFile, requestTime, "GET", "verifica stato lista",
            "richiesta verifica stato per lista id "+idLista
            )
        r = requests.get(url, headers = headers, timeout=100, allow_redirects = False)
        responseTime=timestamp()
        info = str(r.status_code)
        logResponse(logFile, responseTime, requestTime, r.status_code, info)
    return r

def prelevaLista(token, idLista):
    '''Recupera da INAD una lista di codici fiscali 
    per i quali sono stati elaborati i domicili digitali'''
    url = baseURL_INAD+"/listDigitalAddress/response/"+idLista
    headers = {"Authorization": "Bearer "+token}
    with open(logFileName, "a+") as logFile:
        requestTime=timestamp()
        logRequest(
            logFile, requestTime, "GET", "verifica stato lista",
            "richiesta verifica stato per lista id "+idLista
            )
        r = requests.get(url, headers = headers, timeout=100)
        responseTime=timestamp()
        info = str(r.status_code)
        logResponse(logFile, responseTime, requestTime, r.status_code, info)
    return r

durataToken = 86400

#####################################
###INIZIO DELLO SCRIPT INTERATTIVO###
#####################################

#####################################
### INSTALLAZIONE AL PRIMO AVVIO ####
#####################################
print("Benvenuto "+callingUser+".")
if os.path.exists("INAD.cfg") is False:
    print("Il programma non è configurato.")
    print("Copia il file della chiave privata associata alla chiave pubblica del client e-service INAD nella cartella di questo programma.")
    print("Ti chiederò di: ")
    print("- scegliere una password")
    print("- inserire i dati di configurazione del client e-service PDND di INAD;")
    print("- indicare il nome del file della chiave privata.")
#    passw = pwinput.pwinput(prompt = "Scegli una password: ")
#    passw2 = pwinput.pwinput(prompt= "Ripeti la password: ")
#    while passw != passw2:
#        print("Le password non coincidono. Ripeti.")
#        passw = pwinput.pwinput(prompt = "Scegli una password: ")
#        passw2 = pwinput.pwinput(prompt= "Ripeti la password: ")
#    password = passw.encode()
#    chiave = base64.urlsafe_b64encode(kdf().derive(password))
#    password = b""
    chiave = impostaPassword()
    print("Password impostata. \nAnnotala in un luogo segreto e sicuro: NON potrai recuperarla in alcun modo.")
    print("Configuriamo i dati del client e-service di INAD. Li trovi nel back-office della PDND.")
    #seguono i parametri che servono per contattare il client e-service INAD su PDND.
    #alcuni sono predefiniti e non vengono chiesti.
    #Si possono modificare o sostituire con la stringa vuota "" per inserire interattivamente.
    INAD = {
                  "kid" : "",
                  "typ" : "JWT",
                  "iss" : "",
                  "sub" : "",
                  "aud" : "auth.uat.interop.pagopa.it/client-assertion",
                  "alg" : "RS256",
                  "PurposeID" : "",
                  "Client_id" : "",
                  "Client_assertion_type" : "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                  "Grant_type" : "client_credentials",
                  "baseURL" : "https://domiciliodigitaleapi.oscl.infocamere.it/rest/inad/v1/domiciliodigitale"
                 }
    lista = []
    for i in INAD:
        if INAD[i] == "":
            lista.append(i)
    for i in lista:
        value = input(i+": ")
        INAD[i] = value
    cifraDizionario(INAD, chiave, "INAD.cfg")
    print("Dati del client e-service configurati.")
    print("Configuriamo la chiave privata.")
    nomeFileChiave = input("Nome del file della chiave privata (es.: key.priv): ")
    chiaveTrovata = False
    while chiaveTrovata is False:
        if os.path.exists(nomeFileChiave):
            chiaveTrovata = True
            print("File trovato.")
            cifraFile(nomeFileChiave, chiave, "chiave.priv")
            print("Ho configurato la chiave in un file cifrato. Cancella il file " + nomeFileChiave + " dalla cartella del programma.")
        else:
            nomeFileChiave = input(
                "File "+ nomeFileChiave + "non trovato. Verifica e inserisci di nuovo il nome del file della chiave privata: "
                )
    print("La configurazione è terminata. \nRicorda la password per avviare i programmi di interazione con INAD.")
elif os.path.exists("chiave.priv") is False:
    print("IL programma è configurato a metà. Manca la chiave privata da usare per il service e-client INAD.")
    print("Ti chiederò di inserire la password precedentemente scelta.")
    print("Se non la ricordi, cancella il file \'INAD.cfg\' dalla cartella del programma e avvia di nuovo l'installazione.")
    passw = pwinput.pwinput()
    passw2 = pwinput.pwinput(prompt= "Ripeti la password: ")
    while passw != passw2:
        print("Le password non coincidono. Ripeti.")
        passw = pwinput.pwinput()
        passw2 = pwinput.pwinput(prompt= "Ripeti la password: ")
    password = passw.encode()
    chiave = base64.urlsafe_b64encode(kdf().derive(password))
    password=b""
    print("Le password coincidono.")
    print("Copia il file con la chiave privata associata al client e-service INAD nella cartella del programma.")
    nomeFileChiave = input("Nome del file della chiave privata (es.: key.priv): ")
    chiaveTrovata = False
    while chiaveTrovata is False:
        if os.path.exists(nomeFileChiave):
            chiaveTrovata = True
            print("File trovato.")
            cifraFile(nomeFileChiave, chiave, "chiave.priv")
            print("Ho configurato la chiave in un file cifrato. Cancella il file " + nomeFileChiave + " dalla cartella del programma.")
        else:
            nomeFileChiave = input(
                "File "+ nomeFileChiave + "non trovato. Verifica e inserisci di nuovo il nome del file della chiave privata: "
                )
    print("La configurazione è terminata. \nRicorda la password per avviare i programmi di interazione con INAD.")
else:
    print("Il programma sembra già configurato.")
    print("Se non ricordi la password cancella dalla cartella del programma i file \'INAD.cfg\' e \'chiave.priv\' e ripeti l'installazione.")

#####################################
### AVVIO INTERAZIONE CON INAD  #####
#####################################

#Verifica se configurazione presente e chiedi e verifica password.
if "chiave" in locals():
    print("\nSei già loggato. Proseguiamo.")
else:
    passw = pwinput.pwinput()
    password = passw.encode()
    chiave = base64.urlsafe_b64encode(kdf().derive(password))
    password = b""
    passwordCorretta = False
    while passwordCorretta is False:
        with open("INAD.cfg", "r") as f:
            try:
                INAD = decifraDizionario("INAD.cfg", chiave)
                print("La password è corretta.")
                passwordCorretta = True
            except:
                print("La password NON è corretta.")
                passw = pwinput.pwinput()
                password = passw.encode()
                chiave = base64.urlsafe_b64encode(kdf().derive(password))
                password = b""

continuare = True
while continuare is True:

    ###Scegli la funzione da usare
    print("\nparlaConINAD consente le seguenti funzioni: \n1 - estrazione puntuale di un domicilio digitale; \n2 - verifica puntuale di un domicilio fiscale; \n3 - estrazione massiva di domicili digitali; \n4 - recupero dei risultati di una lista precedentemente caricata; \nU - esci da parlaConINAD.")
    scelta = ""
    while scelta not in ["1", "2", "3", "4", "U", "u"]:
        scelta = input("Cosa vuoi fare? Scegli 1, 2, 3 o 4 (U per uscire): ")
    if scelta in ["U", "u"]:
        print("\nCiao " + callingUser + ", è stato un piacere fare affari con te ;)")
        termina()

    ##verifico presenza di un token valido (file INAD.tkn)
    tokenDisponibile = False
    while tokenDisponibile is False:
        if os.path.exists("INAD.tkn") is True:
            try:
                INADtoken = decifraDizionario("INAD.tkn", chiave)
                allora = datetime.datetime.strptime(INADtoken["creato"], "%a, %d %b %Y %H:%M:%S %Z")
                adesso = datetime.datetime.now()
                if int((adesso - allora).total_seconds()) < (durataToken-60):
                    token = INADtoken["token"]
                    print("Il token a disposizione è ancora valido.")
                    tokenDisponibile = True
            #except (cryptography.fernet.InvalidToken, TypeError):
            except:
                os.remove("INAD.tkn")
        else:
            print("Nessun token valido è disponibile. Ne ottengo uno.")
            privateKey = recuperaChiave("chiave.priv", chiave)
            client_assertion = create_m2m_client_assertion(INAD["kid"], INAD["alg"], INAD["typ"],
                INAD["iss"], INAD["sub"], INAD["aud"], privateKey, INAD["PurposeID"])
            token_response = token_request(INAD["iss"], client_assertion,
                INAD["Client_assertion_type"], INAD["Grant_type"])
            tokenDict = {}
            if token_response.status_code == 200:
                tokenDict["token"] = token_response.json()["access_token"]
                tokenDict["creato"] = token_response.headers["date"]
                cifraDizionario(tokenDict, chiave, "INAD.tkn")
                print("Ho creato il token (o voucher). Proseguiamo...")
                token = tokenDict["token"]
                tokenDisponibile = True
            else:
                print("Non sono riuscito a creare il token. Di seguito la risposta completa.")
                try:
                    print(token_response.content.decode())
                except:
                    print(token_response.content)
                termina()

#############################
######  ESTRAZIONE PUNTUALE #
#############################
    if scelta == "1":
        print("\n"+scelta + " - Estrazione puntuale\n")
        cf = chiediCF()
        ref = input("Inserisci un riferimento al procedimento amministrativo: ")
        estrazione = estrai(token, cf, ref)
        if estrazione.status_code == 200:
            try:
                print("Ecco il domicilio digitale di "+cf+": "+estrazione.json()["digitalAddress"][0]["digitalAddress"])
            except:
                print("L\'interazione è andata a buon fine, ma probabilmente il servizio è chiuso.")
            print("Di seguito la response completa:")
            try:
                print(estrazione.content.decode())
            except:
                print(estrazione.content)
        elif estrazione.status_code == 400:
            print("Richiesta mal formulata: " +estrazione.json()["detail"])
        elif estrazione.status_code == 401:
            print("Non autorizzato: " + estrazione.json()["detail"])
        elif estrazione.status_code == 403:
            print:("Operazione non consentita: " + estrazione.json()["detail"])
        elif estrazione.status_code == 404:
            print(estrazione.json()["status"] +" - " + estrazione.json()["detail"])
            print("Soggetto non trovato. Ragionevolmente, "+cf+" non è registrato su INAD")
            print("Di seguito il contenuto completo della risposta: ")
            print(estrazione.json())
        else:
            print("Qualcosa è andato storto, lo status code della risposta è: "+str(estrazione.status_code)+". Consulta le specifiche per maggiori informazioni")
            print("Di seguito il contenuto completo della risposta: ")
            try:
                print(estrazione.content.decode())
            except:
                print(estrazione.content)
#############################
######  VERIFICA PUNTUALE ###
#############################
    elif scelta == "2":
        print("\n"+scelta + " - Verifica puntuale\n")
        cf = chiediCF()
        mail = chiediMail()
        data = chiediData()
        ref = input("Inserisci un riferimento al procedimento amministrativo: ")
        verifica = verificaDomicilio(token, cf, ref, mail, data)
        if verifica.status_code == 200:
            try:
                if verifica.json()["outcome"] is True:
                    print("La verifica del domicilio digitale "+ mail +" per "+cf+" ha dato esito POSITIVO.")
                elif verifica.json()["outcome"] is False:
                    print("La verifica del domicilio digitale "+ mail +" per "+cf+" ha dato esito NEGATIVO.")
            except:
                print("L\'interazione è andata a buon fine, ma probabilmente il servizio è chiuso.")
            print("Di seguito la response completa:")
            try:
                print(verifica.content.decode())
            except:
                print(verifica.content)
        elif verifica.status_code == 400:
            print("Richiesta mal formulata: " +verifica.json()["detail"])
        elif verifica.status_code == 401:
            print("Non autorizzato: " + verifica.json()["detail"])
            print("Di seguito il contenuto completo della risposta: ")
            print(verifica.json())
        elif verifica.status_code == 403:
            print:("Operazione non consentita: " + verifica.json()["detail"])
            print("Di seguito il contenuto completo della risposta: ")
            print(verifica.json())
        elif verifica.status_code == 404:
            print(verifica.json()["status"] +" - " + verifica.json()["detail"])
            print("Quindi, l\'indirizzo PEC inserito non è domicilio digitale generale.")
            print("Di seguito il contenuto completo della risposta: ")
            print(verifica.json())
        else:
            print("Qualcosa è andato storto, lo status code della risposta è: "+str(verifica.status_code)+". Consulta le specifiche per maggiori informazioni")
            print("Di seguito il contenuto completo della risposta: ")
            try:
                print(verifica.content.decode())
            except:
                print(verifica.content)
#############################
######  ESTRAZIONE MASSIVA ##
#############################
    elif scelta == "3":
        print("\n"+scelta + " - Estrazione multipla\n")
        print("Per questa operazione hai bisogno di un file CSV, delimitato da ;, con una colonna che contiene i codici fiscali per i quali estrarre il domicilio.")
        print("Copialo nella cartella del programma, per tua facilità.\n")
        ref = input("Per iniziare, indica una breve descrizione del motivo della ricerca su INAD: ")
        # Individuo il file CSV con i dati in input
        nomeFileDati = input("Indica il nome del file CSV: ")
        fileDatiTrovato = False
        while fileDatiTrovato is False:
            if os.path.exists(nomeFileDati):
                fileDatiTrovato = True
                print("File trovato.")
            else:
                nomeFileDati = input(
                    "File "+ nomeFileDati + " non trovato. Verifica e inserisci di nuovo il nome del file CSV: "
                    )
        print("File CSV trovato.\n")
        # Inizializzo la cartella di lotto e i file di output e log
        data_lotto = timestamp()
        path=crea_cartella(ref, data_lotto) # crea la cartella di lavoro del lotto
        lottoLog=path + data_lotto + "-" + "lotto.log"
        ricevutaJson = path + data_lotto + "-ricevuta.json"
        statoJson = path + data_lotto + "-stato.json"
        domiciliJson = path + data_lotto + "-domiciliDigitali.json"
        lottoJson=path + data_lotto + "-" + "Lotto.json"
        lottoElaboratoJson = path + data_lotto + "-" + "LottoElaborato.json"
        requestsLog = path + data_lotto + "-" + "Requests.log"
        fh = logging.FileHandler(requestsLog)
        log.addHandler(fh)
        outputCSV = path + "elaborato-"+nomeFileDati
        # Definisco un paio di funzioni per creare il log di lotto con eventuali messaggio a video
        def logga(stringa):
            '''Scrive una stringa nel log di lotto'''
            with open(lottoLog, "a+") as fileLog:
                rigaDiLog=[timestamp(),stringa]
                fileLog.write(";".join(rigaDiLog))
                fileLog.write("\n")
                fileLog.flush()
        def stampa(stringa):
            '''Scrive una stringa a schermo e nel log di lotto'''
            print(stringa)
            with open(lottoLog, "a+") as fileLog:
                rigaDiLog=[timestamp(),stringa]
                fileLog.write(";".join(rigaDiLog))
                fileLog.write("\n")
                fileLog.flush()
        logga("Ciao " + os.getlogin() + "!") #apre il lotto di log salutando l'utente
        stampa("Ho creato la cartella di lotto: "+path)
        logga("Data della richiesta: "+data_lotto)
        logga("Motivo della richiesta: "+ref)
        ## Estraggo il file CSV e creo un array di dizionari e un file json nella cartella di lotto
        with open(nomeFileDati, "r") as inputFile:
            reader = csv.DictReader(inputFile, delimiter=";")
            lotto = []
            for i in reader:
                lotto.append(i)
        with open(lottoJson, "w+") as file:
            file.write(json.dumps(lotto, sort_keys=False, indent=4))
        ## Definisco la colonna che contiene il codice fiscale
        print("\nIl CSV importato ha le seguenti chiavi:")
        chiaviCSV = list(lotto[0].keys())
        for i in chiaviCSV:
            print(i)
        print("\n")
        chiaveCF = input("Indicare la chiave che contiene il codice fiscale: ")
        while not chiaveCF in chiaviCSV:
            chiaveCF = input("Indicare la chiave che contiene il codice fiscale: ")
        ## Estraggo lista di codici fiscali per INAD
        listaCF = []
        for i in lotto:
            listaCF.append(i[chiaveCF])
        stampa("Ho estratto la lista di codici fiscali per cui richiedere il domicilio digitale.")
        # Carico la lista su INAD e definisco intervallo di polling
        stampa("Carico la lista su INAD.")
        invio = caricaLista(token, listaCF, ref)
        L = len(listaCF)
        #pausa = 120 + 2 * L
        pausa = 320  #usato in attesa di capire quale sia l'intervallo corretto 
        if invio.status_code == 202:
            with open(ricevutaJson, "w") as file:
                ricevuta = invio.json()
                ricevuta["nomeFileDati"] = nomeFileDati
                ricevuta["cartellaDiLavoro"] = path
                ricevuta["data_lotto"] = data_lotto
                ricevuta["chiaveCF"] = chiaveCF
                file.write(json.dumps(ricevuta,sort_keys=False, indent=4))
            stampa("Lista dei file inviata correttamente. Attendo " + str(pausa) + " secondi per verificare lo stato della richiesta.")
            stampa("Ho salvato la ricevuta della richiesta nella cartella di lotto.")
            stampa("Puoi interrompere l'esecuzione del programma (CTRL+C) e recuperare i risultati in seguito.")
        else:
            stampa("Qualcosa è andato storto. Puoi controllare i log nella cartella di lotto.")
            stampa("Di seguito la risposta completa.")
            stampa(str(invio.content.decode()))
            termina()
        # Attendo il tempo T = pausa
        time.sleep(pausa)
        # Recupero lo stato dell'elaborazione della lista
        idLista = ricevuta["id"]
        listaPronta = False
        while listaPronta is False:
            verifica = statoLista(token, idLista)
            if verifica.status_code == 303: ## poi sarà 303:
                listaPronta = True
                stampa("La richiesta è stata elaborata da INAD. Procedo a prelevarla.")
                with open(statoJson, "w") as file:
                    file.write(json.dumps(verifica.json(), sort_keys=False, indent=4))
            elif verifica.status_code == 200:
                try:
                    with open(statoJson, "w") as file:
                        file.write(json.dumps(verifica.json(), sort_keys=False, indent=4))
                    stampa("La richiesta è ancora in elaborazione. Attendo "+str(pausa)+" secondi per verificare nuovamente. ")
                    stampa("Puoi interrompere il programma con CTRL+C e verificare in seguito lo stato di elaborazione con recuperaLista.py.")
                    time.sleep(pausa)
                except:
                    stampa("Probabilmente il server di INAD sta riposando.")
                    stampa("Interrompo l'esecuzione del programma. Puoi recuperare i risultati dell'estrazione in seguito con lo script recuperaLista.py.")
                    termina()
            else:
                stampa("Qualcosa non funziona. Magari è scaduto il token. Termino il programma. Esegui la verifica più tardi con recuperaLista.py.")
                with open(statoJson, "w") as file:
                    file.write(json.dumps(verifica.json(), sort_keys=False, indent=4))
                termina()
        # Quando la lista è pronta, recupero i domicili e li salvo in domiciliDigitali.json
        domicili = prelevaLista(token, idLista)
        if domicili.status_code == 200:
            try:
                with open(domiciliJson, "w") as file:
                    file.write(json.dumps(domicili.json(), sort_keys=False, indent = 4))
                    stampa("Ho recuperato la lista dei domicili digitali.")
                    stampa("La trovi nel file " + domiciliJson + " nella cartella di lavoro.")
                    listaDomicili = domicili.json()["list"]
            except:
                stampa("Probabilmente il server di INAD sta riposando.")
                stampa("Interrompo l'esecuzione del programma. Puoi recuperare i risultati dell'estrazione in seguito con lo script recuperaLista.py.")
                termina()
        else:
            stampa("Qualcosa è andato storto. Ti invito a guardare i file di log e riprovare più tardi con recuperaLista.py.")
            termina()
        ## Creo un nuovo array di dizionari a partire dall'array lotto e nuovo csv con colonne aggiuntive per il codice fiscale e la professione eventuale.
        lottoElaborato = []
        for soggetto in lotto:
            dizio = {}
            dizio.update(soggetto)
            valoreCF = soggetto[chiaveCF]
            for risultato in listaDomicili:
                if risultato["codiceFiscale"] == valoreCF:
                    if "digitalAddress" in risultato:
                        for address in risultato["digitalAddress"]:
                            indice = risultato["digitalAddress"].index(address)
                            suffisso = ("" if indice == 0 else str(indice+1))
                            dizio.update({"domicilioDigitale"+suffisso : address["digitalAddress"]})
                            if "practicedProfession" in address:
                                dizio.update({"professione"+suffisso : address["practicedProfession"]})
                    break
            lottoElaborato.append(dizio)
        N = 0
        for i in lottoElaborato:
            l=len(i)
            if l > N:
                posiz = lottoElaborato.index(i) # la posizione dell'elemento
            N = max(N,l)
        fieldnames = list(lottoElaborato[posiz].keys())
        with open(outputCSV, "w") as outputfile:
            writer = csv.DictWriter(outputfile, fieldnames=fieldnames, delimiter = ";", lineterminator="\n")
            outputfile.write(";".join(fieldnames))
            outputfile.write("\n")
            writer.writerows(lottoElaborato)
        stampa("Io avrei finito. Il file "+outputCSV+ " è il file CSV che hai caricato con una colonna aggiuntiva per i domicili digitali trovati.")
        stampa("Se qualche soggetto ha più di un domicilio registrato e/o ha indicato una professione, nel CSV creato trovi ulteriori colonne.")

#############################
######  RECUPERO LISTA ######
#############################
    elif scelta == "4":
        print(scelta + " - Recupero risultati di precedente interrogazione multipla.")
        print("Hai bisogno di una ricevuta in formato json di un precedente invio.")
        print("Ti conviene copiarla dalla cartella di lotto alla cartella di questo programma e rinominarla.")
        nomeFileRicevuta = input("Inserisci il nome del file con la ricevuta: ")
        ricevutaTrovata = False
        while ricevutaTrovata is False:
            try:
                with open(nomeFileRicevuta, "rb") as file:
                    datiLotto = json.load(file)
                    nomeFileDati = datiLotto["nomeFileDati"]
                    path = datiLotto["cartellaDiLavoro"]
                    idLista = datiLotto["id"]
                    data_lotto = datiLotto["data_lotto"]
                    chiaveCF = datiLotto["chiaveCF"]
                    ricevutaTrovata = True
            except:
                nomeFileRicevuta = input(
                    "File "+ nomeFileRicevuta + " non trovato. Verifica e inserisci di nuovo il nome del file CSV: "
                    )
        print("File della ricevuta trovato.")
        ## Inizializzazione di cartella di lotto, file di output e logging
        lottoLog=path + data_lotto + "-" + "lotto.log"
        ricevutaJson = path + data_lotto + "-ricevuta.json"
        statoJson = path + data_lotto + "-stato.json"
        domiciliJson = path + data_lotto + "-domiciliDigitali.json"
        lottoJson=path + data_lotto + "-" + "Lotto.json"
        lottoElaboratoJson = path + data_lotto + "-" + "LottoElaborato.json"
        requestsLog = path + data_lotto + "-" + "Requests.log"
        fh = logging.FileHandler(requestsLog)
        log.addHandler(fh)
        outputCSV = path + "elaborato-"+nomeFileDati
        # Definisco un paio di funzioni per creare il log di lotto con eventuali messaggio a video
        def logga(stringa):
            '''Scrive una stringa nel log di lotto'''
            with open(lottoLog, "a+") as fileLog:
                rigaDiLog=[timestamp(),stringa]
                fileLog.write(";".join(rigaDiLog))
                fileLog.write("\n")
                fileLog.flush()
        def stampa(stringa):
            '''Scrive una stringa a schermo e nel log di lotto'''
            print(stringa)
            with open(lottoLog, "a+") as fileLog:
                rigaDiLog=[timestamp(),stringa]
                fileLog.write(";".join(rigaDiLog))
                fileLog.write("\n")
                fileLog.flush()
        # Leggo i dati di lotto dal file json
        with open(lottoJson, "r") as file:
            lotto = json.load(file)
        listaCF = []
        for i in lotto:
            listaCF.append(i[chiaveCF])
        L = len(listaCF)
        #pausa = 120 + 2 * L
        pausa = 320  #in attesa di capire come definirla in funzione di L
        stampa("Informazioni dal file "+nomeFileRicevuta +" importate.")
        stampa("Inizio il recupero della richiesta con id: "+idLista +".")
        # Verifico lo stato di elaborazione della lista
        # Recupero lo stato dell'elaborazione della lista
        listaPronta = False
        while listaPronta is False:
            verifica = statoLista(token, idLista)
            if verifica.status_code == 303:
                listaPronta = True
                stampa("La richiesta è stata elaborata da INAD. Procedo a prelevarla.")
                with open(statoJson, "w") as file:
                    file.write(json.dumps(verifica.json(), sort_keys=False, indent=4))
            elif verifica.status_code == 200:
                try:
                    with open(statoJson, "w") as file:
                        file.write(json.dumps(verifica.json(), sort_keys=False, indent=4))
                    stampa("La richiesta è ancora in elaborazione. Attendo "+str(pausa)+" secondi per verificare nuovamente.")
                    stampa("Puoi interrompere il programma con CRTL+C e recuperare i risultati in un secondo momento.")
                    time.sleep(pausa)
                except:
                    stampa("Probabilmente il server di INAD sta riposando.")
                    stampa("Di seguito la risposta completa.")
                    stampa(str(verifica.content.decode()))
                    stampa("Interrompo l'esecuzione del programma. Puoi recuperare i risultati dell'estrazione in seguito.")
                    termina()
            else:
                stampa("Qualcosa non funziona. Magari è scaduto il token. Termino il programma. Puoi recuprare i risultati dell'estrazione in seguito.")
                with open(statoJson, "w") as file:
                    file.write(json.dumps(verifica.json(), sort_keys=False, indent=4))
                termina()
        # Quando la lista è pronta, recupero i domicili e li salvo in domiciliDigitali.json
        domicili = prelevaLista(token, idLista)
        if domicili.status_code == 200:
            try:
                with open(domiciliJson, "w") as file:
                    file.write(json.dumps(domicili.json(), sort_keys=False, indent = 4))
                    stampa("Ho recuperato la lista dei domicili digitali.")
                    stampa("La trovi nel file " + domiciliJson + " nella cartella di lavoro.")
                    listaDomicili = domicili.json()["list"]
            except:
                stampa("Probabilmente il server di INAD sta riposando.")
                stampa("Di seguito la risposta completa.")
                stampa(str(domicili.content.decode()))
                stampa("Interrompo l'esecuzione del programma. Puoi recuperare i risultati dell'estrazione in seguito.")
                termina()
        else:
            stampa("Qualcosa è andato storto. Puoi recuperare i risultati più tardi.")
            stampa("Di seguito la risposta completa.")
            stampa(str(domicili.content.decode()))
            stampa("Interrompo l'esecuzione del programma. Puoi recuperare i risultati dell'estrazione in seguito.")
            termina()
        ## Creo un nuovo array di dizionari a partire dall'array lotto e nuovo csv con colonne aggiuntive per il codice fiscale e la professione eventuale.
        lottoElaborato = []
        for soggetto in lotto:
            dizio = {}
            dizio.update(soggetto)
            valoreCF = soggetto[chiaveCF]
            for risultato in listaDomicili:
                if risultato["codiceFiscale"] == valoreCF:
                    if "digitalAddress" in risultato:
                        for address in risultato["digitalAddress"]:
                            indice = risultato["digitalAddress"].index(address)
                            suffisso = ("" if indice == 0 else str(indice+1))
                            dizio.update({"domicilioDigitale"+suffisso : address["digitalAddress"]})
                            if "practicedProfession" in address:
                                dizio.update({"professione"+suffisso : address["practicedProfession"]})
                    break
            lottoElaborato.append(dizio)
        N = 0
        for i in lottoElaborato:
            l=len(i)
            if l > N:
                posiz = lottoElaborato.index(i) # la posizione dell'elemento
            N = max(N,l)
        fieldnames = list(lottoElaborato[posiz].keys())
        with open(outputCSV, "w") as outputfile:
            writer = csv.DictWriter(outputfile, fieldnames=fieldnames, delimiter = ";", lineterminator="\n")
            outputfile.write(";".join(fieldnames))
            outputfile.write("\n")
            writer.writerows(lottoElaborato)
        stampa("Io avrei finito. Il file "+outputCSV+ " è il file CSV che hai caricato con una colonna aggiuntiva per i domicili digitali trovati.")
        stampa("Se qualche soggetto ha più di un domicilio registrato e/o ha indicato una professione, nel CSV creato trovi ulteriori colonne.")

#############################
####  USCITA DAL PROGRAMMA ##
#############################
    else:
        print("Ciao " + callingUser + ", è stato un piacere fare affari con te ;)")
        termina()

# Chiedo se si ha intenzione di continuare
    risposta = input("Vuoi fare altre operazioni su INAD [S = sì / N = no]? ")
    while risposta not in ["S", "sì", "s", "Sì", "N", "no", "NO", "n"]:
        risposta = input("Non ho capito. Vuoi fare altre operazioni su INAD [S = sì / N = no]? ")
    if risposta in ["N", "no", "NO", "n"]:
        continuare = False
# Quando è tutto finito, termina
termina()
