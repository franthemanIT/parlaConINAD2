'''Script per l'interrogazione di INAD (Indice Nazionale dei Domicili Digitali) tramite API.
Per l'autenticazione si fa riferimento alla PDND (Piattaforma Digitale Nazionale Dati),
secondo il ModI.'''
## Autore: Francesco Del Castillo (2023)
import datetime
import time
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
import pwinput
import pyinputplus as pyip

##URL E AUDIENCE

#BASE_URL_AUTH = "https://auth.uat.interop.pagopa.it/token.oauth2" #Ambiente PDND di collaudo
#BASE_URL_INAD = "https://domiciliodigitaleapi.oscl.infocamere.it/rest/inad/v1/domiciliodigitale"
#AUD_INTEROP = "auth.uat.interop.pagopa.it/client-assertion"
#DURATA_TOKEN = 86400 #3600 in produzione, 86400 in collaudo (in secondi)

BASE_URL_AUTH = "https://auth.interop.pagopa.it/token.oauth2" #Ambiente PDND di produzione
BASE_URL_INAD = "https://api.inad.gov.it/rest/inad/v1/domiciliodigitale"
AUD_INTEROP = "auth.interop.pagopa.it/client-assertion"
DURATA_TOKEN = 3600 #3600 in produzione, 86400 in collaudo (in secondi)

#nome del file di log generale
LOG_FILE_NAME="INAD.log"

#Regole per il logging delle chiamate requests (si loggano solo le chiamate per estrazioni massive)
#logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger("urllib3")
log.setLevel(logging.DEBUG)

## Funzioni e variabili globali che servono per l'interazione con l'utente
def get_ip_address():
    '''Recupera e restituisce l'indirizzo IP dell'utente'''
    return socket.gethostbyname(socket.gethostname())

CALLING_IP = get_ip_address()
CALLING_USER = os.getlogin()

def timestamp():
    '''Restituisce il timestamp attuale in formato %Y%m%d-%H%M%S-%f'''
    return datetime.datetime.now().strftime("%Y%m%d-%H%M%S-%f")

def timestamp_breve():
    '''Restituisce il timestamp attuale in formato %Y%m%d-%H%M%S'''
    return datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    
def attendi():
    '''Richiede un'interazione dell'utente per proseguire'''
    input("Premi INVIO/ENTER per proseguire.")

def termina():
    '''Richiede un'interazione dell'utente per terminare il programma
    Utile anche a fine srpt per evitare di perdere quanto scritto a video'''
    input("Premi INVIO/ENTER per terminare.")
    sys.exit()

RE_CF = "^([0-9]{11})|([A-Za-z]{6}[0-9]{2}[A-Za-z]{1}[0-9]{2}[A-Za-z]{1}[0-9]{3}[A-Za-z]{1})$"
RE_MAIL = "^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"

def chiedi_cf():
    '''Chiede di inserire un codice fiscale / partita IVA e valida il formato.'''
    ottieni_cf = False
    while ottieni_cf is False:
        x = input("Inserisci il codice fiscale per cui verificare il domicilio digitale: ")
        if re.match(RE_CF, x):
            ottieni_cf = True
        else:
            print("Codice fiscale non valido.")
    return x

def chiedi_mail():
    '''Chiede di inserire un indirizzo e-mail e valida il formato.'''
    ottieni_mail = False
    while ottieni_mail is False:
        x = input("Inserisci l\'indirizzo PEC da verificare: ")
        if re.match(RE_MAIL, x):
            ottieni_mail = True
        else:
            print("Formato indirizzo PEC non valido.")
    return x

def chiedi_data():
    '''Chiede di inserire una data G/M/A o G-M-A
    e la restituisce AAAA-MM-GG'''
    x = pyip.inputDate(prompt = "Inserisci la data alla quale verificare: ",
        formats=["%d/%m/%y", "%d/%m/%Y", "%d-%m-%y", "%d-%m-%Y"])
    y = x.strftime("%Y-%m-%d")
    return y

## Funzioni che servono per la manipolazione di file di input e output
def crea_cartella(descrizione, data_e_ora=timestamp_breve()):
    '''Crea una sottocartella nella cartella di esecuzione dello script
    Se l'argomento data_e_ora è nullo, usa un timestamp breve al suo posto.'''
    path="./lotti/" + data_e_ora + "-" + descrizione + "/"
    if not os.path.isdir(path):
        os.mkdir(path)
    return path

def salva_dizionario(dizionario, file_out):
    '''Salva un dizionario in un file JSON'''
    with open(file_out, "w+") as file:
        file.write(json.dumps(dizionario, sort_keys=False, indent=4))

## Funzioni che servono per il logging
def log_request(log_file, request_time, verbo, metodo, info):
    '''Aggiunge una riga al file log_file, con gli argomenti divisi da un ;
    Si usa per annotare nel log le request di requests'''
    riga_di_log=[request_time, CALLING_IP, CALLING_USER, verbo, metodo, info]
    log_file.write(";".join(riga_di_log))
    log_file.write("\n")
    log_file.flush()

def log_response(log_file, response_time, request_time, status_code, info):
    '''Aggiunge una riga al file log_file, con gli argomenti divisi da un ;
    Si usa per annotare nel log le request di requests'''
    riga_di_log=[response_time, CALLING_IP, request_time, str(status_code), info]
    log_file.write(";".join(riga_di_log))
    log_file.write("\n")
    log_file.flush()

def logga(stringa, file_di_log = None):
    '''Scrive una stringa nel log di lotto'''
    file_di_log = file_di_log or LOTTO_LOG
    with open(file_di_log, "a+") as file:
        riga_di_log=[timestamp(),stringa]
        file.write(";".join(riga_di_log))
        file.write("\n")
        file.flush()

def stampa(stringa, file_di_log = None):
    '''Scrive una stringa a schermo e nel log di lotto'''
    file_di_log = file_di_log or LOTTO_LOG
    print(stringa)
    with open(file_di_log, "a+") as file:
        riga_di_log=[timestamp(),stringa]
        file.write(";".join(riga_di_log))
        file.write("\n")
        file.flush()

def clear():
    '''Cancella la schermo'''
    os.system("cls" if os.name == "nt" else "clear")

## Funzioni crittografiche
def cifra_stringa(stringa, chiave):
    '''Cifra una stringa con la chiave indicata'''
    fernet = Fernet(chiave)
    fernet.encrypt(stringa.encode())

def decifra_stringa(stringa, chiave):
    '''Decifra una stringa cifrata tramite la chiave indicata'''
    fernet = Fernet(chiave)
    fernet.decrypt(stringa).decode()

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

def decifra_file(file_da_decifrare, chiave, output_file = ""):
    '''Decifra un file in un altro file'''
    if output_file == "":
        output_file = file_da_decifrare
    with open(file_da_decifrare, "rb") as f:
        cifrato = f.read()
    fernet = Fernet(chiave)
    originale = fernet.decrypt(cifrato)
    with open(output_file, "wb") as f:
        f.write(originale)

def ricifra_file(file_da_ricifrare, chiave1, chiave2, output_file):
    '''Decifra un file cifrato con chiave 1 o la cifra con chiave2'''
    with open(file_da_ricifrare, "rb") as f:
        cifrato = f.read()
        fernet = Fernet(chiave1)
        in_chiaro = fernet.decrypt(cifrato)
        fernet = Fernet(chiave2)
        ricifrato = fernet.encrypt(in_chiaro)
    with open(output_file, "wb") as f:
        f.write(ricifrato)
        
def recupera_chiave(file_cifrato, chiave):
    '''Recupera la chiave privata da un file cifrato con cifraChiave.
    In realtà decifra qualsiasi file cifrato e lo restituisce come risultato.'''
    with open(file_cifrato, "rb") as f:
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

def ottieni_chiave(stringa):
    '''Ottiene la chiave crittografica a partire da una stringa'''
    x = base64.urlsafe_b64encode(kdf().derive(stringa))
    return x

def imposta_password():
    '''Chiede all'utente di impostare una password sicura
    e restituisce la chiave crittografica derivata'''
    RE_PASSWORD = "^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!#$%&?].*)(?=.*[\W]).{8,20}$"
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
    issued = datetime.datetime.now()
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
    body = {
        "client_id" : client_id,
        "client_assertion" : client_assertion,
        "client_assertion_type" : client_assertion_type,
        "grant_type" : grant_type
    }
    headers = {"Content-Type" : "application/x-www-form-urlencoded"}
    with open(LOG_FILE_NAME, "a+") as log_file:
        request_time=timestamp()
        log_request(log_file, request_time, "POST", "token_request", client_id)
        r = requests.post(BASE_URL_AUTH, headers = headers, timeout=100, data=body)
        response_time=timestamp()
        info = str(r.status_code)
        log_response(log_file, response_time, request_time, r.status_code, info)
    return r

## Funzioni per l'interazione con INAD (autoesplicative)
def estrai_domicilio(token, cf, ref):
    '''Interroga INAD per estrarre un domicilio digitale a partire dal codice fiscale cf
    ref è il practicalReference cioè il riferimento al procedimento amministrativo
    per il quale si richiede l'estrazione'''
    url = BASE_URL_INAD+"/extract/"+cf
    headers = {"Authorization": "Bearer "+token}
    #parameters = {"codice_fiscale" : cf, "practicalReference" : ref}
    parametri = {"practicalReference" : ref}
    with open(LOG_FILE_NAME, "a+") as log_file:
        request_time=timestamp()
        log_request(
            log_file, request_time, "GET", "estrai", "richiesto domicilio digitale per "+cf[:2]+"***"
            )
        r = requests.get(url, headers = headers, params = parametri, timeout=100)
        response_time=timestamp()
        info = str(r.status_code)
        log_response(log_file, response_time, request_time, r.status_code, info)
    return r

def verifica_domicilio(token, cf, ref, mail, data):
    '''Verifica la validità di un domicilio digitale per un certo codice fiscale a una certa data
    ref è il practicalReference cioè il riferimento al procedimento amministrativo 
    per il quale si richiede l'estrazione'''
    url = BASE_URL_INAD+"/verify/"+cf
    headers = {"Authorization": "Bearer "+token}
    parametri = {"practicalReference" : ref, "digital_address" : mail, "since" : data}
    #parametri = {"practicalReference" : ref, "since" : data} #parametri incompleti per test
    with open(LOG_FILE_NAME, "a+") as log_file:
        request_time=timestamp()
        log_request(
            log_file, request_time, "GET", "verifica",
            "richiesta verifica del domicilio digitale "+mail[:3]+"***"
            )
        r = requests.get(url, headers = headers, params = parametri, timeout=100)
        response_time=timestamp()
        info = str(r.status_code)
        log_response(log_file, response_time, request_time, r.status_code, info)
    return r

def carica_lista(token, lista, ref):
    '''Invia a INAD una lista di codici fiscali di cui ottenere il domicilio digitale'''
    url = BASE_URL_INAD+"/listDigitalAddress"
    headers = {"Authorization": "Bearer "+token}
    payload = {
                "codiciFiscali" : lista,
                "practicalReference" : ref
              }
    with open(LOG_FILE_NAME, "a+") as log_file:
        request_time=timestamp()
        log_request(
            log_file, request_time, "POST", "carica lista di CF",
            "richiesta verifica massiva per "+ref
            )
        r = requests.post(url, headers = headers, json = payload, timeout=100)
        response_time=timestamp()
        info = str(r.status_code)
        log_response(log_file, response_time, request_time, r.status_code, info)
    return r

def stato_lista(token, id_lista):
    '''Interroga INAD sullo stato di elaborazione di una lista precedentemente inviata''' 
    url = BASE_URL_INAD+"/listDigitalAddress/state/"+id_lista
    headers = {"Authorization": "Bearer "+token}
    with open(LOG_FILE_NAME, "a+") as log_file:
        request_time=timestamp()
        log_request(
            log_file, request_time, "GET", "verifica stato lista",
            "richiesta verifica stato per lista id "+id_lista
            )
        r = requests.get(url, headers = headers, timeout=100, allow_redirects = False)
        response_time=timestamp()
        info = str(r.status_code)
        log_response(log_file, response_time, request_time, r.status_code, info)
    return r
 
def preleva_lista(token, id_lista):
    '''Recupera da INAD una lista di codici fiscali 
    per i quali sono stati elaborati i domicili digitali'''
    url = BASE_URL_INAD+"/listDigitalAddress/response/"+id_lista
    headers = {"Authorization": "Bearer "+token}
    with open(LOG_FILE_NAME, "a+") as log_file:
        request_time=timestamp()
        log_request(
            log_file, request_time, "GET", "verifica stato lista",
            "richiesta verifica stato per lista id "+id_lista
            )
        r = requests.get(url, headers = headers, timeout=100)
        response_time=timestamp()
        info = str(r.status_code)
        log_response(log_file, response_time, request_time, r.status_code, info)
    return r


## Funzioni per l'elaborazione delle estrazioni di INAD

def verifica_stato_lista(token, id_lista, output_json, pausa): #verifica = verifica_stato_lista(token, id_lista, STATO_JSON, PAUSA)
    '''Interroga circa lo stato di elaborazione di una lista di domicili da estrarre.
    Restituisce la response della chiamata.
    In caso di response che non consente di proseguire nel programma, lo termina.'''
    LISTA_PRONTA = False
    while LISTA_PRONTA is False:
        verify = stato_lista(token, id_lista)
        if verify.status_code == 303:
            LISTA_PRONTA = True
            stampa("La richiesta è stata elaborata da INAD. Procedo a prelevarla.")
            salva_dizionario(verify.json(), output_json)
        elif verify.status_code == 200:
            try:
                salva_dizionario(verify.json(), output_json)
                stampa("La richiesta è ancora in elaborazione.\n"
                       "\nAttendo "+str(pausa)+" secondi per verificare nuovamente. ")
                stampa("Puoi interrompere il programma con CTRL+C e verificare "\
                       "in seguito lo stato di elaborazione.")
                time.sleep(pausa)
            except:
                stampa("Probabilmente il server di INAD sta riposando.")
                stampa("Interrompo l'esecuzione del programma. Puoi recuperare "\
                       "i risultati dell'estrazione in seguito.")
                termina()
        elif verify.status_code in [400, 401, 403, 404, 500, 503]:
            stampa("Il server ha risposto: " + str(verify.status_code) +".")
            for i in verify.json():
                stampa(i +": " +str(verify.json()[i]))
            stampa("Termino il programma. Tu cerca di capire cosa non va ;)")
            termina()
        else:
            stampa("Qualcosa non funziona. Magari è scaduto il token o chissà. "\
                   "Termino il programma. Esegui la verifica più tardi.")
            salva_dizionario(verify.json(), output_json)
            termina()
    return verify

def salva_lista_domicili(token, id_lista, file_out):
    '''Recupera l'elaborazione massiva, la salva in un file e restitiusce un dizionario'''
    dizionario = preleva_lista(token, id_lista)
    if dizionario.status_code == 200:
        try:
            salva_dizionario(dizionario.json(), file_out)
            stampa("Ho recuperato la lista dei domicili digitali.")
            stampa("La trovi nel file " + file_out + " nella cartella di lavoro.")
            dizionario_out = dizionario.json()["list"]
            return dizionario_out
        except:
            stampa("Probabilmente il server di INAD sta riposando.")
            stampa("Interrompo l'esecuzione del programma. Puoi recuperare i risultati "\
                   "dell'estrazione in seguito.")
            stampa(dizionario.content)
            termina()
    else:
        stampa("Qualcosa è andato storto. Ti invito a guardare i file di log "\
               "e riprovare più tardi.")
    
def elabora_lotto(dizionario_in, dizionario_join, colonna_join, file_out, csv_out):
    '''Unisce e restituisce il dizionario di lotto e il dizionario dei domicili estratti
    in un nuovo dizionario e crea un file CSV'''
    dizionario_out = []
    for soggetto in dizionario_in:
        dizio = {}
        dizio.update(soggetto)
        valore_cf = soggetto[colonna_join]
        for risultato in dizionario_join:
            if risultato["codiceFiscale"] == valore_cf:
                if "digitalAddress" in risultato:
                    for address in risultato["digitalAddress"]:
                        indice = risultato["digitalAddress"].index(address)
                        suffisso = ("" if indice == 0 else str(indice+1))
                        dizio.update({"domicilioDigitale"+suffisso : address["digitalAddress"]})
                        if "practicedProfession" in address:
                            dizio.update({"professione"+suffisso : address["practicedProfession"]})
                break
        dizionario_out.append(dizio)
    salva_dizionario(dizionario_out, file_out)
    N = 0
    for i in dizionario_out:
        l=len(i)
        if l > N:
            posiz = dizionario_out.index(i) # la posizione dell'elemento
        N = max(N,l)
    fieldnames = list(dizionario_out[posiz].keys())
    with open(csv_out, "w") as outputfile:
        writer = csv.DictWriter(outputfile, fieldnames=fieldnames, delimiter = ";", lineterminator="\n")
        outputfile.write(";".join(fieldnames))
        outputfile.write("\n")
        writer.writerows(dizionario_out)
    stampa("Io avrei finito. Il file " + csv_out + " è il file CSV "\
           "che hai caricato con una colonna aggiuntiva per i domicili digitali trovati.")
    stampa("Se qualche soggetto ha più di un domicilio registrato "\
           "e/o ha indicato una professione, nel CSV creato trovi ulteriori colonne.")
    return dizionario_out
    
#####################################
###INIZIO DELLO SCRIPT INTERATTIVO###
#####################################

#####################################
### INSTALLAZIONE AL PRIMO AVVIO ####
#####################################
print("Benvenuto "+CALLING_USER+".")
if os.path.exists("lotti/") is False:
    os.mkdir("./lotti/")
if os.path.exists("INAD.cfg") is False:
    CONFIGURATO = False
    print("Il programma non è configurato.")
    print("Ti chiederò di: ")
    print("- scegliere una password")
    print("- inserire i dati di configurazione del client e-service PDND di INAD;")
    print("- indicare il nome del file della chiave privata.")
    chiave = imposta_password()
    print("Password impostata. \nAnnotala in un luogo segreto e sicuro: "\
          "NON potrai recuperarla in alcun modo.")
    if (os.path.exists("INAD.master.cfg") and os.path.exists("chiave.master.priv")) is True:
        print("Scegli: ")
        tipo_configurazione = pyip.inputMenu(["Configurazione manuale", "Configurazione da file master"],\
                                             numbered = True)
        if  tipo_configurazione == "Configurazione manuale":
            pass   
        else:
            print("\nHai bisogno della password master.\n")
            passwM = pwinput.pwinput(prompt = "Inserici la password dei file master: ")
            passwordM = passwM.encode()
            CHIAVEM = base64.urlsafe_b64encode(kdf().derive(passwordM))
            passwM = ""
            passwordM = b""
            PASSWORDM_CORRETTA = False
            while PASSWORDM_CORRETTA is False:
                try:
                    ricifra_file("INAD.master.cfg", CHIAVEM, chiave, "INAD.cfg")
                    print("Configurazione di INAD importata.")
                    PASSWORDM_CORRETTA = True
                except:
                        print("La password NON è corretta.")
                        passwM = pwinput.pwinput()
                        passwordM = passwM.encode()
                        CHIAVEM = base64.urlsafe_b64encode(kdf().derive(passwordM))
                        passwM = ""
                        passwordM = b""
            ricifra_file("chiave.master.priv", CHIAVEM, chiave, "chiave.priv")
            CHIAVEM = ""
            CONFIGURATO = True
    if CONFIGURATO is False:
        print("Configuriamo i dati del client e-service di INAD. Li trovi nel back-office della PDND.")
        #seguono i parametri che servono per contattare il client e-service INAD su PDND.
        #I predefiniti si possono modificare o sostituire con "" per inserirli interattivamente.
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
        lista = []
        for i in INAD:
            if INAD[i] == "":
                lista.append(i)
        for i in lista:
            value = input(i+": ")
            INAD[i] = value
        cifra_dizionario(INAD, chiave, "INAD.cfg")
        print("Dati del client e-service configurati.")
        print("Configuriamo la chiave privata.")
        print("Ti conviene copiare il file con la chiave privata nella cartella del programma.")
        nome_file_chiave = input("Nome del file della chiave privata (es.: key.priv): ")
        CHIAVE_TROVATA = False
        while CHIAVE_TROVATA is False:
            if os.path.exists(nome_file_chiave):
                CHIAVE_TROVATA = True
                print("File trovato.")
                cifra_file(nome_file_chiave, chiave, "chiave.priv")
                print("Ho configurato la chiave in un file cifrato. "\
                      "Cancella il file " + nome_file_chiave + " dalla cartella del programma.")
            else:
                nome_file_chiave = input(
                    "File "+ nome_file_chiave + "non trovato. Verifica e "\
                    "inserisci di nuovo il nome del file della chiave privata: "
                    )
        print("La configurazione è terminata. \n"\
              "Ricorda la password per avviare i programmi di interazione con INAD.")
elif os.path.exists("chiave.priv") is False:
    print("IL programma è configurato a metà. Manca la chiave privata "\
          "da usare per il service e-client INAD.")
    print("Ti chiederò di inserire la password precedentemente scelta.")
    print("Se non la ricordi, cancella il file \'INAD.cfg\' "\
          "dalla cartella del programma e avvia di nuovo l'installazione.")
    passw = pwinput.pwinput()
    password = passw.encode()
    chiave = base64.urlsafe_b64encode(kdf().derive(password))
    passw = ""
    password = b""
    PASSWORD_CORRETTA = False
    while PASSWORD_CORRETTA is False:
        with open("INAD.cfg", "r") as f:
            try:
                INAD = decifra_dizionario("INAD.cfg", chiave)
                print("La password è corretta.")
                PASSWORD_CORRETTA = True
            except:
                print("La password NON è corretta.")
                passw = pwinput.pwinput()
                password = passw.encode()
                chiave = base64.urlsafe_b64encode(kdf().derive(password))
                passw = ""
                password = b""
    print("Copia il file con la chiave privata associata "\
          "al client e-service INAD nella cartella del programma.")
    nome_file_chiave = input("Nome del file della chiave privata (es.: key.priv): ")
    CHIAVE_TROVATA = False
    while CHIAVE_TROVATA is False:
        if os.path.exists(nome_file_chiave):
            CHIAVE_TROVATA = True
            print("File trovato.")
            cifra_file(nome_file_chiave, chiave, "chiave.priv")
            print("Ho configurato la chiave in un file cifrato. "\
                  "Cancella il file " + nome_file_chiave + " dalla cartella del programma.")
        else:
            nome_file_chiave = input(
                "File "+ nome_file_chiave + " non trovato. \n \
                Verifica e inserisci di nuovo il nome del file della chiave privata: "
                )
    print("La configurazione è terminata. \n"\
          "Ricorda la password per avviare i programmi di interazione con INAD.")
else:
    print("Il programma sembra già configurato.")
    print("Se non ricordi la password cancella dalla cartella del programma "\
          "i file \'INAD.cfg\' e \'chiave.priv\' e ripeti l'installazione.")

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
    passw = ""
    password = b""
    PASSWORD_CORRETTA = False
    while PASSWORD_CORRETTA is False:
        with open("INAD.cfg", "r") as f:
            try:
                INAD = decifra_dizionario("INAD.cfg", chiave)
                print("La password è corretta.")
                PASSWORD_CORRETTA = True
            except:
                print("La password NON è corretta.")
                passw = pwinput.pwinput()
                password = passw.encode()
                chiave = base64.urlsafe_b64encode(kdf().derive(password))
                passw = ""
                password = b""

CONTINUARE = True
while CONTINUARE is True:

    ###Scegli la funzione da usare
    print("\nparlaConINAD consente le seguenti funzioni: \n\n"\
          "1 - estrazione puntuale di un domicilio digitale; \n"\
          "2 - verifica puntuale di un domicilio fiscale; \n"\
          "3 - estrazione massiva di domicili digitali; \n"\
          "4 - recupero dei risultati di una lista precedentemente caricata; \n"\
          "U - esci da parlaConINAD.\n")
    scelta = ""
    while scelta not in ["1", "2", "3", "4", "U", "u"]:
        scelta = input("Cosa vuoi fare? Scegli 1, 2, 3 o 4 (U per uscire): ")
    if scelta in ["U", "u"]:
        print("\nCiao " + CALLING_USER + ", è stato un piacere fare affari con te ;)")
        termina()

    ##verifico presenza di un token valido (file INAD.tkn)
    TOKEN_DISPONIBILE = False
    while TOKEN_DISPONIBILE is False:
        if os.path.exists("INAD.tkn") is True:
            print("Verifico se il token PDND è ancora valido.")
            try:
                INADtoken = decifra_dizionario("INAD.tkn", chiave)
                allora = datetime.datetime.strptime(INADtoken["creato"], "%a, %d %b %Y %H:%M:%S %Z")
                adesso = datetime.datetime.now()
                if int((adesso - allora).total_seconds()) < (DURATA_TOKEN-60):
                    token = INADtoken["token"]
                    print("Token valido.")
                    TOKEN_DISPONIBILE = True
                else:
                    print("Token non valido.")
                    os.remove("INAD.tkn")
            except:
                os.remove("INAD.tkn")
        else:
            print("\nNessun token PDND valido è disponibile. Ne ottengo uno.")
            privateKey = recupera_chiave("chiave.priv", chiave)
            client_assertion = create_m2m_client_assertion(INAD["kid"], INAD["alg"], INAD["typ"],
                INAD["iss"], INAD["sub"], INAD["aud"], privateKey, INAD["PurposeID"])
            token_response = token_request(INAD["iss"], client_assertion,
                INAD["Client_assertion_type"], INAD["Grant_type"])
            tokenDict = {}
            if token_response.status_code == 200:
                tokenDict["token"] = token_response.json()["access_token"]
                tokenDict["creato"] = token_response.headers["date"]
                cifra_dizionario(tokenDict, chiave, "INAD.tkn")
                print("Ho creato il token (o voucher). Proseguiamo...")
                token = tokenDict["token"]
                TOKEN_DISPONIBILE = True
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
        cf = chiedi_cf()
        ref = input("Inserisci un riferimento al procedimento amministrativo: ")
        estrazione = estrai_domicilio(token, cf, ref)
        if estrazione.status_code == 200:
            try:
                print("\nDomicilio digitale di " + cf + ": "\
                      +estrazione.json()["digitalAddress"][0]["digitalAddress"])
            except:
                print("\nL\'interazione è andata a buon fine, "\
                      "ma probabilmente il servizio è chiuso.")
            print("\nDi seguito la risposta completa di INAD:")
            try:
                print(estrazione.content.decode())
            except:
                print(estrazione.content)
        elif estrazione.status_code == 400:
            print("\nRichiesta mal formulata: " +estrazione.json()["detail"])
        elif estrazione.status_code == 401:
            print("\nNon autorizzato: " + estrazione.json()["detail"])
        elif estrazione.status_code == 403:
            print:("\nOperazione non consentita: " + estrazione.json()["detail"])
        elif estrazione.status_code == 404:
            print(estrazione.json()["status"] +" - " + estrazione.json()["detail"])
            print("\nSoggetto non trovato. Ragionevolmente, "+cf+" non è registrato su INAD")
            print("\nDi seguito il contenuto completo della risposta: ")
            print(estrazione.json())
        else:
            print("Qualcosa è andato storto, "\
                  "lo status code della risposta è: "+str(estrazione.status_code)+". "\
                  "Consulta le specifiche per maggiori informazioni")
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
        cf = chiedi_cf()
        mail = chiedi_mail()
        data = chiedi_data()
        ref = input("Inserisci un riferimento al procedimento amministrativo: ")
        verifica = verifica_domicilio(token, cf, ref, mail, data)
        if verifica.status_code == 200:
            try:
                if verifica.json()["outcome"] is True:
                    print("\nLa verifica del domicilio digitale " + mail +" per "+cf+" "\
                          "alla data " + data + " ha dato esito POSITIVO.")
                elif verifica.json()["outcome"] is False:
                    print("\nLa verifica del domicilio digitale " + mail +" per "+cf+" "\
                          "alla data " + data + " ha dato esito NEGATIVO.")
            except:
                print("\nL\'interazione è andata a buon fine, "\
                      "ma probabilmente il servizio è chiuso.")
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
            print("Qualcosa è andato storto, "\
                  "lo status code della risposta è: "+str(verifica.status_code)+". "\
                  "Consulta le specifiche per maggiori informazioni")
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
        print("Per questa operazione hai bisogno di un file CSV, delimitato da ;, "\
              "con una colonna che contiene i codici fiscali per i quali estrarre il domicilio.")
        print("Copialo nella cartella del programma, per tua facilità.\n")
        ref = input("Per iniziare, indica una breve descrizione del motivo della ricerca su INAD: ")

        # Individuo il file CSV con i dati in input
        NOME_FILE_DATI = input("Indica il nome del file CSV: ")
        FILE_DATI_TROVATO = False
        while FILE_DATI_TROVATO is False:
            if os.path.exists(NOME_FILE_DATI):
                FILE_DATI_TROVATO = True
                print("File trovato.")
            else:
                NOME_FILE_DATI = input(
                    "File "+ NOME_FILE_DATI + " non trovato. "\
                    "Verifica e inserisci di nuovo il nome del file CSV: "
                    )
        print("File CSV trovato.\n")

        # Inizializzo la cartella di lotto e i file di output e log
        DATA_LOTTO = timestamp_breve()
        PATH=crea_cartella(ref, DATA_LOTTO) # crea la cartella di lavoro del lotto
        LOTTO_LOG=PATH + DATA_LOTTO + "-" + "lotto.log"
        RICEVUTA_JSON = PATH + DATA_LOTTO + "-ricevuta.json"
        STATO_JSON = PATH + DATA_LOTTO + "-stato.json"
        DOMICILI_JSON = PATH + DATA_LOTTO + "-domiciliDigitali.json"
        LOTTO_JSON=PATH + DATA_LOTTO + "-" + "Lotto.json"
        LOTTO_ELABORATO_JSON = PATH + DATA_LOTTO + "-" + "LottoElaborato.json"
        REQUESTS_LOG = PATH + DATA_LOTTO + "-" + "Requests.log"
        fh = logging.FileHandler(REQUESTS_LOG)
        log.addHandler(fh)
        OUTPUT_CSV = PATH + "elaborato-"+NOME_FILE_DATI
        logga("Ciao " + os.getlogin() + "!") #apre il lotto di log salutando l'utente
        stampa("Ho creato la cartella di lotto: "+PATH)
        logga("Data della richiesta: "+DATA_LOTTO)
        logga("Motivo della richiesta: "+ref)

        ## Estraggo il file CSV e creo un array di dizionari e un file json nella cartella di lotto
        with open(NOME_FILE_DATI, "r") as input_file:
            reader = csv.DictReader(input_file, delimiter=";")
            LOTTO = []
            for i in reader:
                LOTTO.append(i)
        salva_dizionario(LOTTO, LOTTO_JSON)

        ## Definisco la colonna che contiene il codice fiscale
        print("\nIl CSV importato ha le seguenti chiavi:")
        CHIAVI_CSV = list(LOTTO[0].keys())
        for i in CHIAVI_CSV:
            print(i)
        print("\n")
        CHIAVE_CF = input("Indicare la chiave che contiene il codice fiscale: ")
        while not CHIAVE_CF in CHIAVI_CSV:
            CHIAVE_CF = input("Indicare la chiave che contiene il codice fiscale: ")

        ## Estraggo lista di codici fiscali per INAD
        LISTA_CF = []
        for i in LOTTO:
            LISTA_CF.append(i[CHIAVE_CF])
        stampa("Ho estratto la lista di codici fiscali per cui richiedere il domicilio digitale.")

        # Carico la lista su INAD e definisco intervallo di polling
        stampa("Carico la lista su INAD.")
        invio = carica_lista(token, LISTA_CF, ref)
        L = len(LISTA_CF)
        #PAUSA = 120 + 2 * L
        PAUSA = 720  #Indicazione AGID: intervallo di polling fra 10 e 15 minuti
        if invio.status_code == 202:
            ricevuta = invio.json()
            ricevuta["nomeFileDati"] = NOME_FILE_DATI
            ricevuta["cartellaDiLavoro"] = PATH
            ricevuta["utente"] = CALLING_USER
            ricevuta["data_lotto"] = DATA_LOTTO
            ricevuta["chiaveCF"] = CHIAVE_CF
            salva_dizionario(ricevuta, RICEVUTA_JSON)
            stampa("Lista dei file inviata correttamente. \nAttendo " + str(PAUSA) + " "\
                   "secondi per verificare lo stato della richiesta.")
            stampa("Ho salvato la ricevuta della richiesta nella cartella di lotto.")
            stampa("Puoi interrompere l'esecuzione del programma (CTRL+C) e "\
                   "recuperare i risultati in seguito.")
        elif invio.status_code in [400, 404, 500, 503]:
            stampa("Il server ha risposto: " + str(invio.status_code) +".")
            for i in invio.json():
                stampa(i +": " +invio.json()[i])
            stampa("Termino il programma. Tu cerca di capire cosa non va ;)")
            termina()
        else:
            stampa("Qualcosa è andato storto. Puoi controllare i log nella cartella di lotto.")
            stampa("Di seguito la risposta completa.")
            stampa(str(invio.content.decode()))
            termina()

        # Attendo il tempo T = PAUSA
        time.sleep(PAUSA)

        # Recupero lo stato dell'elaborazione della lista
        id_lista = ricevuta["id"]
        verifica = verifica_stato_lista(token, id_lista, STATO_JSON, PAUSA)

        # Quando la lista è pronta, recupero i domicili e li salvo in domiciliDigitali.json
        DOMICILI = salva_lista_domicili(token, id_lista, DOMICILI_JSON)

        ## Creo un nuovo array di dizionari a partire dall'array lotto e un
        ## nuovo file CSV con colonne aggiuntive per il codice fiscale e la professione eventuale.
        LOTTO_ELABORATO = elabora_lotto(LOTTO, DOMICILI, CHIAVE_CF, LOTTO_ELABORATO_JSON, OUTPUT_CSV)  #" o non "?
        
#############################
######  RECUPERO LISTA ######
#############################
    elif scelta == "4":
        print("\n" + scelta + " - Recupero risultati di precedente interrogazione multipla.")
        print("\nHai bisogno di una ricevuta in formato json di un precedente invio.")
        print("Puoi sceglierla da un elenco oppure indicare il file manualmente.")
        print("Ti conviene copiarla dalla cartella di lotto alla cartella di questo programma e rinominarla.")
        RICEVUTE = []
        for cartella, sottocartelle, files in os.walk(".\\lotti\\"):
            for file in files:
                if file[-13:] == "ricevuta.json":
                    RICEVUTE.append(os.path.join(cartella, file))
        ULTIME_RICEVUTE = RICEVUTE[-5:]
        ULTIME_RICEVUTE.append("Inserisci manualmente.")
        RICEVUTA_TROVATA = False
        while RICEVUTA_TROVATA is False:
            print("\nRicevute degli ultimi lotti caricati:")
            nome_file_ricevuta = pyip.inputMenu(ULTIME_RICEVUTE, numbered = True, blank = True)
            if nome_file_ricevuta == '':
                print("Scelta non corretta. Riprova.")
                continue
            elif nome_file_ricevuta == "Inserisci manualmente.":
                nome_file_ricevuta = input("Inserisci il nome del file della ricevuta: ")
            try:
                with open(nome_file_ricevuta, "rb") as file:
                    DATI_LOTTO = json.load(file)
                    NOME_FILE_DATI = DATI_LOTTO["nomeFileDati"]
                    PATH = DATI_LOTTO["cartellaDiLavoro"]
                    id_lista = DATI_LOTTO["id"]
                    DATA_LOTTO = DATI_LOTTO["data_lotto"]
                    CHIAVE_CF = DATI_LOTTO["chiaveCF"]
                    RICEVUTA_TROVATA = True
            except:
                print(f"\nFile {nome_file_ricevuta} non trovato.")
        print("\nFile della ricevuta trovato.")

        ## Inizializzazione di cartella di lotto, file di output e logging
        LOTTO_LOG=PATH + DATA_LOTTO + "-" + "lotto.log"
        RICEVUTA_JSON = PATH + DATA_LOTTO + "-ricevuta.json"
        STATO_JSON = PATH + DATA_LOTTO + "-stato.json"
        DOMICILI_JSON = PATH + DATA_LOTTO + "-domiciliDigitali.json"
        LOTTO_JSON=PATH + DATA_LOTTO + "-" + "Lotto.json"
        LOTTO_ELABORATO_JSON = PATH + DATA_LOTTO + "-" + "LottoElaborato.json"
        REQUESTS_LOG = PATH + DATA_LOTTO + "-" + "Requests.log"
        fh = logging.FileHandler(REQUESTS_LOG)
        log.addHandler(fh)
        OUTPUT_CSV = PATH + "elaborato-"+NOME_FILE_DATI

        # Leggo i dati di lotto dal file json
        with open(LOTTO_JSON, "r") as file:
            LOTTO = json.load(file)
        LISTA_CF = []
        for i in LOTTO:
            LISTA_CF.append(i[CHIAVE_CF])
        L = len(LISTA_CF)
        #PAUSA = 120 + 2 * L
        PAUSA = 720  #Indicazione AGID: intervallo di polling fra 10 e 15 minuti
        stampa("Informazioni dal file "+nome_file_ricevuta +" importate.")
        stampa("Inizio il recupero della richiesta con id: "+id_lista +".")

        # Verifico lo stato di elaborazione della lista
        verifica = verifica_stato_lista(token, id_lista, STATO_JSON, PAUSA)

        # Quando la lista è pronta, recupero i domicili e li salvo in domiciliDigitali.json
        DOMICILI = salva_lista_domicili(token, id_lista, DOMICILI_JSON)

        ## Creo un nuovo array di dizionari a partire dall'array lotto e un
        ## nuovo file CSV con colonne aggiuntive per il codice fiscale e la professione eventuale.
        LOTTO_ELABORATO = elabora_lotto(LOTTO, DOMICILI, CHIAVE_CF, LOTTO_ELABORATO_JSON, OUTPUT_CSV)

#############################
####  USCITA DAL PROGRAMMA ##
#############################
    else:
        print("Ciao " + CALLING_USER + ", è stato un piacere fare affari con te ;)")
        termina()

# Chiedo se si ha intenzione di continuare
    risposta = input("Vuoi fare altre operazioni su INAD [S = sì / N = no]? ")
    while risposta not in ["S", "sì", "s", "Sì", "N", "no", "NO", "n"]:
        risposta = input("Non ho capito. Vuoi fare altre operazioni su INAD "\
                         "[S = sì / N = no]? ")
    if risposta in ["N", "no", "NO", "n"]:
        CONTINUARE = False

# Quando è tutto finito, termina
termina()
