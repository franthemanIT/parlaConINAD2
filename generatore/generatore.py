## Questo script consente di generare una coppia di chiavi crittografiche RSA.
## La chiave pubblica si carica (copia e incolla del contenuto del file generato) nel client e-service PDND che si intende usare per accedere all'e-service INAD.
## ATTENZIONE: la chiave private è salvata in chiaro!
from Crypto.PublicKey import RSA

print("Ciao, questo script genera una coppia di chiavi. \nCarica la chiave pubblica nel client PDND.")
nome = input("Inserisci un nome per la coppia di chiavi: ")

key = RSA.generate(2048)
with open(nome+".priv", "wb") as content_file:
    content_file.write(key.exportKey("PEM"))

pubkey = key.publickey()
with open(nome+".pub", "wb") as content_file:
    content_file.write(pubkey.exportKey("PEM"))

print("Missione compiuta.\nI file " + nome + ".priv e " + nome +".pub contengono rispettivamente la chiave privata e la chiave pubblica.")
print("Conserva la chiave privata in un luogo sicuro. Copia e incolla il contenuto della chiave pubblica come chiave pubblica del client PDND.")
