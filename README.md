# parlaConINAD2

** AGGIORNAMENTO **
Su sistemi Windows è possibile **trasformare lo script in un eseguibile** .exe che mantiene la stessa logica di funzionamento.  

Istruzioni:
- SE MANCA: pip install pyinstaller
- pyinstaller parlaConINAD2 --onefile
Sotto la cartella "dists" si recupera l'eseguibile Windows.
Utile per usarlo su PC senza Python installato.


# Descrizione
Script Python **didattico** per interagire con INAD, l'Indice nazionale dei domicili digitali, tramite la PDND (Piattaforma Digitale Nazionale Dati - https://domiciliodigitale.gov.it).  
Lo script funziona nell'**ambiente di collaudo** di PDND e di INAD.  
Per l'uso in ambiente di produzione dovrebbe essere sufficiente cambiare il valore delle variabili degli endpoint di PDND e INAD.  

L'interazione avviene tramite linee di comando:
- per interrogazioni singole con richiesta di inserire i dati della richiesta;
- per interrogazioni massive con richiesta di fornire un file CSV con una colonna di codici fiscali. Lo script **restituisce lo stesso CSV con aggiunta dei dati del domicilio digitale**.

Rispetto alla precedente versione di parlaConINAD:
- c'è un unico fle di script che ingloba la definizione delle funzioni e tutte le operazioni messe a disposizione da INAD;
- anche la configurazione, al primo avvio, è interattiva da riga di comando;
- i dati di configurazione sono cifrati e per avviare lo script occorre una password (vedi sotto).

Un file con codici fiscali registrati nell'ambiente INAD di collaudo è disponibile sul repository GitHub delle API di INAD: https://github.com/AgID/INAD_API_Extraction/blob/main/datasetCampione.csv

# Prerequisiti e configurazione

Per l'esecuzione dello script è necessaria un'installazione di Python con alcuni moduli aggiuntivi (vedi sotto).

Per l'autorizzazione all'uso delle API di INAD, si rimanda alla documentazione della PDND: https://docs.pagopa.it/interoperabilita-1/). In sintesi:
- aderire alla PDND;
- in ambiente di collaudo, creare l'accordo di fruizione dell'e-service "INAD API PUBBLICHE CONSULTAZIONE";
- attendere l'approvazione;
- creare coppia di chiavi come da documentazione;
- in ambiente di collaudo, creare un client e-service e caricarci la chiave pubblica;
- in ambiente di collaudo, creare una finalità per l'e-service "INAD API PUBBLICHE CONSULTAZIONE" e associarla al client e-service creato al punto precedente.

Per la generazione delle chiavi è disponibile lo script **generatore/generatore.py** che produce una coppia di chiavi crittografiche RSA in formato compatibile con le richieste PDND.

**Configurazione**:
Al primo avvio lo script richiede alcune informazioni:
- una password per accedere allo script e cifrare i dati di configurazione. La password non è recuperabile, quindi occorre custodirla in un posto sicuro e segreto;
- i dati del client e-service INAD. Questi sono recuperabili dal back office PDND: conviene tenere la pagina del client e-services sulla PDND apera e fare copia e incolla;
- la chiave privata associata alla chiave pubblica inserita nel client e-service: occorre salvare il file della chiave privata temporaneamente nella cartella di parlaConINAD2 e, una volta configurata, spostarlo.

La password deve soddisfare i seguenti requisiti (modificabile tramite l'espressione regolare RE_PASSWORD):
- ha lunghezza da 8 a 20 caratteri;
- contiene una lettera maiuscola;
- contiene una lettera minuscola;
- contiene un numero;
- contiene un carattere speciale (fra !, #, $, &, ?).

Se si perde la password occorre cancellare i file "INAD.cfg" e "chiave.priv" e ripetere la configurazione.
I file di log e le cartelle di lotto di precedenti estrazioni multiple non andranno perduti.

# Avvertenze e misure di sicurezza

Si tratta di un'**iniziativa didattica**, con lo scopo di:
- rendersi conto dell'interazione con INAD e del passaggio tramite PDND;
- individuare aspetti di criticità per integrazioni stabili ed eleganti con software "veri" in produzione.

Rispetto alla prima versione sono stati migliorati i seguenti aspetti di sicurezza:
- chiave privata e dati del client e-service sono memorizzati cifrati nella cartella di parlaConINAD2;
- conseguentemente, chi ha accesso alla cartella non li vede in chiaro;
- i dati sono cifrati con una chiave ricavata dalla password impostata al primo avvio: per questo la password non è memorizzata in alcun modo (nemmeno come hash);
- di conseguenza chi non conosce la password non può utilizzare efficacemente lo script;
- è stata leggermente migliorata la gestione di errori e eccezioni;
- sono adesso presenti controlli sul formato dei dati di input per codici fiscali / partiva IVA, date e indirizzi e-mail.

Ricordando che lo script fa accesso a INAD che è una banca dati liberamente consultabile via web da chiunque senza autenticazione, le misure di sicurezza adottate sono minime.  
Sembrava corretto proteggere i dati di autenticazione alle API per evitare comunque accessi autenticati abusivi. Durante l'esecuzione dello script i dati cifrati vengono decifrati.  
**Si rimette alla valutazione di ognuno l'implementazione di ulteriori misure di sicurezza**, specialmente se si intende usare lo script nell'ambiente INAD di produzione e se la chiave privata è usata anche per altri e-service.  
Sicuramente lo script, configurato, va mantenuto su una postazione protetta.  
Infine, lo script è pensato per l'uso presidiato da riga di comando e non per essere integrato in software più estesi.  

# Documentazione su INAD

Le specifiche delle API di INAD sono su GitHub: https://github.com/AgID/INAD_API_Extraction.  
Per visualizzarle in modo più comprensibile si può caricare il fiel YAML su https://editor.swagger.io/ (come link o come upload).  
La descrizione testuale è qui: https://domiciliodigitale.gov.it/dgit/home/public/docs/inad-specifiche_tecniche_api_estrazione.pdf
--> Attenzione: a metà giugno 2023, non c'è alineamento pieno fra sepcifiche API e loro descrizione testuale.

Soprattutto, per implementare **fuzioni sensate** e un **uso di INAD legittimo e utile** per chi lavora con i domicili digitali è fondamentale conoscere la **normativa**:  
- Codice dell'amministrazione digitale https://www.normattiva.it/uri-res/N2Ls?urn:nir:stato:decreto.legislativo:2005-03-07;82!vig=2023-06-17, in particolare:
	- gli articoli 6-ter e 3-bis;
	- le modifiche apportate al CAD dall'articolo 24 del dl 76/2020 (https://www.normattiva.it/uri-res/N2Ls?urn:nir:stato:decreto.legge:2020-07-16;76!vig=2022-09-18)
- Linee guida AGID: https://trasparenza.agid.gov.it/moduli/downloadFile.php?file=oggetto_allegati/221871119160O__OLinee+guida+inad+ex+art.+6quater+cad.pdf

# Prerequisiti Python

Gli script fanno uso di alcuni moduli, fra cui:
- jose;
- requests;
- cryptography;
- urllib3;
- pyinputplus;
- pwinput,
che potrebbero non essere parte dell'installazione standard di Python. 
Verificare di averli installati.  

# Consigli per l'uso dello script

Se tutto va bene, in ambiente Windows, un doppio click su parlaConINAD2.py avvia lo script.

Lo script implementa le 4 funzioni di INAD:
1) estrazione puntuale di un domicilio;
2) verifica puntuale di un domicilio;
3) estrazione multipla di domicili (a partire da una lista di codici fiscali);
4) recupero dei risultati dell'estrazione di una lista (pull back).

E' sempre richiesto di specificare il motivo / il riferimento al procedimento amministrativo per cui si effettua l'interrogazione.  

Per le funzioni 1 e 2 basta seguire le indicazioni a riga di comando.  

**3 - Estrazione multipla**

Occorre un file CSV, con delimitatore ;, che contenga una colonna con i codici fiscali da estrarre.  
Lo script restituisce una copia del file CSV alla quale sono aggiunta una o più colonne con i domicili digitali trovati su INAD.  
Si consiglia di **copiare il file CSV nella cartella di parlaConINAD2**.  

L'elaborazione della richiesta è asincrona da parte di INAD. Lo script resta in esecuzione e verifica lo stato con un certo intervallo di polling (al momento 320 secondi, in attesa di indicazioni sul tempo opportuno).  

Si può comunque interrompere lo script (CTRL+C) e recuperare i risultati in seguito con la funzione n. 4.

**4 - Recupero dei risultati**

Lo script richiede di inserire il nome del file .json della ricevuta.  
Conviene copiarlo dalla cartella di lotto nella cartella di parlaConINAD.

L'interazione prosegue poi come nella funzione 3: interrogazione periodica dello stato di elaborazione, recupero dei risultati e produzione della copia elaborata del file CSV di partenza.

# La cartella di lotto

Durante l'esecuzione delle funzioni 3 e 4, lo script genera una cartella, detta cartella di lotto, contenuta nella cartella "lotti".  
La cartella di lotto ha un nome basato sul patterno "TIMESTAMP - descrizione dell'interrogazione" e contiene gli esiti dell'elaborazione e file tecnici intermedi:
- un file JSON con il contenuto del file CSV ricevuto in input;
- log del lotto: include parte di quanto scritto a video;
- log di requests (chiamate HTTP a INAD);
- un file JSON di **ricevuta** della richiesta da parte di INAD (con dati aggiuntivi per il successivo recupero);
- un file JSON con lo stato dell'elaborazione (aggiornato all'ultima verifica);
- un file JSON come recuperato da INAD;
- un file JSON che comprende il contenuto del file CSV originario unito alle risposte di INAD;
- il file CSV fnale che comprende i dati del **CSV originario con colonna/e aggiuntive per i domicili digitali** recuperati e l'eventuale professione del titolare.


**--> ATTENZIONE (per gli "spippolatori" del finesettimana): l'ambiente di test di Infocamere è attivo dal lunedì al venerdì dalle 7 alle 21.**
