# Caccia al PINPO

Sito web con mappa gratuita (OpenStreetMap/Leaflet) dedicata al solo comune di Macerata, con:

- vista `Semplice`, `Satellitare`
- caricamento immagine con lettura EXIF GPS (se presente)
- inserimento pin tramite:
  - posizione EXIF
  - indirizzo (via + civico)
  - selezione manuale da mappa
- preview foto dentro popup mappa
- click sulla preview per fullscreen
- modifica pin (sostituzione immagine)
- spostamento pin (drag + conferma)
- eliminazione pin
- persistenza su database MongoDB (consigliato, configurabile tramite `MONGODB_URI`/`DATABASE_URL`/`MONGO_URL`) o compatibile MySQL se preferisci
- autenticazione multiutente
- passkey WebAuthn opzionale per utente
- nessun ruolo: ogni utente autenticato puo creare/modificare/eliminare pin
- tracking accessi/modifiche con IP, utente e azione

## Requisiti

- Node.js 20+
- `npm install` (include `@simplewebauthn/server`)

## Setup

1. Installa dipendenze:

```bash
npm install
```

2. Configura ambiente:

- configura direttamente `.env` oppure imposta le variabili nell'ambiente di esecuzione.
- imposta almeno (oppure crea un file `.txt` con la URI sull’ultima riga):

  **il file `.txt` è presente nel `.gitignore`**, quindi puoi usarlo per contener
  collegamenti privati senza rischio di pubblicarli nel repository.
  - `MONGODB_URI` (es. `mongodb+srv://user:pass@cluster0.xxxxxx.mongodb.net/dbname`) oppure `DATABASE_URL`/`MONGO_URL`; il servizio si collegherà automaticamente.
    - se preferisci usare MySQL compatibile puoi fornire un URL `mysql://...`, ma MongoDB è raccomandato.

  - formato utenti supportato:
    - `AUTH_USERS=admin,mario` + `AUTH_USER_<NOME>_PASSWORD` + `AUTH_USER_<NOME>_PASSKEY`
    - oppure `AUTH_USERS_ADMIN=Admin` + `AUTH_USER_ADMIN_PASSWORD=...` + `AUTH_USER_ADMIN_PASSKEY=si/no`
  - `SESSION_SECRET`
  - `WEBAUTHN_RP_ID` e `WEBAUTHN_ORIGIN`

3. Avvia:

```bash
npm run dev
```

4. Apri:

`http://localhost:3000`

## Note operative

- Limite immagine: `12MB`, formati supportati: `JPG`, `PNG`, `WEBP`.
- Vista `Semplice`: OpenStreetMap.
- Vista `Satellitare`: Esri World Imagery.
- I pin fuori Macerata sono bloccati lato backend.
- La via viene impostata automaticamente con reverse geocoding.
- La data mostrata e quella di inserimento del pin.
- Per passkey il dominio/origine devono combaciare con `WEBAUTHN_RP_ID`/`WEBAUTHN_ORIGIN`.
  Il server ora rileva automaticamente l'host della richiesta e lo aggiunge alle origini/ID accettate, in modo che il challenge venga generato con il dominio corrente.
- Tracking opzionale salvato in tabella `tracking` del database (se `DATABASE_URL` impostato). In locale, se non presente, continua a usare `data/tracking.log`.
- Endpoint tracking: `GET /api/tracking?limit=200` (richiede login).

## Deploy Render

Questo progetto è pronto per Render:

1. Carica la cartella su Git (GitHub, GitLab, Bitbucket)
2. Accedi su [Render](https://render.com)
3. Crea nuovo servizio web:
   - Seleziona il repository
   - Name: `macerata-map` (o personalizzato)
   - Environment: `Node`
   - Build command: `npm install`
   - Start command: `npm start`
   - Plan: Free è OK per l'inizio
4. Imposta variabili d'ambiente:
   - `NODE_ENV=production`
   - `PORT=3000` (automatico su Render)
   - `SESSION_SECRET` (genera un valore sicuro)
   - `MONGODB_URI`/`DATABASE_URL`/`MONGO_URL` (indirizzo del tuo server MongoDB Atlas, PlanetScale, ecc. oppure MySQL se lo usi)
   - `ADMIN_USERNAME=admin`
   - `ADMIN_PASSWORD` (cambia questo!)
   - `WEBAUTHN_RP_NAME=Macerata FotoMap`
   - `WEBAUTHN_RP_ID` (il tuo dominio Render, es: `macerata-map.onrender.com`)
   - `WEBAUTHN_ORIGIN` (es: `https://macerata-map.onrender.com`)
   - `AUTH_USERS=admin` (o altri utenti)
   - `AUTH_USER_ADMIN_PASSWORD=your_secure_password`
5. Deploy!

Per aggiungere ulteriori utenti, aggiungi al `render.yaml` o via Environment Variables:
- `AUTH_USERS=admin,mario,lucia`
- `AUTH_USER_MARIO_PASSWORD=password_mario`
- `AUTH_USER_LUCIA_PASSWORD=password_lucia`
