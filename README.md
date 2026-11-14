# QR-Shield

**Unified MLOps Framework for Real-Time Detection of Evasive Phishing URLs and QR Codes (Quishing)**

Groupe 4 · Master MIAC · Module *Machine Learning pour la cybersécurité*
Kamal Dafir · Youssef Yazidi · Ayman Annous · Abdellatif Dafiaa · Ilyass Boudrioua

---

## Le problème

Le *quishing* est le phishing par QR code. Un faux autocollant collé sur un parking, un menu ou une facture
renvoie vers un faux site de paiement. Le lien est caché dans l'image : l'utilisateur ne le voit qu'une fois
le site ouvert, et c'est déjà trop tard.

## Ce que fait QR-Shield

On donne **un lien ou une image de QR code**. Le portail répond **OFFICIEL, SÛR, SUSPECT, DANGEREUX ou INDÉTERMINÉ**
et explique pourquoi. **Le lien n'est jamais ouvert.**

```
          lien collé ─────────────┐
                                  ├─> normalisation ─> 1. signature (QR codes officiels)
 image de QR code ─> lecture ─────┘     (sans http,     2. modèle XGBoost unifié + raisons SHAP
          (si illisible : modèle         www,           3. enquête sur le domaine (imitation de marque, âge)
           sur les pixels)               paramètres)    4. base de menaces (signalements)
                                                                    │
                       portail web · bot Telegram  <─── verdict + raisons
                                                                    │
           signalements ─> base de menaces ─> réentraînement champion / challenger ─> surveillance (dérive PSI)
```

| Couche | Rôle | Fichier |
|---|---|---|
| **Module unifié** | Un seul modèle pour les liens collés et les liens lus dans les QR codes | `src/detecteurs.py` |
| **QR codes signés** (contribution) | Signature numérique Ed25519 de l'émetteur : un faux autocollant est détecté à coup sûr | `scripts/emetteur.py`, `registre/` |
| **Enquête sur le domaine** (contribution) | Imitation de marques marocaines et internationales (typosquatting, homoglyphes), âge du domaine (RDAP) | `src/enquete.py` |
| **Boucle de données** (contribution) | Signalements, base de menaces, réentraînement champion / challenger, surveillance de la dérive | `src/menaces.py`, `scripts/reentrainer.py`, `src/surveillance.py` |
| **Canaux** | API FastAPI, portail Streamlit (avec page Surveillance), bot Telegram | `api/`, `app/`, `bot/` |

## Résultats (test, mesure unique)

Données : PhreshPhish 2025 (liens) + Quishing Dataset (liens lus dans 9 987 QR codes), soit 113 539 liens après
normalisation, suppression des doublons et des fuites de domaines. Découpage par date (PhreshPhish) et par domaine (QR codes).

| Modèle | Niveau | Recall | Précision | FPR | MCC |
|---|---|---|---|---|---|
| Baseline (régression logistique) | seuil 0,5 | 85,6 % | 90,7 % | 7,3 % | 0,787 |
| **XGBoost unifié** | SUSPECT (FPR ≤ 5 % en validation) | **89,2 %** | 91,5 % | 6,9 % | **0,825** |
| **XGBoost unifié** | DANGEREUX (FPR ≤ 1 % en validation) | 77,8 % | **98,1 %** | **1,3 %** | 0,793 |

- **QR codes** au niveau DANGEREUX : 2 fausses alertes sur 687 sites sûrs.
- **Enquête sur le domaine** : précision de 98,2 % (378 → 28 fausses alertes après analyse des erreurs) ; 12 phishing ratés par le modèle sont rattrapés, sans hausse notable du FPR.
- **QR codes signés** : 4 attaques simulées (faux autocollant, signature abîmée, fausse clé, émetteur inventé), toutes bloquées.

Hypothèses : **H1** confirmée (XGBoost > baseline) · **H2** le lien caché est plus fiable que l'image (le modèle sur les pixels ne sert que de secours) · **H3** les attaques changent : surveillance de la dérive (PSI) et réentraînement prévus.

## Lancer le projet

### Avec Docker (recommandé)

Prérequis : Docker Desktop. Les modèles entraînés (`models/`) sont fournis à part (trop lourds pour GitHub).

```bash
docker compose up --build
```

- Portail : http://localhost:8501 (page **Surveillance** dans le menu de gauche)
- API : http://localhost:8000/docs

Avec le bot Telegram : créer un fichier `.env` contenant `QRS_TELEGRAM_TOKEN=...` (jeton BotFather), puis
`docker compose --profile telegram up --build`.

### Sans Docker (Windows)

```bat
py -V:3.13 -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn api.main:app --port 8000          :: fenêtre 1
streamlit run app/app.py                  :: fenêtre 2
python bot/bot_telegram.py                :: fenêtre 3 (après set QRS_TELEGRAM_TOKEN=...)
```

### Outils

```bash
python scripts/emetteur.py creer --id mairie-demo --nom "Mairie de Démo" --domaine mairie-demo.ma
python scripts/emetteur.py signer --id mairie-demo --lien https://mairie-demo.ma/paiement --sortie qr_officiel.png
python scripts/attaques.py qr_officiel.png        # fabrique 4 QR codes pirates dans attaques/
python scripts/reentrainer.py --rapide            # duel champion / challenger (test rapide)
```

## Structure

| Dossier | Contenu |
|---|---|
| `notebooks/` | 01 liens, 02 QR codes, 04 module unifié, 05 enquête sur le domaine (Google Colab) |
| `src/` | détecteur unifié, enquête, base de menaces, surveillance |
| `api/` | API FastAPI : `/analyser`, `/signaler`, `/statistiques`, `/surveillance`, `/sante` |
| `app/` | portail Streamlit et page Surveillance |
| `bot/` | bot Telegram |
| `scripts/` | émetteur de QR codes signés, attaques simulées, réentraînement |
| `registre/` | clés publiques des émetteurs officiels, liste Tranco des domaines populaires |
| `archives/` | module fichiers (retiré du projet à la demande de l'enseignant) |

## Éthique et vie privée

- Aucun lien n'est ouvert ; seul le registre des noms de domaine (RDAP) est interrogé pour l'âge du domaine.
- Journal des prédictions : empreinte (hachage) uniquement. Signalements : lien normalisé sans paramètres, sans IP, sans nom, sans identifiant Telegram (principe de minimisation, loi 09-08 / CNDP).
- Les clés privées des émetteurs ne quittent jamais la machine (`cles_privees/` exclu de Git et de Docker).
- Émetteur et attaques de démonstration fictifs (« Mairie de Démo », domaines inventés) : aucune vraie marque n'est imitée.

## Limites

- Le registre `.ma` ne propose pas RDAP : pas d'âge du domaine pour les sites marocains.
- Quelques vrais mots restent proches de marques (*apply / apple*, *finance / binance*).
- Les règles de l'enquête ont été ajustées en observant les erreurs : à revalider sur des données nouvelles (boucle de données).
- Peu de phishing marocain dans les jeux de données publics : d'où l'enquête par règles pour les marques marocaines.
