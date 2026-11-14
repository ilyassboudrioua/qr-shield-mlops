"""
API du portail QR-Shield (FastAPI) : une seule route pour un lien OU une image de QR code.

Lancer depuis la racine du projet :
    uvicorn api.main:app --port 8000
Documentation interactive : http://localhost:8000/docs
"""
import hashlib
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from pydantic import BaseModel

from src.detecteurs import DetecteurUnifie, normaliser
from src.menaces import BaseMenaces
from src.surveillance import tableau_de_bord

RACINE = Path(__file__).resolve().parent.parent
DOSSIER_MODELES = Path(os.environ.get("QRS_MODELES", RACINE / "models"))
DOSSIER_LOGS = Path(os.environ.get("QRS_LOGS", RACINE / "logs"))
FICHIER_REGISTRE = Path(os.environ.get("QRS_REGISTRE", RACINE / "registre" / "emetteurs.json"))
FICHIER_MENACES = Path(os.environ.get("QRS_MENACES", RACINE / "donnees" / "menaces.db"))
DOSSIER_LOGS.mkdir(exist_ok=True)
TAILLE_MAX_IMAGE = 5 * 1024 * 1024      # 5 Mo

app = FastAPI(title="QR-Shield API",
              description="Un lien ou une image de QR code : un seul module, un seul modèle. Rien n'est ouvert.")

base = BaseMenaces(FICHIER_MENACES)
detecteur = DetecteurUnifie(DOSSIER_MODELES, FICHIER_REGISTRE, base)


def journaliser(entree, contenu: bytes, resultat: dict, debut: float):
    """Enregistre chaque prédiction (sans le contenu lui-même, seulement son empreinte) pour le suivi MLOps."""
    ligne = {
        "date": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "entree": entree,
        "empreinte": hashlib.sha256(contenu).hexdigest()[:16],
        "verdict": resultat.get("verdict"),
        "score": resultat.get("score"),
        "modele": resultat.get("modele"),
        "duree_ms": round((time.perf_counter() - debut) * 1000, 1),
    }
    with open(DOSSIER_LOGS / "predictions.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(ligne, ensure_ascii=False) + "\n")
    resultat["duree_ms"] = ligne["duree_ms"]
    return resultat


@app.get("/sante")
def sante():
    return {"etat": "ok", "modele": detecteur.infos["modele"], "emetteurs_officiels": len(detecteur.registre)}


@app.post("/analyser")
async def analyser(lien: Optional[str] = Form(None), image: Optional[UploadFile] = File(None)):
    """Envoyer soit un lien (champ « lien »), soit une image de QR code (champ « image »)."""
    debut = time.perf_counter()
    if image is not None and image.filename:
        contenu = await image.read()
        if len(contenu) > TAILLE_MAX_IMAGE:
            raise HTTPException(413, "Image trop lourde (5 Mo maximum).")
        return journaliser("image", contenu, detecteur.analyser_image(contenu), debut)
    if lien and lien.strip():
        return journaliser("lien", lien.encode(), detecteur.analyser_lien(lien), debut)
    raise HTTPException(400, "Envoyez un lien ou une image de QR code.")


class Signalement(BaseModel):
    lien: str
    avis: str                       # "phishing" ou "sur"
    verdict_portail: Optional[str] = None
    score: Optional[float] = None
    canal: str = "portail"


@app.post("/signaler")
def signaler(s: Signalement):
    """L'utilisateur corrige le portail : ce lien est en fait du phishing, ou c'est une fausse alerte."""
    if s.avis not in ("phishing", "sur"):
        raise HTTPException(400, "avis doit valoir « phishing » ou « sur ».")
    lien = normaliser(s.lien.split("#qrs=")[0])
    if not lien:
        raise HTTPException(400, "Lien vide.")
    etat = base.signaler(lien, s.avis, s.verdict_portail, s.score, s.canal)
    return {"merci": True, "lien_normalise": lien, **etat}


@app.get("/statistiques")
def statistiques():
    return base.statistiques()


@app.get("/surveillance")
def surveillance():
    """Tableau de bord MLOps : volume, verdicts, temps de réponse, signalements, dérive des scores."""
    return tableau_de_bord(DOSSIER_LOGS / "predictions.jsonl", base.statistiques())
