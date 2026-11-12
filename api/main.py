"""
API du portail QR-Shield (FastAPI).

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

from fastapi import FastAPI, File, HTTPException, UploadFile
from pydantic import BaseModel

from src.detecteurs import DetecteurLiens, DetecteurQR

RACINE = Path(__file__).resolve().parent.parent
DOSSIER_MODELES = Path(os.environ.get("QRS_MODELES", RACINE / "models"))
DOSSIER_LOGS = Path(os.environ.get("QRS_LOGS", RACINE / "logs"))
DOSSIER_LOGS.mkdir(exist_ok=True)
TAILLE_MAX_IMAGE = 5 * 1024 * 1024      # 5 Mo

app = FastAPI(title="QR-Shield API",
              description="Détection de liens de phishing et de QR codes piégés (quishing). Rien n'est ouvert.")

liens = DetecteurLiens(DOSSIER_MODELES)
qr = DetecteurQR(DOSSIER_MODELES, liens)


def journaliser(route, contenu: bytes, resultat: dict, debut: float):
    """Enregistre chaque prédiction (sans le contenu lui-même, seulement son empreinte) pour le suivi MLOps."""
    ligne = {
        "date": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "route": route,
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


class DemandeLien(BaseModel):
    url: str


@app.get("/sante")
def sante():
    return {"etat": "ok", "liens": True, "qr": True}


@app.post("/url")
def analyser_lien(demande: DemandeLien):
    debut = time.perf_counter()
    resultat = liens.analyser(demande.url)
    return journaliser("url", demande.url.encode(), resultat, debut)


@app.post("/qr")
async def analyser_qr(image: UploadFile = File(...)):
    debut = time.perf_counter()
    contenu = await image.read()
    if len(contenu) > TAILLE_MAX_IMAGE:
        raise HTTPException(413, "Image trop lourde (5 Mo maximum).")
    return journaliser("qr", contenu, qr.analyser(contenu), debut)