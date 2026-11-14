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

from src.detecteurs import DetecteurUnifie

RACINE = Path(__file__).resolve().parent.parent
DOSSIER_MODELES = Path(os.environ.get("QRS_MODELES", RACINE / "models"))
DOSSIER_LOGS = Path(os.environ.get("QRS_LOGS", RACINE / "logs"))
FICHIER_REGISTRE = Path(os.environ.get("QRS_REGISTRE", RACINE / "registre" / "emetteurs.json"))
DOSSIER_LOGS.mkdir(exist_ok=True)
TAILLE_MAX_IMAGE = 5 * 1024 * 1024      # 5 Mo

app = FastAPI(title="QR-Shield API",
              description="Un lien ou une image de QR code : un seul module, un seul modèle. Rien n'est ouvert.")

detecteur = DetecteurUnifie(DOSSIER_MODELES, FICHIER_REGISTRE)


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
