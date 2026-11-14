"""
Détecteur unifié du portail QR-Shield : un lien OU une image de QR code, un seul modèle.

1. Si on reçoit une image : on lit le lien caché dans le QR code (OpenCV).
2. Le lien (collé ou lu dans le QR code) est normalisé : sans http(s)://, sans www., sans paramètres.
3. Un seul modèle XGBoost (entraîné sur PhreshPhish + les liens des QR codes) donne le verdict.
4. Secours : si le QR code est illisible, un modèle analyse directement l'image (pixels).

Verdicts : SÛR, SUSPECT, DANGEREUX ou INDÉTERMINÉ, avec un score et les raisons (SHAP).
Rien n'est ouvert : on analyse seulement le texte du lien ou l'image du QR code.
"""
import json
import math
import re
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

import cv2
import joblib
import numpy as np
import pandas as pd
import xgboost as xgb
from scipy.sparse import csr_matrix, hstack

MOTS_SUSPECTS = ["login", "verify", "account", "update", "secure", "bank",
                 "signin", "confirm", "password", "wallet", "support", "billing"]

NOMS_LISIBLES = {
    "longueur_url": "longueur du lien",
    "longueur_host": "longueur du nom de domaine",
    "longueur_chemin": "longueur du chemin",
    "nb_points": "nombre de points",
    "nb_tirets": "nombre de tirets",
    "nb_chiffres": "nombre de chiffres",
    "nb_sous_domaines": "nombre de sous-domaines",
    "nb_slash": "nombre de « / »",
    "a_arobase": "présence de « @ »",
    "host_est_ip": "adresse IP à la place du nom",
    "entropie": "désordre des caractères (entropie)",
    "nb_mots_suspects": "mots suspects (login, verify…)",
}


# ---------------------------------------------------------------- outils (identiques au notebook 04)
def charger_xgb(dossier: Path, nom: str):
    """Charge un modèle XGBoost au format natif (.json), portable entre Linux et Windows."""
    modele = xgb.XGBClassifier()
    modele.load_model(str(dossier / f"{nom}.json"))
    return modele


def normaliser(url: str) -> str:
    """Même forme pour un lien collé et un lien lu dans un QR code."""
    u = str(url).strip()
    u = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", u)   # enlève http://, https://, ...
    u = re.sub(r"^www\d*\.", "", u, flags=re.I)          # enlève www. (et www2. ...)
    hote, sep, reste = u.partition("/")
    u = hote.lower() + sep + reste                       # domaine en minuscules
    u = re.split(r"[?#]", u, maxsplit=1)[0]              # enlève les paramètres
    return u.rstrip("/")


def entropie(t):
    if not t:
        return 0.0
    return -sum((n / len(t)) * math.log2(n / len(t)) for n in Counter(t).values())


def features(url):
    """Features simples d'un lien normalisé (sans http, sans www, sans paramètres)."""
    p = urlparse("http://" + url)
    host = p.hostname or ""
    return {
        "longueur_url": len(url), "longueur_host": len(host), "longueur_chemin": len(p.path),
        "nb_points": url.count("."), "nb_tirets": url.count("-"),
        "nb_chiffres": sum(c.isdigit() for c in url),
        "nb_sous_domaines": max(host.count(".") - 1, 0), "nb_slash": url.count("/"),
        "a_arobase": int("@" in url),
        "host_est_ip": int(bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host))),
        "entropie": round(entropie(url), 3),
        "nb_mots_suspects": sum(m in url.lower() for m in MOTS_SUSPECTS),
    }


def niveau(score, seuil_suspect, seuil_dangereux):
    if score >= seuil_dangereux:
        return "DANGEREUX"
    if score >= seuil_suspect:
        return "SUSPECT"
    return "SÛR"


def raisons_principales(contributions, noms, verdict, n=3):
    """Les n indices qui ont le plus poussé dans le sens du verdict (valeurs SHAP)."""
    serie = pd.Series(contributions, index=noms)
    if verdict == "SÛR":
        top = serie.sort_values().head(n)
        top = top[top < 0]
    else:
        top = serie.sort_values(ascending=False).head(n)
        top = top[top > 0]
    return [{"raison": nom, "contribution": round(float(v), 3)} for nom, v in top.items()]


def nom_lisible(nom, valeur):
    """Décrit un indice avec sa vraie valeur pour ce lien."""
    if nom.startswith("ngram "):
        morceau = nom[len("ngram "):]
        return f"contient le morceau {morceau}" if valeur > 0 else f"ne contient pas le morceau {morceau}"
    if nom in ("a_arobase", "host_est_ip"):
        return NOMS_LISIBLES[nom] + (" : oui" if valeur else " : non")
    v = int(valeur) if float(valeur).is_integer() else round(float(valeur), 2)
    return f"{NOMS_LISIBLES.get(nom, nom)} : {v}"


def ressemble_a_un_lien(texte: str) -> bool:
    t = texte.strip()
    return bool(t) and " " not in t and "." in normaliser(t).split("/")[0]


# ---------------------------------------------------------------- détecteur unifié
class DetecteurUnifie:
    """Une seule entrée (lien ou image de QR code), un seul modèle pour tous les liens."""

    def __init__(self, dossier: Path):
        dossier = Path(dossier)
        self.tfidf = joblib.load(dossier / "unifie_tfidf.joblib")
        self.modele = charger_xgb(dossier, "unifie_xgb")
        self.infos = json.load(open(dossier / "unifie_infos.json", encoding="utf-8"))
        self.seuils = (self.infos["seuil_suspect"], self.infos["seuil_dangereux"])
        self.noms = list(self.infos["features"]) + [f"ngram '{g}'" for g in self.tfidf.get_feature_names_out()]

        # secours : modèle sur les pixels quand le QR code est illisible
        self.modele_pixels = charger_xgb(dossier, "qr_xgb_pixels")
        seuil_px = json.load(open(dossier / "qr_infos.json", encoding="utf-8"))["seuil"]
        self.seuils_pixels = (seuil_px, max(seuil_px, 0.9))
        self.lecteur = cv2.QRCodeDetector()

    # ---------- liens
    def analyser_lien(self, texte: str) -> dict:
        texte = texte.strip()
        if not ressemble_a_un_lien(texte):
            return {"verdict": "INDÉTERMINÉ", "score": None, "modele": None, "raisons": [],
                    "message": "Ce texte ne ressemble pas à un lien web."}

        url = normaliser(texte)
        X = pd.DataFrame([features(url)])[self.infos["features"]]
        Xc = hstack([csr_matrix(X.values.astype(np.float32)), self.tfidf.transform([url])]).tocsr()
        score = float(self.modele.predict_proba(Xc)[0, 1])
        verdict = niveau(score, *self.seuils)

        contrib = self.modele.get_booster().predict(xgb.DMatrix(Xc), pred_contribs=True)[0, :-1]
        raisons = raisons_principales(contrib, self.noms, verdict)
        valeurs = dict(zip(self.noms, Xc.toarray()[0]))
        for r in raisons:
            r["raison"] = nom_lisible(r["raison"], valeurs[r["raison"]])

        return {"verdict": verdict, "score": round(score, 4), "lien_normalise": url,
                "modele": "modèle unifié (liens + QR codes)",
                "seuils": {"suspect": round(self.seuils[0], 3), "dangereux": round(self.seuils[1], 3)},
                "raisons": raisons, "message": "Le lien n'a pas été ouvert : seul son texte a été analysé."}

    # ---------- images
    def _lire(self, gris):
        essais = [gris]
        h, w = gris.shape
        if max(h, w) < 400:
            essais.append(cv2.resize(gris, None, fx=6, fy=6, interpolation=cv2.INTER_NEAREST))
        _, otsu = cv2.threshold(gris, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        essais.append(otsu)
        for img in list(essais):
            essais.append(cv2.copyMakeBorder(img, 40, 40, 40, 40, cv2.BORDER_CONSTANT, value=255))
        for img in essais:
            texte, _, _ = self.lecteur.detectAndDecode(img)
            if texte:
                return texte
        return ""

    @staticmethod
    def _grille_69(gris):
        """Retrouve la grille 69 x 69 (0 = sombre, 1 = clair) si l'image a le format du dataset."""
        _, binaire = cv2.threshold(gris, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        sombres = np.argwhere(binaire == 0)
        if len(sombres) == 0:
            return None
        (y0, x0), (y1, x1) = sombres.min(0), sombres.max(0) + 1
        h, w = y1 - y0, x1 - x0
        if abs(h - w) > 0.03 * max(h, w):
            return None
        k = max(h, w) / 69
        if k < 1 or abs(k - round(k)) > 0.05:
            return None
        grille = cv2.resize(binaire[y0:y1, x0:x1], (69, 69), interpolation=cv2.INTER_NEAREST)
        return (grille > 127).astype(np.int16)

    def analyser_image(self, image_bytes: bytes) -> dict:
        gris = cv2.imdecode(np.frombuffer(image_bytes, np.uint8), cv2.IMREAD_GRAYSCALE)
        if gris is None:
            return {"verdict": "INDÉTERMINÉ", "score": None, "raisons": [],
                    "message": "Le fichier envoyé n'est pas une image lisible."}

        texte = self._lire(gris)
        if texte:
            resultat = self.analyser_lien(texte)
            resultat["contenu_qr"] = texte
            resultat["methode"] = "lien lu dans le QR code"
            if resultat["verdict"] == "INDÉTERMINÉ":
                resultat["message"] = "Le QR code contient du texte qui n'est pas un lien web (par exemple un code Wi-Fi)."
            return resultat

        grille = self._grille_69(gris)
        if grille is not None:
            score = float(self.modele_pixels.predict_proba(grille.reshape(1, -1))[0, 1])
            return {"verdict": niveau(score, *self.seuils_pixels), "score": round(score, 4),
                    "modele": "image du QR code (pixels)", "methode": "QR code illisible : analyse de l'image",
                    "raisons": [], "contenu_qr": None,
                    "message": "Le lien n'a pas pu être lu. Le verdict vient de l'image seule (fiabilité moyenne)."}

        return {"verdict": "INDÉTERMINÉ", "score": None, "raisons": [], "contenu_qr": None,
                "message": "Aucun QR code n'a pu être lu dans cette image. Par prudence, ne le scannez pas."}