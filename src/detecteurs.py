"""
Détecteurs du portail QR-Shield (liens et QR codes).

Chaque détecteur charge un modèle entraîné dans les notebooks (dossier models/)
et renvoie un verdict : SÛR, SUSPECT, DANGEREUX ou INDÉTERMINÉ, avec un score et des raisons.
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
    "a_arobase": "présence de « @ »",
    "host_est_ip": "adresse IP à la place du nom",
    "https": "connexion HTTPS",
    "entropie": "désordre des caractères (entropie)",
    "nb_mots_suspects": "mots suspects (login, verify…)",
}


# ---------------------------------------------------------------- chargement des modèles
def charger_xgb(dossier: Path, nom: str):
    """Charge un modèle XGBoost au format natif (.json), portable entre Linux et Windows."""
    modele = xgb.XGBClassifier()
    modele.load_model(str(dossier / f"{nom}.json"))
    return modele


# ---------------------------------------------------------------- outils communs
def entropie(texte):
    if not texte:
        return 0.0
    freq = Counter(texte)
    return -sum((n / len(texte)) * math.log2(n / len(texte)) for n in freq.values())


def features_url(url):
    """Les mêmes features que dans le notebook 01 (module liens)."""
    p = urlparse(url)
    host = p.hostname or ""
    return {
        "longueur_url": len(url),
        "longueur_host": len(host),
        "longueur_chemin": len(p.path),
        "nb_points": url.count("."),
        "nb_tirets": url.count("-"),
        "nb_chiffres": sum(c.isdigit() for c in url),
        "nb_sous_domaines": max(host.count(".") - 1, 0),
        "a_arobase": int("@" in url),
        "host_est_ip": int(bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host))),
        "https": int(p.scheme == "https"),
        "nb_parametres": len(p.query.split("&")) if p.query else 0,
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
    """Les n features qui ont le plus poussé dans le sens du verdict (valeurs SHAP)."""
    serie = pd.Series(contributions, index=noms)
    if verdict == "SÛR":
        top = serie.sort_values().head(n)
        top = top[top < 0]
    else:
        top = serie.sort_values(ascending=False).head(n)
        top = top[top > 0]
    return [{"raison": nom, "contribution": round(float(v), 3)} for nom, v in top.items()]


def nom_lisible(nom, valeur):
    """Décrit une feature avec sa vraie valeur pour ce lien (présence ou absence d'un morceau, valeur numérique)."""
    if nom.startswith("ngram "):
        morceau = nom[len("ngram "):]
        if valeur > 0:
            return f"contient le morceau {morceau}"
        texte = f"ne contient pas le morceau {morceau}"
        if morceau.strip("'") in ("ps:", "tps", "ttps", "tps:", "ttps:", "s:/", "s://"):
            texte += " (pas de HTTPS)"
        return texte
    if nom == "https":
        return "connexion HTTPS" if valeur else "pas de connexion HTTPS"
    if nom in ("a_arobase", "host_est_ip"):
        return NOMS_LISIBLES[nom] + (" : oui" if valeur else " : non")
    v = int(valeur) if float(valeur).is_integer() else round(float(valeur), 2)
    return f"{NOMS_LISIBLES.get(nom, nom)} : {v}"


# ---------------------------------------------------------------- module liens
class DetecteurLiens:
    """Deux modèles :
    - liens complets (avec http/https) : modèle v2 entraîné sur PhreshPhish (2024-2025) ;
    - liens sans http/https : modèle entraîné sur les liens décodés des QR codes.
    """

    def __init__(self, dossier: Path):
        self.tfidf = joblib.load(dossier / "links_tfidf_v2.joblib")
        self.modele = charger_xgb(dossier, "links_xgb_v2")
        self.infos = json.load(open(dossier / "links_infos_v2.json", encoding="utf-8"))
        self.seuils = (self.infos["seuil"], 0.5)

        self.tfidf_sans = joblib.load(dossier / "qr_tfidf.joblib")
        self.modele_sans = charger_xgb(dossier, "qr_xgb_lien")
        self.infos_qr = json.load(open(dossier / "qr_infos.json", encoding="utf-8"))
        self.seuils_sans = (self.infos_qr["seuil"], max(self.infos_qr["seuil"], 0.9))

    @staticmethod
    def _sans_parametres(url):
        return url.split("?")[0].split("#")[0]

    def analyser(self, url: str) -> dict:
        url = url.strip()
        if not url or " " in url or "." not in url:
            return {"verdict": "INDÉTERMINÉ", "score": None, "modele": None, "raisons": [],
                    "message": "Ce texte ne ressemble pas à un lien web."}

        complet = url.lower().startswith(("http://", "https://"))
        if complet:
            propre = self._sans_parametres(url)
            noms_feat = self.infos["features"]
            X = pd.DataFrame([features_url(propre)])[noms_feat]
            tfidf, modele, seuils = self.tfidf, self.modele, self.seuils
            nom_modele = "liens (PhreshPhish 2024-2025)"
            texte = propre
        else:
            texte = url  # ce modèle a été entraîné sur les liens complets, paramètres compris
            noms_feat = self.infos_qr["features_lien"]
            X = pd.DataFrame([features_url("http://" + texte)])[noms_feat]
            tfidf, modele, seuils = self.tfidf_sans, self.modele_sans, self.seuils_sans
            nom_modele = "liens sans http (QR codes)"

        Xc = hstack([csr_matrix(X.values.astype(float)), tfidf.transform([texte])]).tocsr()
        score = float(modele.predict_proba(Xc)[0, 1])
        verdict = niveau(score, *seuils)

        contrib = modele.get_booster().predict(xgb.DMatrix(Xc), pred_contribs=True)[0, :-1]
        noms = list(noms_feat) + [f"ngram '{g}'" for g in tfidf.get_feature_names_out()]
        raisons = raisons_principales(contrib, noms, verdict)
        valeurs = dict(zip(noms, Xc.toarray()[0]))
        for r in raisons:
            r["raison"] = nom_lisible(r["raison"], valeurs[r["raison"]])

        return {"verdict": verdict, "score": round(score, 4), "modele": nom_modele,
                "seuils": {"suspect": seuils[0], "dangereux": seuils[1]},
                "raisons": raisons, "message": "Le lien n'a pas été ouvert : seul son texte a été analysé."}


# ---------------------------------------------------------------- module QR codes
class DetecteurQR:
    """1. Lire le QR code (OpenCV). 2. Si un lien est lu : modèle des liens.
    3. Sinon, si l'image a le format du dataset (69 x 69 modules) : modèle sur les pixels."""

    def __init__(self, dossier: Path, liens: DetecteurLiens):
        self.liens = liens
        self.modele_pixels = charger_xgb(dossier, "qr_xgb_pixels")
        self.infos = json.load(open(dossier / "qr_infos.json", encoding="utf-8"))
        self.lecteur = cv2.QRCodeDetector()

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
        zone = binaire[y0:y1, x0:x1]
        grille = cv2.resize(zone, (69, 69), interpolation=cv2.INTER_NEAREST)
        return (grille > 127).astype(np.int16)

    def analyser(self, image_bytes: bytes) -> dict:
        tableau = np.frombuffer(image_bytes, np.uint8)
        gris = cv2.imdecode(tableau, cv2.IMREAD_GRAYSCALE)
        if gris is None:
            return {"verdict": "INDÉTERMINÉ", "score": None, "raisons": [],
                    "message": "Le fichier envoyé n'est pas une image lisible."}

        texte = self._lire(gris)
        if texte:
            resultat = self.liens.analyser(texte)
            resultat["contenu_qr"] = texte
            resultat["methode"] = "lien caché lu dans le QR code"
            if resultat["verdict"] == "INDÉTERMINÉ":
                resultat["message"] = "Le QR code contient du texte qui n'est pas un lien web (par exemple un code Wi-Fi)."
            return resultat

        grille = self._grille_69(gris)
        if grille is not None:
            score = float(self.modele_pixels.predict_proba(grille.reshape(1, -1))[0, 1])
            seuil = self.infos["seuil"]
            return {"verdict": niveau(score, seuil, max(seuil, 0.9)), "score": round(score, 4),
                    "modele": "image du QR code (pixels)", "methode": "QR code illisible : analyse de l'image",
                    "raisons": [], "contenu_qr": None,
                    "message": "Le lien n'a pas pu être lu. Le verdict vient de l'image seule (fiabilité moyenne)."}

        return {"verdict": "INDÉTERMINÉ", "score": None, "raisons": [], "contenu_qr": None,
                "message": "Aucun QR code n'a pu être lu dans cette image. Par prudence, ne le scannez pas."}