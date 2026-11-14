"""
Surveillance du modèle en service (MLOps) à partir du journal logs/predictions.jsonl.

Dérive (hypothèse H3) : on compare la distribution des scores des analyses récentes à celle des
analyses plus anciennes avec le PSI (Population Stability Index), l'indicateur utilisé en banque et en ML :
  PSI < 0,10 : stable · 0,10 à 0,25 : dérive modérée · > 0,25 : dérive forte (à examiner, réentraîner ?)
"""
import json
from pathlib import Path

import numpy as np
import pandas as pd

FENETRE_RECENTE = 50      # les 50 dernières analyses
MINIMUM = 30              # analyses nécessaires de chaque côté pour calculer la dérive


def psi(reference, recent, nb_classes=10):
    bornes = np.linspace(0, 1, nb_classes + 1)
    ref = np.histogram(reference, bornes)[0] / len(reference)
    rec = np.histogram(recent, bornes)[0] / len(recent)
    ref, rec = np.clip(ref, 1e-4, None), np.clip(rec, 1e-4, None)
    return float(np.sum((rec - ref) * np.log(rec / ref)))


def tableau_de_bord(fichier_journal: Path, stats_signalements: dict) -> dict:
    fichier_journal = Path(fichier_journal)
    if not fichier_journal.exists():
        return {"analyses": 0, "signalements": stats_signalements}
    lignes = [json.loads(l) for l in fichier_journal.read_text(encoding="utf-8").splitlines() if l.strip()]
    df = pd.DataFrame(lignes)
    if df.empty:
        return {"analyses": 0, "signalements": stats_signalements}
    df["jour"] = pd.to_datetime(df["date"]).dt.strftime("%Y-%m-%d")
    entree = df["entree"] if "entree" in df else df.get("route", pd.Series(["lien"] * len(df)))

    par_jour = df.groupby(["jour", "verdict"]).size().unstack(fill_value=0)
    scores = df["score"].dropna().astype(float)
    derive = {"etat": "pas assez de données", "psi": None,
              "n_reference": max(len(scores) - FENETRE_RECENTE, 0), "n_recent": min(len(scores), FENETRE_RECENTE)}
    if len(scores) >= FENETRE_RECENTE + MINIMUM:
        valeur = psi(scores.iloc[:-FENETRE_RECENTE], scores.iloc[-FENETRE_RECENTE:])
        derive.update(psi=round(valeur, 3), etat="stable" if valeur < 0.10 else
                      "dérive modérée" if valeur < 0.25 else "dérive forte")

    return {
        "analyses": int(len(df)),
        "par_verdict": df["verdict"].value_counts().to_dict(),
        "par_entree": entree.value_counts().to_dict(),
        "par_jour": {j: {k: int(v) for k, v in ligne.items()} for j, ligne in par_jour.iterrows()},
        "temps_ms": {"moyen": round(float(df["duree_ms"].mean()), 1),
                     "p95": round(float(df["duree_ms"].quantile(0.95)), 1),
                     "max": round(float(df["duree_ms"].max()), 1)},
        "part_alertes_recente": round(float(df["verdict"].tail(FENETRE_RECENTE).isin(["SUSPECT", "DANGEREUX"]).mean()), 3),
        "part_alertes_globale": round(float(df["verdict"].isin(["SUSPECT", "DANGEREUX"]).mean()), 3),
        "derive": derive,
        "signalements": stats_signalements,
    }
