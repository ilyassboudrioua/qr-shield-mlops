"""
Réentraînement du modèle unifié avec les signalements des utilisateurs (boucle de données MLOps).

Principe « champion / challenger » :
  1. le CHAMPION est le modèle en service (models/unifie_*) ;
  2. on entraîne un CHALLENGER sur les mêmes données + les liens signalés par les utilisateurs ;
  3. les deux sont mesurés sur le MÊME test (jamais utilisé pour l'entraînement) et sur des signalements
     mis de côté ;
  4. le challenger remplace le champion SEULEMENT s'il est au moins aussi bon sur le test et meilleur
     (ou égal) sur les signalements. Sinon le champion reste. Chaque version est archivée (retour arrière possible).

Lancer depuis la racine du projet (données : donnees/unifie.csv, copié depuis le Drive) :
    python scripts/reentrainer.py              # entraînement complet (quelques minutes)
    python scripts/reentrainer.py --rapide     # test rapide du mécanisme (moins d'arbres)
"""
import argparse
import json
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
import xgboost as xgb
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import average_precision_score, recall_score, roc_curve

RACINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RACINE))
from src.detecteurs import charger_xgb, features, normaliser   # noqa: E402
from src.menaces import BaseMenaces                            # noqa: E402

MODELES = RACINE / "models"
VERSIONS = MODELES / "versions"
DONNEES = RACINE / "donnees" / "unifie.csv"
BASE = RACINE / "donnees" / "menaces.db"
POIDS_SIGNALEMENT = 5          # un lien signalé compte comme 5 exemples (c'est une erreur réelle du modèle)
TOLERANCE = 0.002              # baisse de PR-AUC tolérée sur le test


def matrice(urls, tfidf, noms_features):
    simples = pd.DataFrame([features(u) for u in urls])[noms_features].values.astype(np.float32)
    return hstack([csr_matrix(simples), tfidf.transform(urls)]).tocsr()


def seuil_pour(y, proba, budget):
    fpr, tpr, seuils = roc_curve(y, proba)
    i = np.argmax(tpr * (fpr <= budget))
    return float(seuils[i])


def mesurer(nom, modele, tfidf, infos, test, sig_eval):
    p = modele.predict_proba(matrice(test["url"], tfidf, infos["features"]))[:, 1]
    y = test["label"].values
    res = {"modele": nom, "pr_auc_test": average_precision_score(y, p),
           "recall_test_suspect": recall_score(y, p >= infos["seuil_suspect"]),
           "fpr_test_suspect": float(((p >= infos["seuil_suspect"]) & (y == 0)).sum() / (y == 0).sum())}
    if len(sig_eval):
        ps = modele.predict_proba(matrice(sig_eval["url"], tfidf, infos["features"]))[:, 1]
        res["signalements_corrects"] = float(((ps >= infos["seuil_suspect"]).astype(int) == sig_eval["label"].values).mean())
    return res


def main(rapide: bool):
    debut = time.time()
    df = pd.read_csv(DONNEES)
    train, val, test = (df[df["ens"] == e] for e in ["train", "val", "test"])

    # 1. Signalements : 70 % pour apprendre, 30 % mis de côté pour juger
    signal = pd.DataFrame(BaseMenaces(BASE).exemples(), columns=["url", "label"]) if BASE.exists() \
        else pd.DataFrame(columns=["url", "label"])
    signal["url"] = signal["url"].map(normaliser)
    signal = signal[~signal["url"].isin(test["url"]) & ~signal["url"].isin(val["url"])]   # jamais dans val/test
    signal = signal.sample(frac=1, random_state=42)
    coupe = int(len(signal) * 0.7) if len(signal) >= 10 else len(signal)
    sig_train, sig_eval = signal.iloc[:coupe], signal.iloc[coupe:]
    print(f"Signalements utilisables : {len(signal)} (apprentissage {len(sig_train)}, évaluation {len(sig_eval)})")

    # 2. Challenger : mêmes réglages que le notebook 04, données + signalements
    urls = pd.concat([train["url"], sig_train["url"]])
    y = np.concatenate([train["label"].values, sig_train["label"].astype(int).values])
    poids = np.concatenate([np.ones(len(train)), np.full(len(sig_train), POIDS_SIGNALEMENT)])
    tfidf = TfidfVectorizer(analyzer="char", ngram_range=(3, 5), max_features=20000,
                            sublinear_tf=True, dtype=np.float32).fit(urls)
    noms = list(features("exemple.com").keys())
    challenger = xgb.XGBClassifier(n_estimators=60 if rapide else 600, max_depth=8, learning_rate=0.1,
                                   subsample=0.8, colsample_bytree=0.5, tree_method="hist",
                                   n_jobs=-1, random_state=42)
    challenger.fit(matrice(urls, tfidf, noms), y, sample_weight=poids)
    p_val = challenger.predict_proba(matrice(val["url"], tfidf, noms))[:, 1]
    infos_ch = {"modele": "XGBoost unifié (liens collés + liens des QR codes + signalements)",
                "features": noms, "seuil_suspect": seuil_pour(val["label"].values, p_val, 0.05),
                "seuil_dangereux": seuil_pour(val["label"].values, p_val, 0.01),
                "normalisation": "sans schéma, sans www, domaine en minuscules, sans paramètres, sans / final",
                "donnees": f"PhreshPhish 2025 + Quishing Dataset + {len(sig_train)} signalements",
                "sklearn": sklearn.__version__, "xgboost": xgb.__version__}
    print(f"Challenger entraîné en {time.time() - debut:.0f} s")

    # 3. Champion (modèle en service) mesuré sur les mêmes données
    infos_cp = json.load(open(MODELES / "unifie_infos.json", encoding="utf-8"))
    champion = charger_xgb(MODELES, "unifie_xgb")
    tfidf_cp = joblib.load(MODELES / "unifie_tfidf.joblib")
    r_cp = mesurer("champion", champion, tfidf_cp, infos_cp, test, sig_eval)
    r_ch = mesurer("challenger", challenger, tfidf, infos_ch, test, sig_eval)
    print(pd.DataFrame([r_cp, r_ch]).set_index("modele").round(4).to_string())

    # 4. Décision
    ok_test = r_ch["pr_auc_test"] >= r_cp["pr_auc_test"] - TOLERANCE
    ok_sig = r_ch.get("signalements_corrects", 1) >= r_cp.get("signalements_corrects", 1)
    promu = ok_test and ok_sig and not rapide
    version = datetime.now(timezone.utc).strftime("v%Y%m%d-%H%M%S")
    dossier = VERSIONS / ("test-rapide" if rapide else version)
    dossier.mkdir(parents=True, exist_ok=True)
    challenger.save_model(str(dossier / "unifie_xgb.json"))
    joblib.dump(tfidf, dossier / "unifie_tfidf.joblib")
    json.dump(infos_ch, open(dossier / "unifie_infos.json", "w", encoding="utf-8"), indent=2, ensure_ascii=False)

    if promu:
        sauvegarde = VERSIONS / f"{version}-ancien-champion"
        sauvegarde.mkdir(exist_ok=True)
        for f in ["unifie_xgb.json", "unifie_tfidf.joblib", "unifie_infos.json"]:
            shutil.copy2(MODELES / f, sauvegarde / f)
            shutil.copy2(dossier / f, MODELES / f)
    decision = ("PROMU : le challenger remplace le champion" if promu else
                "test rapide : rien n'est remplacé" if rapide else
                "REFUSÉ : le champion reste en service")
    print(f"\nDécision : {decision}")

    historique = MODELES / "historique.json"
    lignes = json.load(open(historique, encoding="utf-8")) if historique.exists() else []
    lignes.append({"version": version, "date": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                   "signalements": len(signal), "champion": r_cp, "challenger": r_ch, "decision": decision})
    json.dump(lignes, open(historique, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    print(f"Historique : {historique}  |  version archivée : {dossier}")
    if promu:
        print("Relancez l'API pour charger le nouveau modèle.")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--rapide", action="store_true", help="test rapide du mécanisme, sans remplacer le modèle")
    main(p.parse_args().rapide)
