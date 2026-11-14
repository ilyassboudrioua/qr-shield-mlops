"""
Page « Surveillance » du portail : l'état du modèle en service (MLOps).
Elle s'ouvre depuis le menu à gauche du portail Streamlit.
"""
import os

import pandas as pd
import requests
import streamlit as st

API = os.environ.get("QRS_API", "http://localhost:8000")
ORDRE = ["OFFICIEL", "SÛR", "SUSPECT", "DANGEREUX", "INDÉTERMINÉ"]
COULEURS = {"OFFICIEL": "#1A73E8", "SÛR": "#188038", "SUSPECT": "#E37400", "DANGEREUX": "#D93025",
            "INDÉTERMINÉ": "#5F6368"}

st.set_page_config(page_title="QR-Shield · Surveillance", layout="wide")
st.title("Surveillance du modèle")
st.caption("Suivi MLOps du modèle en service : volume, verdicts, temps de réponse, signalements et dérive.")

try:
    t = requests.get(f"{API}/surveillance", timeout=20).json()
except requests.RequestException:
    st.error("L'API ne répond pas. Lancez-la d'abord : uvicorn api.main:app --port 8000")
    st.stop()

if not t.get("analyses"):
    st.info("Aucune analyse enregistrée pour l'instant. Faites quelques analyses dans le portail.")
    st.stop()

sig = t["signalements"]
c = st.columns(5)
c[0].metric("Analyses", t["analyses"])
c[1].metric("Alertes récentes", f"{t['part_alertes_recente']:.0%}",
            f"{(t['part_alertes_recente'] - t['part_alertes_globale']) * 100:+.1f} pts vs global", delta_color="off")
c[2].metric("Temps de réponse moyen", f"{t['temps_ms']['moyen']:.0f} ms", f"p95 : {t['temps_ms']['p95']:.0f} ms",
            delta_color="off")
c[3].metric("Signalements", sig.get("signalements", 0))
c[4].metric("Menaces connues", sig.get("menaces_connues", 0))

d = t["derive"]
texte = (f"Dérive des scores (PSI, {d['n_recent']} analyses récentes contre {d['n_reference']} plus anciennes) : "
         f"**{d['etat']}**" + (f" · PSI = {d['psi']}" if d["psi"] is not None else ""))
{"stable": st.success, "dérive modérée": st.warning, "dérive forte": st.error}.get(d["etat"], st.info)(texte)
st.caption("PSI < 0,10 : stable · 0,10 à 0,25 : dérive modérée · > 0,25 : dérive forte, il faut examiner les "
           "nouveaux liens et envisager un réentraînement (scripts/reentrainer.py).")

gauche, droite = st.columns([2, 1])
with gauche:
    st.subheader("Analyses par jour et par verdict")
    jours = pd.DataFrame(t["par_jour"]).T.fillna(0)
    colonnes = [v for v in ORDRE if v in jours.columns]
    st.bar_chart(jours[colonnes], color=[COULEURS[v] for v in colonnes])
with droite:
    st.subheader("Répartition")
    st.write("**Par verdict**")
    st.dataframe(pd.Series(t["par_verdict"], name="analyses").reindex([v for v in ORDRE if v in t["par_verdict"]]))
    st.write("**Par type d'entrée**")
    st.dataframe(pd.Series(t["par_entree"], name="analyses"))

st.subheader("Signalements des utilisateurs")
e = sig.get("erreurs_signalees", {})
s1, s2, s3 = st.columns(3)
s1.metric("Phishing ratés signalés", e.get("phishing_rates", 0))
s2.metric("Fausses alertes signalées", e.get("fausses_alertes", 0))
s3.metric("Avis « phishing » / « sûr »",
          f"{sig.get('par_avis', {}).get('phishing', 0)} / {sig.get('par_avis', {}).get('sur', 0)}")
