"""
Interface web du portail QR-Shield (Streamlit) : une seule zone, un lien OU un QR code.

Lancer depuis la racine du projet (l'API doit déjà tourner) :
    streamlit run app/app.py
Puis ouvrir http://localhost:8501
"""
import os

import requests
import streamlit as st

API = os.environ.get("QRS_API", "http://localhost:8000")
COULEURS = {"SÛR": "#188038", "SUSPECT": "#E37400", "DANGEREUX": "#D93025", "INDÉTERMINÉ": "#5F6368"}

st.set_page_config(page_title="QR-Shield", layout="centered")
st.title("QR-Shield")
st.caption("Groupe 4 · Master MIAC · Machine Learning pour la cybersécurité")
st.write("Collez un lien **ou** ajoutez l'image d'un QR code : le portail indique s'il est sûr ou dangereux, "
         "et pourquoi. **Le lien n'est jamais ouvert.**")


def afficher(resultat: dict):
    verdict = resultat.get("verdict", "INDÉTERMINÉ")
    couleur = COULEURS.get(verdict, "#5F6368")
    score = resultat.get("score")
    texte_score = f" · score {score:.2f}" if score is not None else ""
    st.markdown(
        f"<div style='padding:14px 18px;border-radius:6px;background:{couleur};color:white;"
        f"font-size:22px;font-weight:700'>{verdict}{texte_score}</div>", unsafe_allow_html=True)

    if resultat.get("contenu_qr"):
        st.write("**Contenu du QR code :**")
        st.code(resultat["contenu_qr"], language=None)
    if resultat.get("lien_normalise"):
        st.write(f"**Lien analysé (normalisé) :** `{resultat['lien_normalise']}`")
    if resultat.get("methode"):
        st.write(f"**Méthode :** {resultat['methode']}")

    raisons = resultat.get("raisons") or []
    if raisons:
        st.write("**Pourquoi ?**")
        for r in raisons:
            st.write(f"- {r['raison']} ({r['contribution']:+.2f})")

    details = []
    if resultat.get("modele"):
        details.append(f"modèle : {resultat['modele']}")
    if resultat.get("seuils"):
        s = resultat["seuils"]
        details.append(f"seuils : suspect ≥ {s['suspect']:.3f}, dangereux ≥ {s['dangereux']:.3f}")
    if resultat.get("duree_ms") is not None:
        details.append(f"temps de réponse : {resultat['duree_ms']} ms")
    if details:
        st.caption(" · ".join(details))
    if resultat.get("message"):
        st.info(resultat["message"])


lien = st.text_input("Lien", placeholder="https://exemple.com/connexion  ou  exemple.com/connexion")
st.write("ou")
webcam = st.toggle("Utiliser la webcam")
image = (st.camera_input("Montrez le QR code à la caméra") if webcam
         else st.file_uploader("Image d'un QR code", type=["png", "jpg", "jpeg"]))

if st.button("Analyser", type="primary"):
    if image is None and not lien.strip():
        st.warning("Collez un lien ou ajoutez une image de QR code.")
    else:
        if image is not None:
            if lien.strip():
                st.caption("Un lien et une image ont été fournis : l'image est analysée.")
            st.image(image, width=220)
            envoi = {"files": {"image": (image.name or "qr.png", image.getvalue())}}
        else:
            envoi = {"data": {"lien": lien}}
        try:
            reponse = requests.post(f"{API}/analyser", timeout=60, **envoi)
        except requests.ConnectionError:
            st.error("L'API ne répond pas. Lancez-la d'abord : uvicorn api.main:app --port 8000")
        else:
            if reponse.status_code == 200:
                afficher(reponse.json())
            else:
                st.error(f"Erreur {reponse.status_code} : {reponse.json().get('detail', reponse.text)}")