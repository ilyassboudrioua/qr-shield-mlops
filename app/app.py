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
COULEURS = {"OFFICIEL": "#1A73E8", "SÛR": "#188038", "SUSPECT": "#E37400", "DANGEREUX": "#D93025", "INDÉTERMINÉ": "#5F6368"}

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

    if resultat.get("emetteur"):
        st.success(f"Émetteur officiel vérifié : {resultat['emetteur']}")
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
            c = r.get("contribution")
            st.write(f"- {r['raison']}" + (f" ({c:+.2f})" if c is not None else f" ({r.get('origine', 'règle')})"))

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


def signaler(resultat: dict, avis: str):
    try:
        r = requests.post(f"{API}/signaler", timeout=20, json={
            "lien": resultat["lien_normalise"], "avis": avis,
            "verdict_portail": resultat.get("verdict"), "score": resultat.get("score")})
        r.raise_for_status()
        etat = r.json()
        st.session_state["merci"] = (f"Merci, signalement enregistré. Ce lien a été signalé {etat['phishing']} fois "
                                     f"comme phishing et {etat['sur']} fois comme sûr.")
    except requests.RequestException:
        st.session_state["merci"] = "Le signalement n'a pas pu être envoyé (API indisponible)."


lien = st.text_input("Lien", placeholder="https://exemple.com/connexion  ou  exemple.com/connexion")
st.write("ou")
webcam = st.toggle("Utiliser la webcam")
image = (st.camera_input("Montrez le QR code à la caméra") if webcam
         else st.file_uploader("Image d'un QR code", type=["png", "jpg", "jpeg"]))

if st.button("Analyser", type="primary"):
    st.session_state.pop("resultat", None)
    st.session_state.pop("merci", None)
    if image is None and not lien.strip():
        st.warning("Collez un lien ou ajoutez une image de QR code.")
    else:
        if image is not None:
            if lien.strip():
                st.caption("Un lien et une image ont été fournis : l'image est analysée.")
            envoi = {"files": {"image": (image.name or "qr.png", image.getvalue())}}
        else:
            envoi = {"data": {"lien": lien}}
        try:
            reponse = requests.post(f"{API}/analyser", timeout=60, **envoi)
        except requests.ConnectionError:
            st.error("L'API ne répond pas. Lancez-la d'abord : uvicorn api.main:app --port 8000")
        else:
            if reponse.status_code == 200:
                st.session_state["resultat"] = reponse.json()
            else:
                st.error(f"Erreur {reponse.status_code} : {reponse.json().get('detail', reponse.text)}")

# le résultat reste affiché après un clic sur « Signaler » (Streamlit relance la page à chaque clic)
resultat = st.session_state.get("resultat")
if resultat:
    if image is not None:
        st.image(image, width=220)
    afficher(resultat)
    if resultat.get("lien_normalise") and resultat.get("verdict") != "OFFICIEL":
        st.write("**Le portail s'est trompé ?** Votre signalement aide à améliorer le modèle.")
        c1, c2 = st.columns(2)
        if c1.button("Signaler : c'est du phishing"):
            signaler(resultat, "phishing")
        if c2.button("Signaler : c'est un site sûr"):
            signaler(resultat, "sur")
    if st.session_state.get("merci"):
        st.success(st.session_state["merci"])
