"""
Bot Telegram de QR-Shield : on lui envoie un lien ou la photo d'un QR code, il répond avec le verdict.

Le bot ne fait aucune analyse lui-même : il transmet à l'API du portail (route /analyser), comme l'interface
web. Un seul modèle, une seule logique, plusieurs canaux (web, Telegram).
Vie privée : le bot ne garde ni le nom, ni le numéro, ni l'identifiant Telegram de l'utilisateur.

Lancer depuis la racine du projet (l'API doit déjà tourner) :
    set QRS_TELEGRAM_TOKEN=le_jeton_donné_par_BotFather        (Windows)
    python bot/bot_telegram.py
"""
import html
import os
import re
import secrets

import requests
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import (Application, CallbackQueryHandler, CommandHandler, ContextTypes,
                          MessageHandler, filters)

API = os.environ.get("QRS_API", "http://localhost:8000")
JETON = os.environ.get("QRS_TELEGRAM_TOKEN", "")
LIEN = re.compile(r"(https?://\S+|(?:[\w-]+\.)+[a-zA-Z]{2,}(?:/\S*)?)")
PASTILLE = {"OFFICIEL": "[OFFICIEL]", "SÛR": "[SÛR]", "SUSPECT": "[SUSPECT]",
            "DANGEREUX": "[DANGEREUX]", "INDÉTERMINÉ": "[INDÉTERMINÉ]"}
CONSEIL = {
    "OFFICIEL": "QR code officiel vérifié par signature numérique.",
    "SÛR": "Aucun signe de phishing détecté. Restez quand même attentif à ce qu'on vous demande.",
    "SUSPECT": "Prudence : n'entrez ni mot de passe, ni code, ni carte bancaire sur ce site.",
    "DANGEREUX": "N'ouvrez pas ce lien et ne scannez pas ce QR code.",
    "INDÉTERMINÉ": "Impossible de conclure. Par prudence, ne l'ouvrez pas.",
}


def formater(r: dict) -> str:
    """Texte de la réponse. Les liens sont écrits en <code> : Telegram ne les rend PAS cliquables,
    pour que l'utilisateur ne puisse pas ouvrir un lien de phishing par erreur depuis le bot."""
    e = html.escape
    verdict = r.get("verdict", "INDÉTERMINÉ")
    lignes = [f"<b>{PASTILLE.get(verdict, verdict)}</b>" + (f"  score {r['score']:.2f}" if r.get("score") is not None else "")]
    if r.get("emetteur"):
        lignes.append(f"Émetteur vérifié : {e(r['emetteur'])}")
    if r.get("contenu_qr"):
        lignes.append(f"Contenu du QR code : <code>{e(r['contenu_qr'][:200])}</code>")
    if r.get("lien_normalise"):
        lignes.append(f"Lien analysé : <code>{e(r['lien_normalise'])}</code>")
    raisons = r.get("raisons") or []
    if raisons:
        lignes.append("\nPourquoi :")
        lignes += [f"- {e(x['raison'])}" for x in raisons[:4]]
    lignes.append("\n" + CONSEIL.get(verdict, ""))
    if r.get("message") and verdict != "OFFICIEL":
        lignes.append(e(r["message"]))
    return "\n".join(lignes)


def boutons(context: ContextTypes.DEFAULT_TYPE, r: dict):
    """Boutons « Signaler » (le lien est gardé en mémoire du bot, le temps de la conversation)."""
    if not r.get("lien_normalise") or r.get("verdict") == "OFFICIEL":
        return None
    cle = secrets.token_hex(4)
    context.bot_data[cle] = {"lien": r["lien_normalise"], "verdict": r.get("verdict"), "score": r.get("score")}
    return InlineKeyboardMarkup([[InlineKeyboardButton("Signaler : phishing", callback_data=f"p:{cle}"),
                                  InlineKeyboardButton("Signaler : site sûr", callback_data=f"s:{cle}")]])


def appeler_api(**envoi) -> dict:
    reponse = requests.post(f"{API}/analyser", timeout=60, **envoi)
    reponse.raise_for_status()
    return reponse.json()


async def demarrer(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Bonjour, je suis QR-Shield.\n\n"
        "Envoyez-moi un lien ou la photo d'un QR code : je vous dis s'il est sûr ou dangereux, et pourquoi.\n"
        "Je n'ouvre jamais le lien.")


async def texte(update: Update, context: ContextTypes.DEFAULT_TYPE):
    trouve = LIEN.search(update.message.text or "")
    if not trouve:
        await update.message.reply_text("Je n'ai pas trouvé de lien dans votre message. Envoyez un lien ou une photo de QR code.")
        return
    try:
        r = appeler_api(data={"lien": trouve.group(0)})
    except requests.RequestException:
        await update.message.reply_text("Le service d'analyse ne répond pas. Réessayez dans un instant.")
        return
    await update.message.reply_text(formater(r), reply_markup=boutons(context, r), parse_mode="HTML",
                                    disable_web_page_preview=True)


async def photo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    fichier = update.message.photo[-1] if update.message.photo else update.message.document
    contenu = bytes(await (await fichier.get_file()).download_as_bytearray())
    try:
        r = appeler_api(files={"image": ("qr.jpg", contenu)})
    except requests.RequestException:
        await update.message.reply_text("Le service d'analyse ne répond pas. Réessayez dans un instant.")
        return
    await update.message.reply_text(formater(r), reply_markup=boutons(context, r), parse_mode="HTML",
                                    disable_web_page_preview=True)


async def signalement(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    avis, cle = q.data.split(":", 1)
    info = context.bot_data.pop(cle, None)
    if info is None:
        await q.answer("Ce signalement a déjà été envoyé.")
        return
    try:
        etat = requests.post(f"{API}/signaler", timeout=20, json={
            "lien": info["lien"], "avis": "phishing" if avis == "p" else "sur",
            "verdict_portail": info["verdict"], "score": info["score"], "canal": "telegram"}).json()
        await q.answer("Merci, signalement enregistré.")
        await q.edit_message_reply_markup(None)
        await q.message.reply_text(f"Merci. Ce lien a été signalé {etat['phishing']} fois comme phishing "
                                   f"et {etat['sur']} fois comme sûr.")
    except requests.RequestException:
        await q.answer("Le signalement n'a pas pu être envoyé.")


def main():
    if not JETON:
        raise SystemExit("Jeton manquant : faites d'abord  set QRS_TELEGRAM_TOKEN=...  (jeton donné par BotFather).")
    app = Application.builder().token(JETON).build()
    app.add_handler(CommandHandler("start", demarrer))
    app.add_handler(MessageHandler(filters.PHOTO | filters.Document.IMAGE, photo))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, texte))
    app.add_handler(CallbackQueryHandler(signalement))
    print("Bot QR-Shield démarré. Ctrl + C pour arrêter.")
    app.run_polling()


if __name__ == "__main__":
    main()
