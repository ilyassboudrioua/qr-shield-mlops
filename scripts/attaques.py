"""
Tests d'attaque contre les QR codes signés (simulation, aucun site réel n'est visé).

À partir d'un vrai QR code officiel, on fabrique 4 QR codes comme le ferait un pirate :
  1. autocollant : le pirate garde la signature officielle mais remplace le lien par le sien ;
  2. signature_abimee : la signature est modifiée de quelques caractères ;
  3. fausse_cle : le pirate signe son lien avec SA propre clé et prétend être la mairie ;
  4. emetteur_inconnu : le pirate invente un émetteur qui n'est pas dans le registre.

Lancer depuis la racine du projet :
    python scripts/attaques.py qr_officiel.png
Les images sont créées dans le dossier attaques/.
"""
import base64
import sys
from pathlib import Path

import cv2
import qrcode
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

FAUX_LIEN = "https://mairie-dem0-paiement.top/payer"     # domaine inventé, il n'existe pas


def b64(octets: bytes) -> str:
    return base64.urlsafe_b64encode(octets).decode().rstrip("=")


def lire(image: str) -> str:
    texte = cv2.QRCodeDetector().detectAndDecode(cv2.imread(image))[0]
    if "#qrs=" not in texte:
        raise SystemExit("Cette image ne contient pas de QR code signé.")
    return texte


if __name__ == "__main__":
    officiel = lire(sys.argv[1] if len(sys.argv) > 1 else "qr_officiel.png")
    lien, signe = officiel.split("#qrs=")
    id_emetteur, signature = signe.split(".", 1)
    cle_pirate = Ed25519PrivateKey.generate()

    attaques = {
        "1_autocollant": f"{FAUX_LIEN}#qrs={id_emetteur}.{signature}",
        "2_signature_abimee": f"{lien}#qrs={id_emetteur}.{signature[:-4]}AAAA",
        "3_fausse_cle": f"{FAUX_LIEN}#qrs={id_emetteur}.{b64(cle_pirate.sign(FAUX_LIEN.encode()))}",
        "4_emetteur_inconnu": f"{FAUX_LIEN}#qrs=mairie-officielle.{b64(cle_pirate.sign(FAUX_LIEN.encode()))}",
    }
    Path("attaques").mkdir(exist_ok=True)
    for nom, contenu in attaques.items():
        qrcode.make(contenu).save(f"attaques/{nom}.png")
        print(f"attaques/{nom}.png  ->  {contenu[:70]}...")
