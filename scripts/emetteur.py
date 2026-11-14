"""
Outil de l'émetteur officiel (entreprise, mairie, banque...) : créer ses clés et signer ses QR codes.

Principe (signature numérique Ed25519) :
- l'émetteur garde une CLÉ PRIVÉE secrète : lui seul peut signer ;
- sa CLÉ PUBLIQUE est publiée dans le registre (registre/emetteurs.json) : tout le monde peut vérifier ;
- la signature est ajoutée à la fin du lien, après « #qrs= » : le lien reste utilisable par n'importe quel
  scanner (la partie après # n'est jamais envoyée au site).

Exemples, depuis la racine du projet :
    python scripts/emetteur.py creer --id mairie-demo --nom "Mairie de Démo" --domaine mairie-demo.ma
    python scripts/emetteur.py signer --id mairie-demo --lien https://mairie-demo.ma/paiement --sortie qr_officiel.png
"""
import argparse
import base64
import json
from pathlib import Path

import qrcode
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

RACINE = Path(__file__).resolve().parent.parent
REGISTRE = RACINE / "registre" / "emetteurs.json"
CLES = RACINE / "cles_privees"          # dossier secret, jamais envoyé sur GitHub
PREFIXE = "#qrs="


def b64(octets: bytes) -> str:
    return base64.urlsafe_b64encode(octets).decode().rstrip("=")


def charger_registre() -> dict:
    return json.loads(REGISTRE.read_text(encoding="utf-8")) if REGISTRE.exists() else {}


def creer(id_emetteur: str, nom: str, domaines: list):
    CLES.mkdir(exist_ok=True)
    REGISTRE.parent.mkdir(exist_ok=True)
    fichier_cle = CLES / f"{id_emetteur}.pem"
    if fichier_cle.exists():
        raise SystemExit(f"La clé de {id_emetteur} existe déjà : {fichier_cle}")

    cle_privee = Ed25519PrivateKey.generate()
    fichier_cle.write_bytes(cle_privee.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    cle_publique = cle_privee.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    registre = charger_registre()
    registre[id_emetteur] = {"nom": nom, "domaines": [d.lower() for d in domaines],
                             "cle_publique": b64(cle_publique)}
    REGISTRE.write_text(json.dumps(registre, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Clé privée (SECRÈTE) : {fichier_cle}")
    print(f"Clé publique ajoutée au registre : {REGISTRE}")


def signer(id_emetteur: str, lien: str, sortie: str):
    lien = lien.split("#")[0]                       # on signe le lien sans fragment
    cle_privee = serialization.load_pem_private_key((CLES / f"{id_emetteur}.pem").read_bytes(), None)
    signature = cle_privee.sign(lien.encode("utf-8"))
    contenu = f"{lien}{PREFIXE}{id_emetteur}.{b64(signature)}"
    qrcode.make(contenu, error_correction=qrcode.constants.ERROR_CORRECT_M).save(sortie)
    print(f"Contenu du QR code : {contenu}")
    print(f"Image enregistrée : {sortie}")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Outil de l'émetteur : créer des clés, signer des QR codes.")
    sous = p.add_subparsers(dest="action", required=True)
    c = sous.add_parser("creer", help="créer un émetteur (clé privée + entrée dans le registre)")
    c.add_argument("--id", required=True)
    c.add_argument("--nom", required=True)
    c.add_argument("--domaine", action="append", required=True, help="domaine autorisé (répéter si plusieurs)")
    s = sous.add_parser("signer", help="signer un lien et produire l'image du QR code")
    s.add_argument("--id", required=True)
    s.add_argument("--lien", required=True)
    s.add_argument("--sortie", default="qr_officiel.png")
    a = p.parse_args()
    if a.action == "creer":
        creer(a.id, a.nom, a.domaine)
    else:
        signer(a.id, a.lien, a.sortie)