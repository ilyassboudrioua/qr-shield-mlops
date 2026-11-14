"""
Enquête sur le domaine, sans jamais ouvrir le site.

Partie 1 (hors ligne) : imitation de marques connues, internationales et marocaines.
  - la marque apparaît dans un domaine qui n'est pas le sien  (paypal-secure-login.top)
  - faute de frappe volontaire, ou typosquatting              (paypa1.com, attijariwafabnk.com)
  - lettres déguisées, ou homoglyphes                         (pаypal.com avec un « а » cyrillique)
"""
import unicodedata

import tldextract

EXTRACTEUR = tldextract.TLDExtract(suffix_list_urls=())   # liste des suffixes embarquée, sans réseau

# marque -> domaines officiels (domaine enregistré, sans sous-domaine)
MARQUES = {
    # Maroc
    "attijariwafa": ["attijariwafabank.com"],
    "cihbank": ["cihbank.ma"],
    "bankofafrica": ["bankofafrica.ma"],
    "barid": ["barid.ma"],
    "cashplus": ["cashplus.ma"],
    "iam": ["iam.ma"],
    "inwi": ["inwi.ma"],
    "jumia": ["jumia.ma", "jumia.com"],
    "cnss": ["cnss.ma"],
    "oncf": ["oncf.ma"],
    "royalairmaroc": ["royalairmaroc.com"],
    # international
    "paypal": ["paypal.com", "paypal.me"],
    "google": ["google.com", "google.fr", "google.co.ma", "gmail.com", "youtube.com"],
    "microsoft": ["microsoft.com", "live.com", "outlook.com", "office.com", "microsoftonline.com"],
    "outlook": ["outlook.com", "live.com", "office.com", "microsoft.com"],
    "office365": ["office.com", "microsoft.com", "microsoftonline.com"],
    "apple": ["apple.com", "icloud.com"],
    "icloud": ["icloud.com", "apple.com"],
    "amazon": ["amazon.com", "amazon.fr", "amazon.de", "amazon.co.uk"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "fb.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com"],
    "linkedin": ["linkedin.com"],
    "dhl": ["dhl.com", "dhl.fr"],
    "fedex": ["fedex.com"],
    "binance": ["binance.com"],
    "coinbase": ["coinbase.com"],
}
COURTES = {m for m in MARQUES if len(m) < 5}   # dhl, iam, inwi, cnss, oncf : seulement en mot entier

# mots « appâts » qu'on colle souvent à une marque : paypalsecure, amazonlogin, cihbankverify...
APPATS = ["secure", "security", "login", "logon", "signin", "verify", "verification", "account", "update",
          "support", "service", "services", "help", "online", "auth", "confirm", "billing", "pay", "payment",
          "bank", "client", "clients", "app", "mobile", "web", "portal", "alert", "recharge", "livraison",
          "colis", "delivery", "track", "tracking", "id", "ma", "fr", "official", "officiel", "maroc", "team"]

# lettres qui se ressemblent -> lettre latine (cyrillique, grec, chiffres « leet »)
SOSIES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j",
    "ѕ": "s", "ԁ": "d", "ɡ": "g", "ո": "n", "ս": "u", "ⅼ": "l",
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "τ": "t", "ι": "i", "κ": "k",
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s",
})


def squelette(texte: str) -> str:
    """Forme « visuelle » d'un texte : lettres déguisées remplacées, accents retirés."""
    t = unicodedata.normalize("NFKD", texte.lower())
    t = "".join(c for c in t if not unicodedata.combining(c))
    t = t.translate(SOSIES)
    return t.replace("rn", "m").replace("vv", "w")


def distance(a: str, b: str) -> int:
    """Distance de Damerau-Levenshtein : nombre de fautes (ajout, oubli, remplacement, inversion)."""
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cout = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cout)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def que_des_appats(reste: str) -> bool:
    """Vrai si le reste du mot est vide, des chiffres, ou une suite de mots appâts (ex. « secure » + « login »)."""
    reste = reste.strip("0123456789")
    if not reste:
        return True
    ok = [True] + [False] * len(reste)
    for i in range(1, len(reste) + 1):
        ok[i] = any(ok[i - len(m)] and reste[i - len(m):i] == m for m in APPATS if len(m) <= i)
    return ok[-1]


def cibles(marque: str) -> set:
    """Les formes à comparer : le nom de la marque et le nom de ses domaines officiels (attijariwafabank...)."""
    return {marque} | {EXTRACTEUR(d).domain for d in MARQUES[marque]}


def decoder_punycode(hote: str) -> str:
    try:
        return hote.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        return hote


def imitation_de_marque(hote: str) -> list:
    """Renvoie la liste des alertes d'imitation pour un nom d'hôte (vide si rien de suspect)."""
    hote = hote.lower().strip(".")
    alertes = []
    if "xn--" in hote or any(ord(c) > 127 for c in hote):
        alertes.append({"type": "punycode", "marque": None,
                        "detail": f"nom de domaine écrit avec des caractères spéciaux ({decoder_punycode(hote)})"})
    lisible = decoder_punycode(hote)
    ext = EXTRACTEUR(lisible)
    enregistre = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    mots = [m for m in (ext.subdomain + "." + ext.domain).replace("-", ".").replace("_", ".").split(".") if m]
    colle = (ext.subdomain + ext.domain).replace(".", "").replace("-", "")

    for marque, officiels in MARQUES.items():
        if enregistre in officiels:
            return []                                     # c'est le vrai site de la marque
    for marque, officiels in MARQUES.items():
        for mot in mots + [colle]:
            sq = squelette(mot)
            if mot == marque or (marque not in COURTES and marque in mot
                                 and que_des_appats(mot.replace(marque, "", 1))):
                alertes.append({"type": "marque_detournee", "marque": marque,
                                "detail": f"utilise le nom « {marque} » sans être son site officiel ({officiels[0]})"})
                break
            if sq != mot and (sq == marque or (marque not in COURTES and marque in sq
                                               and que_des_appats(sq.replace(marque, "", 1)))):
                alertes.append({"type": "homoglyphe", "marque": marque,
                                "detail": f"« {mot} » imite « {marque} » avec des lettres déguisées"})
                break
            if marque not in COURTES and any(
                    abs(len(sq) - len(c)) <= 2 and 0 < distance(sq, c) <= (1 if len(c) < 8 else 2)
                    for c in cibles(marque)):
                alertes.append({"type": "typosquatting", "marque": marque,
                                "detail": f"« {mot} » ressemble à « {marque} » (faute de frappe volontaire)"})
                break
    return alertes
