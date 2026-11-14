"""
Base de menaces du portail QR-Shield (SQLite) : les signalements des utilisateurs.

- Chaque signalement garde seulement le lien NORMALISÉ (sans paramètres, donc sans identifiants
  personnels), son empreinte, l'avis de l'utilisateur et le verdict du portail. Aucune adresse IP,
  aucun nom, aucun compte (principe de minimisation, loi 09-08 / CNDP).
- Effet immédiat : un lien signalé plusieurs fois comme phishing devient une MENACE CONNUE.
- Effet à long terme : les signalements servent d'exemples pour réentraîner le modèle (scripts/reentrainer.py).
"""
import hashlib
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

SEUIL_MENACE = 2          # nombre de signalements « phishing » pour devenir une menace connue


class BaseMenaces:
    def __init__(self, fichier: Path):
        fichier = Path(fichier)
        fichier.parent.mkdir(parents=True, exist_ok=True)
        self.fichier = fichier
        with self._connexion() as c:
            c.execute("""CREATE TABLE IF NOT EXISTS signalements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT NOT NULL,
                empreinte TEXT NOT NULL,
                lien_normalise TEXT NOT NULL,
                avis TEXT NOT NULL CHECK (avis IN ('phishing', 'sur')),
                verdict_portail TEXT,
                score REAL,
                canal TEXT DEFAULT 'portail')""")
            c.execute("CREATE INDEX IF NOT EXISTS idx_empreinte ON signalements(empreinte)")

    def _connexion(self):
        return sqlite3.connect(self.fichier)

    @staticmethod
    def empreinte(lien_normalise: str) -> str:
        return hashlib.sha256(lien_normalise.encode("utf-8")).hexdigest()[:16]

    def signaler(self, lien_normalise, avis, verdict_portail=None, score=None, canal="portail"):
        with self._connexion() as c:
            c.execute("INSERT INTO signalements (date, empreinte, lien_normalise, avis, verdict_portail, score, canal) "
                      "VALUES (?, ?, ?, ?, ?, ?, ?)",
                      (datetime.now(timezone.utc).isoformat(timespec="seconds"), self.empreinte(lien_normalise),
                       lien_normalise, avis, verdict_portail, score, canal))
        return self.etat(lien_normalise)

    def etat(self, lien_normalise) -> dict:
        """Combien de fois ce lien a été signalé comme phishing ou comme sûr, et s'il est une menace connue."""
        with self._connexion() as c:
            lignes = dict(c.execute("SELECT avis, COUNT(*) FROM signalements WHERE empreinte = ? GROUP BY avis",
                                    (self.empreinte(lien_normalise),)).fetchall())
        phishing, sur = lignes.get("phishing", 0), lignes.get("sur", 0)
        return {"phishing": phishing, "sur": sur, "menace_connue": phishing >= SEUIL_MENACE and phishing > sur}

    def statistiques(self) -> dict:
        with self._connexion() as c:
            total = c.execute("SELECT COUNT(*) FROM signalements").fetchone()[0]
            par_avis = dict(c.execute("SELECT avis, COUNT(*) FROM signalements GROUP BY avis").fetchall())
            erreurs = dict(c.execute(
                "SELECT CASE WHEN avis = 'phishing' THEN 'phishing_rates' ELSE 'fausses_alertes' END, COUNT(*) "
                "FROM signalements WHERE (avis = 'phishing' AND verdict_portail = 'SÛR') "
                "OR (avis = 'sur' AND verdict_portail IN ('SUSPECT', 'DANGEREUX')) GROUP BY 1").fetchall())
            menaces = c.execute(
                "SELECT COUNT(*) FROM (SELECT empreinte, SUM(avis = 'phishing') p, SUM(avis = 'sur') s "
                "FROM signalements GROUP BY empreinte) WHERE p >= ? AND p > s", (SEUIL_MENACE,)).fetchone()[0]
        return {"signalements": total, "par_avis": par_avis, "erreurs_signalees": erreurs, "menaces_connues": menaces}

    def exemples(self):
        """Les liens avec un avis majoritaire clair, pour le réentraînement : (lien_normalise, label)."""
        with self._connexion() as c:
            return c.execute(
                "SELECT lien_normalise, CASE WHEN p > s THEN 1 ELSE 0 END FROM ("
                "SELECT lien_normalise, SUM(avis = 'phishing') p, SUM(avis = 'sur') s "
                "FROM signalements GROUP BY empreinte) WHERE p != s").fetchall()
