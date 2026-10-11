# IntegraSec MVP - Surveillance d'intégrité de fichiers (Linux)

IntegraSec est un MVP défensif pour surveiller l'intégrité de fichiers sur machines Linux.
Il comprend un agent Go, un backend API Go/SQLite et un tableau de bord web minimal.

> ⚠️ Ce MVP ne remplace pas un EDR/SIEM et n'exécute aucune remédiation automatique.

## 1) Architecture monorepo

- `/agent` : agent Linux CLI (`baseline`, `scan`, `watch`)
- `/backend` : API HTTP + stockage SQLite
- `/frontend` : interface web minimale
- `/docs` : architecture et test E2E documenté

## 2) Prérequis

- Go 1.22+
- Linux (pour l'usage agent)

## 3) Installation locale

```bash
git clone https://github.com/Bigik7/integrasec-platform.git
cd integrasec-platform
go work sync
```

## 4) Configuration sans secrets versionnés

### Backend

Copier les variables de `backend/config.example.env` dans votre environnement local (ou `.env` non commitée) :

- `INTEGRASEC_BOOTSTRAP_KEY` (obligatoire)
- `INTEGRASEC_DB_PATH`
- `INTEGRASEC_ADDR`
- `INTEGRASEC_MAX_BODY_BYTES`
- `INTEGRASEC_FRONTEND_DIR`

### Agent

Utiliser `agent/config.example.json` et injecter la clé agent via variable d'environnement :

```bash
export INTEGRASEC_AGENT_KEY='agent-key-local-1234'
```

## 5) Lancer le backend

```bash
cd backend
INTEGRASEC_BOOTSTRAP_KEY='bootstrap-local' go run ./cmd/integrasec-backend
```

Endpoints principaux :

- `GET /health`
- `POST /api/v1/machines/register`
- `POST /api/v1/events`
- `GET /api/v1/events?machine=&type=&limit=`
- `GET /api/v1/machines`

## 6) Enrôler une machine/agent

```bash
curl -sS -X POST http://localhost:8080/api/v1/machines/register \
  -H 'Content-Type: application/json' \
  -H 'X-Bootstrap-Key: bootstrap-local' \
  -d '{
    "machine_id":"linux-01",
    "hostname":"srv-linux-01",
    "agent_key":"agent-key-local-1234"
  }'
```

## 7) Agent Linux : baseline, scan, watch

Depuis `agent/` :

### Baseline SHA-256

```bash
go run ./cmd/integrasec-agent baseline --config ./config.example.json
```

### Scan (comparaison à la baseline)

```bash
go run ./cmd/integrasec-agent scan --config ./config.example.json
```

### Watch (événements temps réel + rescans fiables périodiques)

```bash
go run ./cmd/integrasec-agent watch --config ./config.example.json
```

Option sortie JSON : `--json`

## 8) Frontend minimal

Le backend sert `frontend/index.html` (si le dossier configuré existe). Accès via :

- `http://localhost:8080/`

Le dashboard affiche :

- santé API,
- machines connues,
- événements récents.

## 9) Tests

- Unitaires agent : hashing + comparaison baseline
- API backend : routes principales + validation
- E2E documenté : `docs/e2e.md` + test `TestE2ERegisterAndEventFlow`

Exécuter :

```bash
make lint
make test
```

## 10) Contraintes de sécurité et limites MVP

- SHA-256 utilisé pour le MVP ; en production, la baseline doit être signée/protégée.
- Aucune clé/secrets dans le code source.
- Validation stricte des entrées et limites de taille des payloads API.
- Chemins d'événements validés et nettoyés côté API.
- Timestamps en UTC (RFC3339).
- Principe du moindre privilège recommandé pour l'exécution agent/backend.
- Solution défensive uniquement ; intégration EDR/SIEM à prévoir.

## 11) Prochaines étapes

- mTLS/JWT + rotation des clés agent
- Signature cryptographique de baseline
- Règles de sévérité enrichies
- Multi-tenant et gestion d'utilisateurs
- Intégration SIEM/alerting
