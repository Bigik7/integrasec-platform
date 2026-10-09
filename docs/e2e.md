# Test de bout en bout documenté (MVP)

## Objectif
Vérifier un flux complet : enrôlement machine -> ingestion d'un événement -> consultation via API.

## Pré-requis
- Go >= 1.22
- Variables backend configurées (`backend/config.example.env`)
- Une clé bootstrap et une clé agent de test

## Étapes manuelles (curl)

1. Démarrer le backend :

```bash
cd backend
INTEGRASEC_BOOTSTRAP_KEY=bootstrap-demo go run ./cmd/integrasec-backend
```

2. Enregistrer une machine :

```bash
curl -sS -X POST http://localhost:8080/api/v1/machines/register \
  -H 'Content-Type: application/json' \
  -H 'X-Bootstrap-Key: bootstrap-demo' \
  -d '{
    "machine_id":"linux-01",
    "hostname":"srv-linux-01",
    "agent_key":"agent-key-demo-1234"
  }'
```

3. Envoyer un événement :

```bash
curl -sS -X POST http://localhost:8080/api/v1/events \
  -H 'Content-Type: application/json' \
  -H 'X-Agent-Key: agent-key-demo-1234' \
  -d '[{
    "machine":"linux-01",
    "path":"/etc/ssh/sshd_config",
    "type":"modified",
    "old_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "new_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "timestamp_utc":"2026-01-01T00:00:00Z",
    "severity":"high"
  }]'
```

4. Consulter les événements :

```bash
curl -sS 'http://localhost:8080/api/v1/events?machine=linux-01&limit=10' \
  -H 'X-Agent-Key: agent-key-demo-1234'
```

## Vérification automatisée liée
Le test Go `TestE2ERegisterAndEventFlow` dans `backend/internal/api/server_test.go` couvre le même scénario de bout en bout au niveau API.
