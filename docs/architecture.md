# Architecture MVP IntegraSec

## Vue d'ensemble

Le MVP est structuré en monorepo avec une séparation claire des composants :

- `agent/` : agent Linux en Go (CLI `baseline`, `scan`, `watch`) ;
- `backend/` : API HTTP en Go + stockage SQLite ;
- `frontend/` : tableau de bord minimal statique ;
- `docs/` : architecture, scénarios de test et guide d'exploitation.

## Flux principal

1. L'agent calcule une baseline SHA-256 des fichiers surveillés.
2. L'agent compare l'état courant à la baseline.
3. Les événements (`added`, `deleted`, `modified`) sont envoyés à l'API via `X-Agent-Key`.
4. Le backend valide, stocke, expose les événements et les machines.
5. Le frontend interroge l'API pour afficher santé, machines et événements.

## Sécurité MVP

- Hashing des fichiers via SHA-256.
- Authentification simple par clé d'agent (`X-Agent-Key`) et clé d'enrôlement (`X-Bootstrap-Key`).
- Validation stricte des payloads JSON, tailles de requêtes, types d'événements et chemins.
- Timestamps stockés et servis au format UTC (RFC3339).
- Aucun secret versionné (variables d'environnement + fichiers d'exemple).

## Limites connues

- MVP défensif : pas de remédiation automatique.
- Protection de la baseline non durcie (à signer/chiffrer en production).
- Auth simplifiée (pas de mTLS/JWT/rotation de secrets automatisée).
- Tableau de bord sans gestion d'utilisateurs.
