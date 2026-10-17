# Zyxel Nebula Firewall Monitor

Application web pour inventorier les pare-feu Zyxel gérés depuis le cloud Nebula.

## Objectifs

- Interroger les organisations, réseaux et appareils accessibles avec une clé API Nebula.
- Afficher les pare-feu Zyxel détectés, regroupés par organisation et réseau.
- Conserver le dernier inventaire complet dans un fichier local et afficher la date du scan.
- Suivre l'état VPN, le CPU, la mémoire et les sessions, avec un historique glissant de 48 heures.
- Servir l'interface derrière Nginx, sans exposer la clé API au navigateur.

## Démarrage avec Docker

1. Copier `.env.example` vers `.env` et renseigner `NEBULA_API_KEY`.
2. Démarrer l'application avec `docker compose up --build -d`.
3. Ouvrir [http://localhost:8080](http://localhost:8080).

L'inventaire est mis en cache dans `data/inventory.json`. Un scan est lancé au premier démarrage si le cache est vide ; les chargements suivants réutilisent le cache. Le bouton de scan permet de le rafraîchir. Un scan incomplet ou en erreur ne remplace pas le dernier inventaire réussi.

## Supervision

Le service API collecte l'état des tunnels VPN toutes les minutes et les métriques système (CPU, mémoire et sessions) toutes les cinq minutes. Les données et alertes sont conservées dans `data/monitoring.sqlite` sur les dernières 48 heures ; ce volume doit être accessible en écriture par l'utilisateur du conteneur API.

Le dashboard affiche l'état de collecte par pare-feu, les alertes actives et les courbes d'historique. Une alerte VPN est confirmée après deux mesures consécutives indiquant une coupure ; une alerte CPU ou mémoire est déclenchée après deux mesures consécutives à 90 % ou plus. Une mesure indisponible ou trop ancienne reste signalée comme telle, sans être considérée saine. En cas de limite API Nebula, les appels sont suspendus temporairement avant reprise.

## Périmètre actuel

La supervision s'appuie sur les métriques exposées par l'API cloud Nebula. Les débits WAN/LAN instantanés, les sondes de connectivité vers les applications cloud et la disponibilité réelle des services derrière les VPN ne sont pas inclus.

## Sécurité

La clé API Nebula est lue par le service serveur depuis `.env`. Ce fichier et le cache local sont exclus de Git. Ne jamais publier la clé, même dans les journaux ou des captures d'écran.
