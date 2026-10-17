# Zyxel Nebula Firewall Monitor

Application web pour inventorier les pare-feu Zyxel gérés depuis le cloud Nebula.

## Objectifs

- Interroger les organisations, réseaux et appareils accessibles avec une clé API Nebula.
- Afficher les pare-feu Zyxel détectés, regroupés par organisation et réseau.
- Conserver le dernier inventaire complet dans un fichier local et afficher la date du scan.
- Suivre la disponibilité cloud, les interfaces WAN, le CPU, la mémoire et les sessions, avec un historique glissant de 48 heures.
- Servir l'interface derrière Nginx, sans exposer la clé API au navigateur.

## Démarrage avec Docker

1. Copier `.env.example` vers `.env` et renseigner `NEBULA_API_KEY`.
2. Démarrer l'application avec `docker compose up --build -d`.
3. Ouvrir [http://localhost:8080](http://localhost:8080).

L'inventaire est mis en cache dans `data/inventory.json`. Un scan est lancé au premier démarrage si le cache est vide ; les chargements suivants réutilisent le cache. Le bouton de scan permet de le rafraîchir. Un scan incomplet ou en erreur ne remplace pas le dernier inventaire réussi.

## Supervision

Le service API collecte l'état cloud des pare-feu et les états VPN documentés toutes les minutes. Il collecte les ports, les paramètres des interfaces WAN et les métriques système (CPU, mémoire et sessions) toutes les cinq minutes. Les données et alertes sont conservées dans `data/monitoring.sqlite` sur les dernières 48 heures ; ce volume doit être accessible en écriture par l'utilisateur du conteneur API.

Le dashboard affiche la disponibilité cloud, la configuration WAN sans conserver ni montrer les adresses IP, les vitesses de port et les courbes d'historique. Les alertes cloud hors ligne et perte de tous les ports WAN associés nécessitent deux mesures consécutives ; les alertes VPN et CPU/mémoire conservent la même confirmation sur deux mesures. Une valeur de vitesse absente reste inconnue et ne déclenche pas à elle seule une alerte de lien. Une mesure indisponible ou trop ancienne n'est pas considérée saine. En cas de limite API Nebula, les appels sont suspendus temporairement avant reprise.

## Périmètre actuel

La supervision s'appuie sur les métriques exposées par l'API cloud Nebula. Les débits WAN/LAN instantanés, les sondes de connectivité vers les applications cloud et la disponibilité réelle des services derrière les VPN ne sont pas inclus.

## Sécurité

La clé API Nebula est lue par le service serveur depuis `.env`. Ce fichier et le cache local sont exclus de Git. Ne jamais publier la clé, même dans les journaux ou des captures d'écran.
