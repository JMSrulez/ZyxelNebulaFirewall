# Zyxel Nebula Firewall Monitor

Application web pour inventorier les pare-feu Zyxel gérés depuis le cloud Nebula.

## Objectifs

- Interroger les organisations, réseaux et appareils accessibles avec une clé API Nebula.
- Afficher les pare-feu Zyxel détectés, regroupés par organisation et réseau.
- Conserver le dernier inventaire complet dans un fichier local et afficher la date du scan.
- Servir l'interface derrière Nginx, sans exposer la clé API au navigateur.

## Démarrage avec Docker

1. Copier `.env.example` vers `.env` et renseigner `NEBULA_API_KEY`.
2. Démarrer l'application avec `docker compose up --build -d`.
3. Ouvrir [http://localhost:8080](http://localhost:8080).

L'inventaire est mis en cache dans `data/inventory.json`. Un scan est lancé au premier démarrage si le cache est vide ; les chargements suivants réutilisent le cache. Le bouton de scan permet de le rafraîchir. Un scan incomplet ou en erreur ne remplace pas le dernier inventaire réussi.

## Périmètre actuel

Cette première version couvre uniquement la découverte et l'affichage des pare-feu. L'historisation du statut et du trafic LAN/WAN viendra dans une étape ultérieure.

## Sécurité

La clé API Nebula est lue par le service serveur depuis `.env`. Ce fichier et le cache local sont exclus de Git. Ne jamais publier la clé, même dans les journaux ou des captures d'écran.
