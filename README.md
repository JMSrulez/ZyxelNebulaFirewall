# Zyxel Nebula Firewall Monitor

Application web en cours de conception pour superviser un ou plusieurs pare-feu Zyxel gérés depuis le cloud Nebula.

## Objectifs

- Se connecter à l'API Nebula à l'aide d'une clé API fournie par l'utilisateur.
- Découvrir les organisations et les réseaux accessibles avec cette clé.
- Recenser les pare-feu Zyxel présents dans ces réseaux.
- Historiser leur état ainsi que le volume de trafic sur les ports LAN et WAN.
- Présenter ces informations dans une interface web de supervision.

## État du projet

Le projet démarre : l'application et ses fonctionnalités restent à construire.

## Sécurité

La clé API Nebula est un secret. Elle ne doit pas être publiée dans le dépôt, les journaux ou des captures d'écran. Son stockage et son utilisation devront être sécurisés dans l'application.
