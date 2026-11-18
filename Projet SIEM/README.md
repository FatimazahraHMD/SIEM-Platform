# Plateforme SIEM — Détection et investigation de cyberattaques

Projet réalisé dans le cadre d'un stage au Centre Hospitalier Universitaire 
Hassan II de Fès (juillet-août 2026), au sein du service informatique.

## Objectif

Concevoir et déployer une plateforme de supervision capable de centraliser 
les journaux réseau et système, de simuler des scénarios d'attaques réalistes, 
et de les détecter automatiquement grâce à des détecteurs développés en Python, 
avant de notifier l'administrateur en temps réel.

## Architecture

- **Stack ELK** (Elasticsearch, Logstash, Kibana) déployée sous Docker sur CentOS Stream 9
- **Zeek** et **Suricata** pour la supervision réseau
- **Filebeat** et **Winlogbeat** pour la collecte des journaux
- Laboratoire isolé sous VirtualBox : Windows 10 (victime), Kali Linux (attaquant), CentOS (serveur)

## Attaques simulées et détectées

| Attaque | Outil d'attaque | Détecteur |
|---|---|---|
| Force brute (SMB) | smbclient | BruteForceDetector |
| ARP Poisoning | arpspoof (dsniff) | ARPDetector |
| DNS Spoofing | scapy | DNSAnomalyDetector (via Suricata) |
| XSS (Stocké, Réfléchi, DOM-based) | application Flask vulnérable | XSSDetector |
| Injection SQL (5 techniques) | DVWA | SQLiDetector |

## Fonctionnement des détecteurs

Chaque détecteur partage la même architecture : il interroge les journaux 
collectés, applique une logique de détection dédiée, indexe l'alerte dans 
Elasticsearch, et envoie une notification par e-mail à l'administrateur.

## Configuration

Les fichiers `config.py` ne sont pas inclus dans ce dépôt pour des raisons 
de sécurité (ils contiennent des identifiants). Voici leur structure générale 
à recréer localement :

\`\`\`python
# config.py — à créer dans chaque dossier de détecteur

ES_HOST = "http://localhost:9200"
ES_INDEX = "alerts-<nom_du_detecteur>"

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "votre_email@example.com"
SMTP_PASSWORD = "votre_mot_de_passe_application"
ALERT_RECIPIENT = "admin@example.com"

THRESHOLD = 5
TIME_WINDOW = 60
\`\`\`

## Résultats

Taux de détection de 100% sur les 7 scénarios d'attaques testés. 
Deux études de cas d'investigation menées sur les alertes réellement 
générées (campagne d'injection SQL, tentative de DNS Spoofing).

## Auteur

HAMROUD Fatima Zahra — Élève Ingénieure Cybersécurité, ENSA Fès