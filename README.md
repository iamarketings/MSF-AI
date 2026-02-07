
# MSF-AI : Assistant IA pour Metasploit Framework

Ce projet est un assistant basé sur l'intelligence artificielle conçu pour interagir avec le Metasploit Framework. Il fournit une interface conversationnelle en langage naturel pour exécuter diverses tâches de test d'intrusion, de la reconnaissance à l'exploitation et au reporting.

## 🚀 Fonctionnalités

*   **IA Conversationnelle** : Interagissez avec Metasploit en utilisant des phrases simples et naturelles.
*   **Orchestration de Tâches** : Décomposez des objectifs complexes (ex: "scanner et exploiter") en une série d'étapes exécutées automatiquement.
*   **Architecture Modulaire (MVC)** : Le projet est structuré selon le patron de conception MVC (Modèle-Vue-Contrôleur), ce qui le rend facile à maintenir et à étendre.
*   **Intégration d'Outils** : L'assistant peut utiliser une variété d'outils pour la reconnaissance, la post-exploitation, les tests d'applications web et la génération de rapports.
*   **RAG (Retrieval-Augmented Generation)** : L'IA peut consulter une base de connaissances pour fournir des réponses plus précises et contextuelles.

## 🏗️ Architecture

Le projet s'articule autour des composants suivants :

*   **Contrôleur (`msf_controller.py`)** : C'est le point d'entrée principal de l'application. Il gère les entrées de l'utilisateur, coordonne les actions entre l'IA et Metasploit, et fait le lien entre le modèle et la vue.
*   **Modèle (`msf_model.py`)** : Représente la logique métier. Il gère la connexion avec le serveur RPC de Metasploit et exécute les commandes.
*   **Vue (`msf_view.py`)** : Gère l'interface utilisateur en ligne de commande, y compris l'affichage des bannières, des statuts et des réponses de l'IA.
*   **Orchestrateur (`msf_orchestrator.py`)** : Permet de décomposer des objectifs de haut niveau en tâches plus petites et de les exécuter de manière séquentielle.
*   **RAG (`msf_rag.py`)** : Construit et utilise une base de connaissances vectorielles pour améliorer la pertinence des réponses de l'IA.

## 📋 Prérequis

Avant de commencer, assurez-vous d'avoir les éléments suivants installés :

*   **Python 3.8+**
*   **Metasploit Framework**
*   Un compte **DeepSeek AI** pour obtenir une clé API.

## ⚙️ Installation

1.  **Clonez le dépôt Git :**
    ```bash
    git clone https://github.com/iamarketings/MSF-AI.git
    cd MSF-AI
    ```

2.  **Installez les dépendances Python :**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Configurez les variables d'environnement :**
    Créez un fichier `.env` à la racine du projet (`msf_aiv4/.env`) et ajoutez les informations suivantes :

    ```
    DEEPSEEK_API_KEY="VOTRE_CLÉ_API_DEEPSEEK"
    MSF_RPC_USER="msf"
    MSF_RPC_PASS="VOTRE_MOT_DE_PASSE_MSF"
    MSF_RPC_PORT="55553"
    ```

4.  **Démarrez le serveur RPC de Metasploit :**
    Ouvrez un terminal et lancez `msfconsole`. Ensuite, utilisez la commande suivante pour démarrer le serveur RPC avec un nom d'utilisateur et un mot de passe :
    ```bash
    msfconsole -x "load msgrpc Pass=VOTRE_MOT_DE_PASSE_MSF User=msf"
    ```
    Assurez-vous que le mot de passe correspond à celui que vous avez configuré dans le fichier `.env`.

## ▶️ Utilisation

Une fois que le serveur RPC de Metasploit est en cours d'exécution, vous pouvez lancer l'assistant IA :

```bash
python msf_aiv4/msf_controller.py
```

L'assistant affichera une bannière de bienvenue et vous pourrez commencer à interagir avec lui en entrant des commandes en langage naturel.

**Exemples de commandes :**

*   `cherche des exploits pour eternalblue`
*   `scan les ports sur 192.168.1.10`
*   `exploite le service vsftpd sur 10.0.0.5` (mode orchestration)

## 🛠️ Outils Disponibles

L'assistant dispose d'un ensemble d'outils pour réaliser différentes actions :

*   **Reconnaissance** : Recherche de modules, géolocalisation d'IP, etc.
*   **Réseau** : Scan de ports, etc.
*   **Web** : Scan de vulnérabilités web, etc.
*   **Post-Exploitation** : Exécution de commandes sur une session, etc.
*   **Reporting** : Génération de rapports.

## Versions

*   **v3** : Ancienne version de l'assistant.
*   **v4** : Version actuelle, avec une architecture améliorée, l'orchestration de tâches et l'intégration de RAG.
