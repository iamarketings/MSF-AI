# Metasploit Framework AI Assistant (MSF-AI v4)

> [!CAUTION]
> ## 🔴 Sécurité et Responsabilité Légale
> Ce projet automatise des capacités offensives qui peuvent causer des dommages significatifs.
> - **L'utilisation non autorisée sur des systèmes tiers est illégale.**
> - Ce logiciel est destiné uniquement à des fins éducatives et de tests d'intrusion autorisés dans des environnements contrôlés (LAB).
> - Les auteurs déclinent toute responsabilité en cas de mauvaise utilisation ou de dommages causés par cet outil.

MSF-AI v4 est un assistant d'automatisation avancé pour le Metasploit Framework, propulsé par l'IA (DeepSeek/APIs compatibles) avec orchestration Langgraph. Le projet démontre une architecture professionnelle orientée audit de sécurité et tests d'intrusion automatisés.

## 🎯 Vue d'Ensemble

L'assistant offre une interface conversationnelle pour interagir avec Metasploit et effectuer diverses tâches de test d'intrusion de manière autonome grâce à une orchestration avancée.

## 📐 Architecture et Design

Le projet suit une architecture modulaire MVC (Modèle-Vue-Contrôleur) :
*   **Modèle** (`msf_model.py`) : Gestion complète de la connexion RPC Metasploit.
*   **Vue** (`msf_view.py`) : Interface terminal dynamique avec prompts contextuels.
*   **Contrôleur** (`msf_controller.py`) : Coordinateur de logique, gestion de l'historique et des outils.
*   **Orchestrateur** (`msf_orchestrator.py`) : Moteur d'exécution basé sur **Langgraph** (Planner -> Executor -> Analyzer).

### Modularité des Outils
Les outils sont répartis par catégories dans `msf_aiv4/tools/` :
*   **Réseau** : CIDR, géolocalisation, scan de ports parallèle, port knocking.
*   **Web** : Analyse de formulaires (BeautifulSoup), détection WAF, injection SQL, en-têtes de sécurité.
*   **Reconnaissance** : WHOIS réel, énumération DNS, découverte de sous-domaines (crt.sh).
*   **Post-Exploitation** : Collecte d'infos système, recherche de fichiers, extraction d'identifiants.
*   **OS** : Identification et interaction avec Linux, WSL et Windows.

## 🚀 Fonctionnalités Clés

*   **Orchestration Langgraph** : Planification dynamique et adaptative des tâches.
*   **Système RAG (Retrieval-Augmented Generation)** : Base de connaissances SQLite pour enrichir les réponses de l'IA avec des exploits réels et des bonnes pratiques.
*   **Gestion de Sécurité Intégrée** : Modes "safe" (lecture seule/info) et "unsafe" (exécution totale) configurables.
*   **Audit Logging** : Journalisation détaillée de toutes les actions offensives au format JSON (`audit.json`).
*   **Performance** : Scans de ports parallèles et mise en cache des résultats (WHOIS, DNS).

## ⚙️ Installation et Configuration

1.  **Prérequis** :
    *   Python 3.10+
    *   Metasploit Framework (avec `msfrpcd` actif)

2.  **Installation** :
    ```bash
    git clone <repository-url>
    cd msf-ai-assistant
    pip install -r requirements.txt
    ```

3.  **Configuration** :
    Copiez `.env.example` en `.env` et remplissez vos clés :
    ```env
    DEEPSEEK_API_KEY=votre_cle_ici
    MSF_RPC_PASS=votre_mot_de_passe
    ```

4.  **Lancement** :
    ```bash
    python3 msf_mvc.py
    ```

## 📖 Utilisation

| Commande | Description |
|----------|-------------|
| `help` | Affiche le menu d'aide |
| `sessions` | Liste les sessions Metasploit actives |
| `config` | Affiche la configuration actuelle |
| `security <mode>` | Change le mode (safe/unsafe) |
| `set RHOSTS <ip>` | Définit une variable de contexte |
| `clear` | Efface l'écran |
| `exit` | Quitte l'application |

## 🧪 Tests

Lancez la suite de tests avec pytest :
```bash
pytest tests/
```

---
**Développé avec une approche "Security by Design". Usage en environnement LAB uniquement.**
