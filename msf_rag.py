#!/usr/bin/env python3
"""
MSF AI v4 - Système RAG (Retrieval-Augmented Generation)
Base de connaissances pour les modules Metasploit et les techniques d'exploitation.
"""
import sqlite3
import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

logger = logging.getLogger('MSF_AI.RAG')

class MSFRagLibrary:
    """
    Bibliothèque RAG basée sur SQLite pour la connaissance Metasploit.
    Contient des informations sur les modules, CVE, vulnérabilités et bonnes pratiques.
    """
    
    def __init__(self, db_path: str = "msf_knowledge.db"):
        self.db_path = Path(db_path)
        self.db = None
        self.connect()
        self.init_db()
    
    def connect(self):
        """Établit la connexion à la base de données."""
        try:
            self.db = sqlite3.connect(str(self.db_path))
            self.db.row_factory = sqlite3.Row  # Permet l'accès aux lignes comme des dictionnaires
            logger.info(f"Connecté à la base de données RAG : {self.db_path}")
        except Exception as e:
            logger.error(f"Échec de la connexion à la base de données RAG : {e}")
            raise
    
    def init_db(self):
        """Initialise le schéma de la base de données."""
        try:
            # Créer la table des exploits
            self.db.execute("""
                CREATE TABLE IF NOT EXISTS exploits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    module_path TEXT UNIQUE NOT NULL,
                    cve TEXT,
                    description TEXT,
                    tags TEXT,
                    success_rate REAL DEFAULT 0.0,
                    best_practices TEXT,
                    refs TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Créer la table des signatures de vulnérabilité
            self.db.execute("""
                CREATE TABLE IF NOT EXISTS vulnerability_signatures (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve TEXT UNIQUE NOT NULL,
                    product TEXT,
                    version TEXT,
                    description TEXT,
                    severity TEXT,
                    exploitability_score REAL,
                    detection_method TEXT,
                    mitigation TEXT,
                    refs TEXT
                )
            """)
            
            # Créer la table des modèles de prompt (prompt templates)
            self.db.execute("""
                CREATE TABLE IF NOT EXISTS prompt_templates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    template TEXT,
                    category TEXT,
                    usage_count INTEGER DEFAULT 0
                )
            """)
            
            # Créer la table de connaissances 'villager'
            self.db.execute("""
                CREATE TABLE IF NOT EXISTS villager_knowledge (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT,
                    content TEXT,
                    source TEXT DEFAULT 'Villager-v0.2'
                )
            """)
            
            # Créer les index
            self.db.execute("CREATE INDEX IF NOT EXISTS idx_exploits_tags ON exploits(tags)")
            self.db.execute("CREATE INDEX IF NOT EXISTS idx_exploits_cve ON exploits(cve)")
            self.db.execute("CREATE INDEX IF NOT EXISTS idx_vuln_cve ON vulnerability_signatures(cve)")
            self.db.execute("CREATE INDEX IF NOT EXISTS idx_villager_title ON villager_knowledge(title)")
            
            self.db.commit()
        except Exception as e:
            logger.error(f"Échec de l'initialisation de la base de données : {e}")
            raise

    def _sanitize_query(self, query: str) -> str:
        """Assainit la requête pour éviter les injections SQL simples."""
        return query.replace("'", "''").replace(";", "")

    def retrieve_context(self, query: str, limit: int = 5) -> List[Dict[str, Any]]:
        """Récupère le contexte pertinent basé sur la requête."""
        query = self._sanitize_query(query)
        try:
            # Rechercher dans les exploits
            exploit_results = self.db.execute("""
                SELECT * FROM exploits 
                WHERE description LIKE ? OR tags LIKE ? 
                LIMIT ?
            """, (f"%{query}%", f"%{query}%", limit)).fetchall()
            
            # Rechercher dans les connaissances villager
            villager_results = self.db.execute("""
                SELECT * FROM villager_knowledge
                WHERE title LIKE ? OR content LIKE ?
                LIMIT ?
            """, (f"%{query}%", f"%{query}%", limit)).fetchall()
            
            context = []
            
            for result in exploit_results:
                context.append({
                    "type": "exploit",
                    "module_path": result["module_path"],
                    "description": result["description"],
                    "tags": result["tags"],
                    "success_rate": result["success_rate"],
                    "best_practices": result["best_practices"],
                    "source": "Base de données des modules MSF"
                })
                
            for result in villager_results:
                context.append({
                    "type": "knowledge_entry",
                    "description": result["title"], 
                    "template": result["content"][:500] + "...", 
                    "source": "Base de connaissances Villager"
                })
            
            return context
        except Exception as e:
            logger.error(f"Échec de la récupération du contexte : {e}")
            return []

    def retrieve_vulnerabilities(self, product: str, version: str = None) -> List[Dict[str, Any]]:
        """Récupère les signatures de vulnérabilité basées sur le produit et la version."""
        product = self._sanitize_query(product)
        if version:
            version = self._sanitize_query(version)
        try:
            query = "SELECT * FROM vulnerability_signatures WHERE product LIKE ?"
            params = [f"%{product}%"]
            if version:
                query += " AND version LIKE ?"
                params.append(f"%{version}%")

            results = self.db.execute(query, params).fetchall()
            return [dict(r) for r in results]
        except Exception as e:
            logger.error(f"Échec de la récupération des vulnérabilités : {e}")
            return []

    def enhance_prompt(self, user_query: str, context_limit: int = 5) -> str:
        """Améliore la requête utilisateur avec le contexte RAG."""
        context = self.retrieve_context(user_query, context_limit)
        if not context:
            return user_query
            
        context_str = "\n[CONTEXTE RAG DÉTECTÉ]\n"
        for item in context:
            if item['type'] == 'exploit':
                context_str += f"- [Exploit] {item['module_path']}: {item['description']}\n"
                context_str += f"  Taux de succès : {item.get('success_rate', 'N/A')}\n"
                context_str += f"  Bonnes pratiques : {item.get('best_practices', 'Aucune')}\n"
            else:
                context_str += f"- [{item['type']}] {item['description']}\n"
                if 'template' in item:
                    context_str += f"  Contenu : {item['template']}\n"
                
        return f"{context_str}\n\nRequête Utilisateur : {user_query}"
        
    def close(self):
        """Ferme la connexion à la base de données."""
        if self.db:
            self.db.close()

def create_rag_library() -> MSFRagLibrary:
    """Fonction utilitaire pour créer la bibliothèque RAG."""
    return MSFRagLibrary()
