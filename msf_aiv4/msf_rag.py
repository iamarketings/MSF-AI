#!/usr/bin/env python3
"""
MSF AI v4 - RAG System (Retrieval-Augmented Generation)
Knowledge base for Metasploit modules and exploitation techniques
"""
import sqlite3
import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

logger = logging.getLogger('MSF_AI.RAG')

class MSFRagLibrary:
    """
    SQLite-based RAG library for Metasploit knowledge
    Contains information about modules, CVE, vulnerabilities, and best practices
    """
    
    def __init__(self, db_path: str = "msf_knowledge.db"):
        self.db_path = Path(db_path)
        self.db = None
        self.connect()
        self.init_db()
    
    def connect(self):
        """Establishes database connection"""
        try:
            self.db = sqlite3.connect(str(self.db_path))
            self.db.row_factory = sqlite3.Row  # Allow dict-like access to rows
            logger.info(f"Connected to RAG database: {self.db_path}")
        except Exception as e:
            logger.error(f"Failed to connect to RAG database: {e}")
            raise
    
    def init_db(self):
        """Initializes the database schema"""
        try:
            # Create exploits table
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
            
            # Create vulnerability signatures table
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
            
            # Create prompt templates table
            self.db.execute("""
                CREATE TABLE IF NOT EXISTS prompt_templates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    template TEXT,
                    category TEXT,
                    usage_count INTEGER DEFAULT 0
                )
            """)
            
            # Create villager knowledge table
            self.db.execute("""
                CREATE TABLE IF NOT EXISTS villager_knowledge (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT,
                    content TEXT,
                    source TEXT DEFAULT 'Villager-v0.2'
                )
            """)
            
            # Create indexes
            self.db.execute("CREATE INDEX IF NOT EXISTS idx_exploits_tags ON exploits(tags)")
            self.db.execute("CREATE INDEX IF NOT EXISTS idx_exploits_cve ON exploits(cve)")
            self.db.execute("CREATE INDEX IF NOT EXISTS idx_vuln_cve ON vulnerability_signatures(cve)")
            self.db.execute("CREATE INDEX IF NOT EXISTS idx_villager_title ON villager_knowledge(title)")
            
            self.db.commit()
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise

    def retrieve_context(self, query: str, limit: int = 5) -> List[Dict[str, Any]]:
        """Retrieves relevant context based on query"""
        try:
            # Search exploits
            exploit_results = self.db.execute("""
                SELECT * FROM exploits 
                WHERE description LIKE ? OR tags LIKE ? 
                LIMIT ?
            """, (f"%{query}%", f"%{query}%", limit)).fetchall()
            
            # Search villager knowledge
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
                    "source": "MSF Module Database"
                })
                
            for result in villager_results:
                context.append({
                    "type": "knowledge_entry",
                    "description": result["title"], 
                    "template": result["content"][:500] + "...", 
                    "source": "Villager Knowledge Base"
                })
            
            return context
        except Exception as e:
            logger.error(f"Failed to retrieve context: {e}")
            return []

    def enhance_prompt(self, user_query: str, context_limit: int = 5) -> str:
        """Enhances user query with RAG context."""
        context = self.retrieve_context(user_query, context_limit)
        if not context:
            return user_query
            
        context_str = "\n[CONTEXTE RAG DÉTECTÉ]\n"
        for item in context:
            context_str += f"- [{item['type']}] {item['description']}\n"
            if 'template' in item:
                context_str += f"  Content: {item['template']}\n"
                
        return f"{context_str}\n\nRequête User: {user_query}"
        
    def close(self):
        if self.db:
            self.db.close()

def create_rag_library() -> MSFRagLibrary:
    return MSFRagLibrary()