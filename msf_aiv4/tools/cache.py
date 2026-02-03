"""
Système de Cache simple pour MSF-AI v4
"""
import time
import functools
import json
import os
from typing import Any, Dict

# Cache en mémoire
_memory_cache = {}

def cache_result(expiry_seconds=3600):
    """Décorateur pour mettre en cache les résultats d'appels coûteux."""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Créer une clé de cache basée sur le nom de la fonction et les arguments
            cache_key = f"{func.__name__}:{args}:{kwargs}"

            if cache_key in _memory_cache:
                result, timestamp = _memory_cache[cache_key]
                if time.time() - timestamp < expiry_seconds:
                    return result

            # Exécuter la fonction et stocker le résultat
            result = func(*args, **kwargs)
            _memory_cache[cache_key] = (result, time.time())
            return result
        return wrapper
    return decorator
