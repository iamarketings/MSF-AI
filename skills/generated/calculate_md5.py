import hashlib

def calculate_md5(text: str) -> str:
    """
    Calcule le hash MD5 d'une chaîne de caractères.
    
    Args:
        text (str): La chaîne à hasher
        
    Returns:
        str: Le hash MD5 en hexadécimal
    """
    # Encoder la chaîne en bytes
    text_bytes = text.encode('utf-8')
    
    # Calculer le hash MD5
    md5_hash = hashlib.md5(text_bytes)
    
    # Retourner la représentation hexadécimale
    return md5_hash.hexdigest()