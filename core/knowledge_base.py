import json
import os
import logging

logger = logging.getLogger('iotbreaker')
KB_FILE = "ai_knowledge_base.json"

def load_knowledge():
    """Charge la base de connaissances de l'IA depuis le fichier JSON."""
    if not os.path.exists(KB_FILE):
        return {"learnings": []}
    try:
        with open(KB_FILE, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        logger.error(f"Impossible de charger la base de connaissances : {e}")
        return {"learnings": []}

def save_knowledge(kb):
    """Sauvegarde la base de connaissances dans le fichier JSON."""
    try:
        with open(KB_FILE, "w") as f:
            json.dump(kb, f, indent=2)
    except IOError as e:
        logger.error(f"Impossible de sauvegarder la base de connaissances : {e}")

def add_learning(kb, new_learning):
    """Ajoute un nouvel apprentissage à la base de connaissances."""
    # Évite les doublons
    if new_learning not in kb["learnings"]:
        kb["learnings"].append(new_learning)
        logger.info(f"Nouveau savoir acquis : {new_learning}")

def get_recent_learnings(kb, count=5):
    """Récupère les apprentissages les plus récents."""
    return kb["learnings"][-count:] if kb["learnings"] else []

def search_learnings(kb, query):
    """Recherche dans les apprentissages existants."""
    matching_learnings = []
    query_lower = query.lower()
    for learning in kb["learnings"]:
        if query_lower in learning.lower():
            matching_learnings.append(learning)
    return matching_learnings

def get_knowledge_stats(kb):
    """Retourne des statistiques sur la base de connaissances."""
    return {
        "total_learnings": len(kb["learnings"]),
        "recent_learnings": len(get_recent_learnings(kb)),
        "file_size": os.path.getsize(KB_FILE) if os.path.exists(KB_FILE) else 0
    } 