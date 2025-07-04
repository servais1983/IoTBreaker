import logging

# Configuration du logging
logger = logging.getLogger('iotbreaker')

# Variables globales pour le chargement lazy de l'IA
pipe = None
ai_loaded = False

def _load_ai_model():
    """Charge le modèle IA de manière lazy"""
    global pipe, ai_loaded
    
    if ai_loaded:
        return True
        
    try:
        import torch
        from transformers import pipeline
        
        pipe = pipeline(
            "text-generation",
            model="microsoft/Phi-3-mini-4k-instruct",
            device_map="auto",  # Utilise le GPU si disponible
            torch_dtype="auto",
            trust_remote_code=True,
        )
        ai_loaded = True
        logger.info("Modèle d'IA Phi-3 chargé avec succès.")
        return True
    except Exception as e:
        ai_loaded = False
        logger.error(f"Impossible de charger le modèle d'IA Phi-3. L'analyse par IA sera désactivée. Erreur: {e}")
        return False

def get_ai_analysis(prompt_text, max_length=512):
    """
    Interroge le modèle d'IA local pour obtenir une analyse.
    Retourne la réponse de l'IA ou None si le modèle n'est pas disponible.
    """
    # Chargement lazy de l'IA
    if not _load_ai_model():
        return "Analyse par IA non disponible (modèle non chargé)."

    # Structure du message pour le modèle d'instruction
    messages = [
        {"role": "system", "content": "You are a world-class cybersecurity expert specializing in IoT. Analyze the provided data and give clear, concise, and actionable insights in French."},
        {"role": "user", "content": prompt_text},
    ]

    try:
        # Génération de la réponse
        output = pipe(
            messages,
            max_new_tokens=max_length,
            do_sample=True,
            temperature=0.7,
            top_k=50,
            top_p=0.95,
        )
        # Extraction du texte généré
        response_text = output[0]["generated_text"][-1]['content']
        return response_text.strip()
    except Exception as e:
        logger.error(f"Erreur lors de la génération de la réponse de l'IA: {e}")
        return "Erreur lors de l'analyse par l'IA." 