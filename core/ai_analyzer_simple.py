import logging

# Configuration du logging
logger = logging.getLogger('iotbreaker')

def get_ai_analysis(prompt_text, max_length=512):
    """
    Version simplifiée de l'analyse IA qui fonctionne sans modèle lourd.
    Retourne des réponses prédéfinies basées sur des mots-clés.
    """
    
    # Analyse basée sur des mots-clés pour simuler l'IA
    prompt_lower = prompt_text.lower()
    
    # Commandes de découverte
    if any(word in prompt_lower for word in ['discover', 'scan', 'trouve', 'cherche', 'découvre']):
        if 'caméra' in prompt_lower or 'camera' in prompt_lower:
            return "DISCOVER_CAMERAS"
        elif 'routeur' in prompt_lower or 'router' in prompt_lower:
            return "DISCOVER_ROUTERS"
        elif 'ampoule' in prompt_lower or 'bulb' in prompt_lower:
            return "DISCOVER_BULBS"
        elif 'thermostat' in prompt_lower:
            return "DISCOVER_THERMOSTATS"
        elif 'wifi' in prompt_lower:
            return "SCAN_WIFI"
        elif 'bluetooth' in prompt_lower:
            return "SCAN_BLUETOOTH"
        else:
            return "DISCOVER"
    
    # Commandes d'analyse
    elif any(word in prompt_lower for word in ['analyze', 'analyse', 'vérifie', 'check']):
        if 'service' in prompt_lower:
            return "ANALYZE_SERVICES all"
        elif 'fingerprint' in prompt_lower:
            return "FINGERPRINT all"
        elif 'banner' in prompt_lower:
            return "BANNER_GRAB all"
        else:
            return "ANALYZE all"
    
    # Commandes de sécurité
    elif any(word in prompt_lower for word in ['vulnérabilité', 'vulnerability', 'sécurité', 'security']):
        if 'défaut' in prompt_lower or 'default' in prompt_lower:
            return "CHECK_DEFAULTS all"
        elif 'telnet' in prompt_lower:
            return "CHECK_TELNET all"
        elif 'ssh' in prompt_lower:
            return "CHECK_SSH all"
        elif 'web' in prompt_lower:
            return "CHECK_WEB all"
        elif 'config' in prompt_lower:
            return "CHECK_CONFIG all"
        else:
            return "CHECK all"
    
    # Commandes de rapport
    elif any(word in prompt_lower for word in ['rapport', 'report', 'génère', 'generate']):
        if 'html' in prompt_lower:
            return "REPORT_HTML"
        elif 'pdf' in prompt_lower:
            return "REPORT_PDF"
        elif 'export' in prompt_lower:
            return "EXPORT"
        else:
            return "REPORT"
    
    # Commandes Shodan
    elif any(word in prompt_lower for word in ['shodan', 'ip publique', 'public ip']):
        if 'similaire' in prompt_lower or 'similar' in prompt_lower:
            return "SHODAN_SIMILAR"
        elif 'visibilité' in prompt_lower or 'visibility' in prompt_lower:
            return "SHODAN_VISIBILITY"
        else:
            return "SHODAN_IP"
    
    # Commandes IA
    elif any(word in prompt_lower for word in ['analyse ia', 'ai analysis', 'recommandation', 'recommendation']):
        if 'risque' in prompt_lower or 'risk' in prompt_lower:
            return "AI_RISKS"
        elif 'recommandation' in prompt_lower or 'recommendation' in prompt_lower:
            return "AI_RECOMMENDATIONS"
        else:
            return "AI_ANALYSIS"
    
    # Commande inconnue
    else:
        return "UNKNOWN"

def get_ai_insights(context):
    """
    Génère des insights IA basés sur le contexte d'audit
    """
    insights = []
    
    if context.get('devices_found'):
        device_count = len(context['devices_found'])
        insights.append(f"✅ {device_count} appareil(s) IoT découvert(s)")
        
        # Analyse des types d'appareils
        device_types = {}
        for device in context.get('devices', {}).values():
            device_type = device.get('type', 'Inconnu')
            device_types[device_type] = device_types.get(device_type, 0) + 1
        
        for device_type, count in device_types.items():
            insights.append(f"📱 {count} appareil(s) de type '{device_type}'")
    
    if context.get('vulnerabilities'):
        vuln_count = len(context['vulnerabilities'])
        high_vulns = len([v for v in context['vulnerabilities'] if v.get('severity') == 'High'])
        
        insights.append(f"🚨 {vuln_count} vulnérabilité(s) trouvée(s)")
        if high_vulns > 0:
            insights.append(f"⚠️ {high_vulns} vulnérabilité(s) critique(s)")
    
    if not insights:
        insights.append("🔍 Aucun appareil découvert pour le moment")
    
    return insights

def get_ai_recommendations(context):
    """
    Génère des recommandations IA basées sur le contexte
    """
    recommendations = []
    
    # Recommandations basées sur les vulnérabilités
    if context.get('vulnerabilities'):
        high_vulns = [v for v in context['vulnerabilities'] if v.get('severity') == 'High']
        if high_vulns:
            recommendations.append("🔒 Corrigez immédiatement les vulnérabilités critiques")
        
        telnet_vulns = [v for v in context['vulnerabilities'] if 'telnet' in v.get('type', '').lower()]
        if telnet_vulns:
            recommendations.append("🚫 Désactivez les ports Telnet non sécurisés")
    
    # Recommandations générales
    if context.get('devices_found'):
        recommendations.append("🔐 Changez les mots de passe par défaut")
        recommendations.append("📡 Isolez les appareils IoT sur un réseau séparé")
        recommendations.append("🔄 Maintenez les firmwares à jour")
    
    if not recommendations:
        recommendations.append("🔍 Lancez un scan complet pour identifier les vulnérabilités")
    
    return recommendations 