import datetime
from fpdf import FPDF

# Variable globale pour stocker tous les détails des scans
scan_details = {
    'discovered_devices': [],
    'port_scans': [],
    'vulnerability_tests': [],
    'shodan_results': [],
    'execution_summary': {}
}

def add_scan_detail(category, data):
    """Ajoute un détail de scan à la collection globale"""
    if category not in scan_details:
        scan_details[category] = []
    scan_details[category].append(data)

def add_execution_summary(key, value):
    """Ajoute un élément au résumé d'exécution"""
    scan_details['execution_summary'][key] = value

def generate_text_report(results, scenario_name):
    """Génère un rapport texte détaillé avec tous les scans effectués."""
    
    print("\n\n" + "="*80)
    print(" " * 25 + "RAPPORT D'AUDIT IOTBREAKER")
    print("="*80)
    
    print(f"Scénario exécuté : {scenario_name}")
    print(f"Date du rapport  : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 80)
    
    # Résumé d'exécution
    if scan_details['execution_summary']:
        print("\n📊 RÉSUMÉ D'EXÉCUTION")
        print("-" * 40)
        for key, value in scan_details['execution_summary'].items():
            print(f"  {key}: {value}")
    
    # Appareils découverts
    if scan_details['discovered_devices']:
        print("\n🔍 APPAREILS DÉCOUVERTS")
        print("-" * 40)
        for device in scan_details['discovered_devices']:
            print(f"  IP: {device.get('ip', 'N/A')}")
            print(f"  Type estimé: {device.get('type', 'N/A')}")
            print(f"  Ports ouverts: {device.get('open_ports', [])}")
            if device.get('banners'):
                print(f"  Bannières détectées: {len(device['banners'])}")
            print()
    
    # Scans de ports
    if scan_details['port_scans']:
        print("\n🔌 SCANS DE PORTS")
        print("-" * 40)
        for scan in scan_details['port_scans']:
            print(f"  Cible: {scan.get('target', 'N/A')}")
            print(f"  Ports testés: {scan.get('ports_tested', [])}")
            print(f"  Ports ouverts: {scan.get('open_ports', [])}")
            print(f"  Ports fermés: {scan.get('closed_ports', [])}")
            print()
    
    # Tests de vulnérabilités
    if scan_details['vulnerability_tests']:
        print("\n🛡️ TESTS DE VULNÉRABILITÉS")
        print("-" * 40)
        for test in scan_details['vulnerability_tests']:
            print(f"  Cible: {test.get('target', 'N/A')}")
            print(f"  Module: {test.get('module', 'N/A')}")
            print(f"  Test effectué: {test.get('test_type', 'N/A')}")
            print(f"  Résultat: {test.get('result', 'N/A')}")
            if test.get('details'):
                print(f"  Détails: {test['details']}")
            print()
    
    # Résultats Shodan
    if scan_details['shodan_results']:
        print("\n🌐 RECHERCHE EXTERNE SHODAN")
        print("-" * 40)
        for shodan_result in scan_details['shodan_results']:
            print(f"  Cible: {shodan_result.get('ip', 'N/A')}")
            print(f"  Pays: {shodan_result.get('country', 'N/A')}")
            print(f"  Organisation: {shodan_result.get('org', 'N/A')}")
            print(f"  Ports ouverts: {shodan_result.get('ports', [])}")
            if shodan_result.get('services'):
                print(f"  Services détectés: {len(shodan_result['services'])}")
            print()
    
    # Vulnérabilités trouvées
    print("\n🚨 VULNÉRABILITÉS TROUVÉES")
    print("-" * 40)
    
    if not results:
        print("✅ Félicitations ! Aucune vulnérabilité n'a été trouvée.")
    else:
        # On trie les résultats par sévérité pour le rapport
        severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        sorted_results = sorted(results, key=lambda x: severity_order.get(x.get('severity', 'LOW'), 0), reverse=True)
        
        print(f"📈 Synthèse : {len(sorted_results)} vulnérabilité(s) trouvée(s).\n")
        
        for vuln in sorted_results:
            severity_icon = {
                'CRITICAL': '🔴',
                'HIGH': '🟠', 
                'MEDIUM': '🟡',
                'LOW': '🔵'
            }.get(vuln.get('severity', 'LOW'), '⚪')
            
            print(f"{severity_icon} IP Cible    : {vuln.get('ip', 'N/A')}")
            print(f"   Module      : {vuln.get('module', 'N/A')}")
            print(f"   Sévérité    : {vuln.get('severity', 'N/A')}")
            print(f"   Description : {vuln.get('description', 'N/A')}")
            print("-" * 50)
        
    print("\n📋 Fin du rapport détaillé.")
    print("="*80)

def generate_html_report(results, scenario_name):
    """Génère un rapport HTML détaillé avec tous les scans effectués."""
    
    # On récupère la date pour le nom du fichier et le titre
    now = datetime.datetime.now()
    report_filename = f"report-{now.strftime('%Y-%m-%d_%H-%M-%S')}.html"
    
    # On trie les résultats par sévérité pour le rapport
    severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
    sorted_results = sorted(results, key=lambda x: severity_order.get(x.get('severity', 'LOW'), 0), reverse=True)

    # Dictionnaire pour mapper les sévérités à des couleurs CSS
    severity_colors = {
        'CRITICAL': '#dc3545', # Rouge
        'HIGH': '#fd7e14',     # Orange
        'MEDIUM': '#ffc107',   # Jaune
        'LOW': '#17a2b8'      # Bleu
    }

    # On commence à construire notre chaîne de caractères HTML
    html = f"""
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <title>Rapport d'audit IoTBreaker</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 2em; background-color: #f8f9fa; color: #333; }}
            .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 2em; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }}
            h1, h2, h3 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
            h1 {{ text-align: center; color: #2c3e50; }}
            .section {{ margin: 30px 0; padding: 20px; background: #f8f9fa; border-radius: 8px; border-left: 4px solid #3498db; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; background: white; }}
            th, td {{ padding: 12px; border: 1px solid #dee2e6; text-align: left; }}
            th {{ background-color: #3498db; color: white; font-weight: bold; }}
            tr:nth-child(even) {{ background-color: #f8f9fa; }}
            .severity {{ font-weight: bold; color: white; padding: 5px 10px; border-radius: 5px; display: inline-block; }}
            .footer {{ margin-top: 30px; text-align: center; font-size: 0.9em; color: #6c757d; padding: 20px; border-top: 1px solid #dee2e6; }}
            .summary-box {{ background: #e8f4fd; padding: 15px; border-radius: 8px; margin: 20px 0; }}
            .device-card {{ background: white; padding: 15px; margin: 10px 0; border-radius: 8px; border: 1px solid #dee2e6; }}
            .port-status {{ display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 0.8em; }}
            .port-open {{ background: #d4edda; color: #155724; }}
            .port-closed {{ background: #f8d7da; color: #721c24; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔍 Rapport d'audit IoTBreaker</h1>
            <div class="summary-box">
                <p><strong>📋 Scénario :</strong> {scenario_name}</p>
                <p><strong>📅 Date :</strong> {now.strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
    """

    # Résumé d'exécution
    if scan_details['execution_summary']:
        html += """
            <div class="section">
                <h2>📊 Résumé d'exécution</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Métrique</th>
                            <th>Valeur</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        for key, value in scan_details['execution_summary'].items():
            html += f"""
                        <tr>
                            <td>{key}</td>
                            <td>{value}</td>
                        </tr>
            """
        html += """
                    </tbody>
                </table>
            </div>
        """

    # Appareils découverts
    if scan_details['discovered_devices']:
        html += """
            <div class="section">
                <h2>🔍 Appareils découverts</h2>
        """
        for device in scan_details['discovered_devices']:
            html += f"""
                <div class="device-card">
                    <h3>📱 {device.get('ip', 'N/A')}</h3>
                    <p><strong>Type estimé:</strong> {device.get('type', 'N/A')}</p>
                    <p><strong>Ports ouverts:</strong> {', '.join(map(str, device.get('open_ports', []))) if device.get('open_ports') else 'Aucun'}</p>
                    <p><strong>Bannières détectées:</strong> {len(device.get('banners', {}))}</p>
                </div>
            """
        html += "</div>"

    # Scans de ports
    if scan_details['port_scans']:
        html += """
            <div class="section">
                <h2>🔌 Scans de ports</h2>
        """
        for scan in scan_details['port_scans']:
            html += f"""
                <div class="device-card">
                    <h3>🎯 {scan.get('target', 'N/A')}</h3>
                    <p><strong>Ports testés:</strong> {', '.join(map(str, scan.get('ports_tested', [])))}</p>
                    <p><strong>Ports ouverts:</strong> 
            """
            for port in scan.get('open_ports', []):
                html += f'<span class="port-status port-open">{port}</span> '
            html += "</p><p><strong>Ports fermés:</strong> "
            for port in scan.get('closed_ports', []):
                html += f'<span class="port-status port-closed">{port}</span> '
            html += "</p></div>"
        html += "</div>"

    # Tests de vulnérabilités
    if scan_details['vulnerability_tests']:
        html += """
            <div class="section">
                <h2>🛡️ Tests de vulnérabilités</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Cible</th>
                            <th>Module</th>
                            <th>Test</th>
                            <th>Résultat</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        for test in scan_details['vulnerability_tests']:
            html += f"""
                        <tr>
                            <td>{test.get('target', 'N/A')}</td>
                            <td>{test.get('module', 'N/A')}</td>
                            <td>{test.get('test_type', 'N/A')}</td>
                            <td>{test.get('result', 'N/A')}</td>
                        </tr>
            """
        html += """
                    </tbody>
                </table>
            </div>
        """

    # Résultats Shodan
    if scan_details['shodan_results']:
        html += """
            <div class="section">
                <h2>🌐 Recherche externe Shodan</h2>
        """
        for shodan_result in scan_details['shodan_results']:
            html += f"""
                <div class="device-card">
                    <h3>🌍 {shodan_result.get('ip', 'N/A')}</h3>
                    <p><strong>Pays:</strong> {shodan_result.get('country', 'N/A')}</p>
                    <p><strong>Organisation:</strong> {shodan_result.get('org', 'N/A')}</p>
                    <p><strong>Ports ouverts:</strong> {', '.join(map(str, shodan_result.get('ports', [])))}</p>
                    <p><strong>Services détectés:</strong> {len(shodan_result.get('services', []))}</p>
                </div>
            """
        html += "</div>"

    # Vulnérabilités trouvées
    html += """
            <div class="section">
                <h2>🚨 Vulnérabilités trouvées</h2>
    """
    
    if not sorted_results:
        html += '<p style="color: #28a745; font-weight: bold;">✅ Félicitations ! Aucune vulnérabilité n\'a été trouvée.</p>'
    else:
        html += f'<p><strong>📈 Synthèse :</strong> {len(sorted_results)} vulnérabilité(s) trouvée(s).</p>'
        html += """
                <table>
                    <thead>
                        <tr>
                            <th>Sévérité</th>
                            <th>IP Cible</th>
                            <th>Module</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        for vuln in sorted_results:
            color = severity_colors.get(vuln.get('severity', 'LOW'), '#6c757d')
            html += f"""
                        <tr>
                            <td><span class="severity" style="background-color:{color};">{vuln.get('severity', 'N/A')}</span></td>
                            <td>{vuln.get('ip', 'N/A')}</td>
                            <td>{vuln.get('module', 'N/A')}</td>
                            <td>{vuln.get('description', 'N/A')}</td>
                        </tr>
            """
        html += """
                    </tbody>
                </table>
        """
        
    html += """
            </div>
            <div class="footer">
                📋 Rapport généré par IoTBreaker v2.0 - Outil d'audit de sécurité IoT professionnel
            </div>
        </div>
    </body>
    </html>
    """

    # On écrit le contenu HTML dans un fichier
    try:
        with open(report_filename, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"\n[+] Rapport HTML généré avec succès : {report_filename}")
    except Exception as e:
        print(f"[!] ERREUR: Impossible de générer le rapport HTML : {e}") 

class PDF(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.cell(0, 10, 'Rapport d\'audit IoTBreaker', 1, 0, 'C')
        self.ln(20)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

def generate_pdf_report(results, scenario_name):
    """Génère un rapport PDF à partir de la liste des vulnérabilités."""
    now = datetime.datetime.now()
    report_filename = f"report-{now.strftime('%Y-%m-%d_%H-%M-%S')}.pdf"

    pdf = PDF()
    pdf.add_page()
    pdf.set_font('Arial', '', 12)

    # Infos du scénario
    pdf.cell(0, 10, f"Scénario exécuté : {scenario_name}", 0, 1)
    pdf.cell(0, 10, f"Date du rapport : {now.strftime('%Y-%m-%d %H:%M:%S')}", 0, 1)
    pdf.ln(10)

    # Synthèse
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, f"Synthèse : {len(results)} vulnérabilité(s) trouvée(s)", 0, 1)
    pdf.ln(5)

    if not results:
        pdf.set_font('Arial', '', 12)
        pdf.cell(0, 10, "Félicitations ! Aucune vulnérabilité n'a été trouvée.", 0, 1)
    else:
        # Tableau des résultats
        col_widths = [30, 30, 25, 105] # Largeurs des colonnes
        header = ['Sévérité', 'IP Cible', 'Module', 'Description']
        pdf.set_fill_color(0, 123, 255) # Bleu
        pdf.set_text_color(255, 255, 255)
        pdf.set_font('Arial', 'B', 10)
        for i, h in enumerate(header):
            pdf.cell(col_widths[i], 7, h, 1, 0, 'C', 1)
        pdf.ln()
        pdf.set_text_color(0, 0, 0)
        pdf.set_font('Arial', '', 9)
        severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        sorted_results = sorted(results, key=lambda x: severity_order.get(x.get('severity', 'LOW'), 0), reverse=True)
        for vuln in sorted_results:
            pdf.cell(col_widths[0], 6, vuln.get('severity', 'N/A'), 1)
            pdf.cell(col_widths[1], 6, vuln.get('ip', 'N/A'), 1)
            pdf.cell(col_widths[2], 6, vuln.get('module', 'N/A'), 1)
            pdf.multi_cell(col_widths[3], 6, vuln.get('description', 'N/A'), 1)
    try:
        pdf.output(report_filename)
        print(f"\n[+] Rapport PDF généré avec succès : {report_filename}")
    except Exception as e:
        print(f"[!] ERREUR: Impossible de générer le rapport PDF : {e}") 