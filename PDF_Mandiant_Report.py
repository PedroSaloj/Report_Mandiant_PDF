import re
import io
import os
import datetime
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
# Importaciones necesarias de ReportLab para generar el PDF
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, PageBreak, ListFlowable, ListItem
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors

# ==========================================
# 0. FUNCIONES DE UTILIDAD (Directorios y Tiempo)
# ==========================================

def setup_directories(input_dir_name="ENTRADA", output_dir_name="OUTPUT"):
    """Crea los directorios de entrada y salida si no existen."""
    base_path = os.path.dirname(os.path.abspath(__file__))
    input_path = os.path.join(base_path, input_dir_name)
    output_path = os.path.join(base_path, output_dir_name)

    if not os.path.exists(input_path):
        os.makedirs(input_path)
        print(f"ℹ️ Directorio creado: {input_path}")
    
    if not os.path.exists(output_path):
        os.makedirs(output_path)
        print(f"ℹ️ Directorio creado: {output_path}")
        
    return input_path, output_path

def get_timestamped_filename(base_name, extension=".pdf"):
    """Genera un nombre de archivo con marca de tiempo."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{base_name}_{timestamp}{extension}"

# ==========================================
# 1. FUNCIONES DE PARSING (Extracción de datos)
# ==========================================

def parse_categories_report(text_content):
    """Extrae los datos de la tabla del reporte de categorías."""
    data = []
    regex = r"^\s*([^|=]+?)\s*\|\s*(\d+)\s*\|\s*([\d\.]+)"
    
    for line in text_content.splitlines():
        match = re.search(regex, line)
        if match:
            data.append({
                'Categoria': match.group(1).strip(),
                'Cantidad_IPs': int(match.group(2)),
                'Score_Promedio': float(match.group(3))
            })
    
    if not data:
        print("⚠️ Advertencia: No se encontraron datos válidos en el texto de categorías.")
        return pd.DataFrame(columns=['Categoria', 'Cantidad_IPs', 'Score_Promedio'])
        
    return pd.DataFrame(data)

def parse_full_report(text_content):
    """Extrae IPs/URLs y Scores del reporte completo."""
    data = []
    separator = '------------------------------------------------------------'
    blocks = text_content.split(separator)
    
    ip_regex = r"🔍 IP:\s+(.*)"
    score_regex = r"📊 Mandiant Score:\s+(\d+)"
    
    for block in blocks:
        clean_block = block.strip()
        if not clean_block: continue
            
        ip_match = re.search(ip_regex, clean_block)
        score_match = re.search(score_regex, clean_block)
        
        if ip_match and score_match:
            data.append({
                'IoC': ip_match.group(1).strip(),
                'Score': int(score_match.group(1))
            })
            
    if not data:
        print("⚠️ Advertencia: No se encontraron indicadores válidos en el texto del reporte completo.")
        return pd.DataFrame(columns=['IoC', 'Score'])

    return pd.DataFrame(data)

def parse_geolocation_report(text_content):
    """
    Extrae datos del reporte de geolocalización.
    Retorna un diccionario estructurado con resumen y detalles por país.
    """
    geo_data = {'summary': {}, 'details': {}}
    
    # 1. Extraer Resumen Estadístico
    stats_regexs = {
        'total': r"Total de IPs analizadas:\s*(\d+)",
        'success': r"Análisis exitosos:\s*(\d+)",
        'failed': r"Análisis fallidos:\s*(\d+)",
        'rate': r"Tasa de éxito:\s*([\d\.]+)%",
        'countries': r"Países únicos encontrados:\s*(\d+)"
    }
    
    for key, regex in stats_regexs.items():
        match = re.search(regex, text_content)
        if match:
            geo_data['summary'][key] = match.group(1)

    # 2. Extraer Distribución por País
    # Dividimos el texto a partir de la sección de distribución
    if "DISTRIBUCIÓN POR PAÍS:" in text_content:
        dist_section = text_content.split("DISTRIBUCIÓN POR PAÍS:")[1]
        
        current_country = None
        # Regex para encabezado de país: Ej: "United States (88 IPs):"
        country_header_regex = r"^\s*([A-Za-z\s]+)\s\((\d+)\sIPs\):"
        # Regex para línea de IP: Ej: "• 18.116.239.38 - Dublin, Ohio (Amazon.com, Inc.)"
        ip_line_regex = r"^\s*•\s*([\d\.]+)\s-\s(.*?)\s\((.*?)\)"

        for line in dist_section.splitlines():
            line = line.strip()
            if not line: continue
            
            # Verificar si es encabezado de país
            country_match = re.search(country_header_regex, line)
            if country_match:
                current_country = country_match.group(1).strip()
                geo_data['details'][current_country] = []
                continue
            
            # Verificar si es línea de IP (si ya tenemos un país seleccionado)
            if current_country:
                ip_match = re.search(ip_line_regex, line)
                if ip_match:
                    geo_data['details'][current_country].append({
                        'ip': ip_match.group(1),
                        'location': ip_match.group(2),
                        'isp': ip_match.group(3)
                    })

    if not geo_data['summary'] and not geo_data['details']:
         print("⚠️ Advertencia: No se encontraron datos válidos en el reporte de geolocalización.")
         return None

    return geo_data

# ==========================================
# 2. FUNCIONES DE GRÁFICOS (Visualización)
# ==========================================
# (Sin cambios en esta sección respecto a la versión anterior)
def create_category_bar_chart(df):
    if df.empty: return None
    plt.figure(figsize=(8, 4))
    sns.set_theme(style="whitegrid")
    df_sorted = df.sort_values('Cantidad_IPs', ascending=False)
    ax = sns.barplot(data=df_sorted, x='Categoria', y='Cantidad_IPs', palette='viridis', hue='Categoria', legend=False)
    plt.title('Distribución de IoCs por Categoría', fontsize=14, fontweight='bold')
    plt.xlabel('Categoría de Amenaza', fontsize=12)
    plt.ylabel('Cantidad Total', fontsize=12)
    plt.xticks(rotation=15, ha='right')
    for i in ax.containers: ax.bar_label(i,)
    plt.tight_layout()
    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format='png', dpi=300, bbox_inches='tight')
    img_buffer.seek(0)
    plt.close()
    return img_buffer

def create_top_scores_chart(df, top_n=15):
    if df.empty: return None
    df_sorted = df.sort_values(by='Score', ascending=False)
    top_df = df_sorted.head(top_n)
    height_fig = max(4, len(top_df) * 0.4) 
    plt.figure(figsize=(9, height_fig))
    sns.set_theme(style="whitegrid")
    ax = sns.barplot(data=top_df, y='IoC', x='Score', orient='h', hue='Score', palette='magma', legend=False, dodge=False)
    plt.title(f'Top {len(top_df)} Indicadores con Mayor Score de Riesgo', fontsize=14, fontweight='bold')
    plt.xlabel('Mandiant Score', fontsize=12)
    plt.ylabel('')
    current_xmax = ax.get_xlim()[1]
    ax.set_xlim(0, max(100, current_xmax * 1.05))
    for i in ax.containers: ax.bar_label(i, padding=3, fmt='%d', fontweight='bold')
    plt.tight_layout()
    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format='png', dpi=300, bbox_inches='tight')
    img_buffer.seek(0)
    plt.close()
    return img_buffer

# ==========================================
# 3. FUNCIÓN DE GENERACIÓN DE PDF (ReportLab)
# ==========================================

def generate_pdf_report(output_path, cat_text, full_text, geo_text):
    print("\n--- Iniciando proceso de generación ---")
    
    # 1. Procesar datos
    print("Procesando datos de los archivos...")
    df_categories = parse_categories_report(cat_text)
    df_full = parse_full_report(full_text)
    geo_data = parse_geolocation_report(geo_text)

    if df_categories.empty and df_full.empty and geo_data is None:
        print("\n❌ Error crítico: No hay datos válidos en ninguno de los archivos. Se cancela el PDF.")
        return

    # 2. Generar gráficos
    print("Generando gráficos estadísticos...")
    cat_chart_buffer = create_category_bar_chart(df_categories)
    top_scores_chart_buffer = create_top_scores_chart(df_full, top_n=15)

    # 3. Maquetar PDF
    print(f"Maquetando documento PDF...")
    doc = SimpleDocTemplate(
        output_path, pagesize=letter,
        rightMargin=inch/2, leftMargin=inch/2,
        topMargin=inch/2, bottomMargin=inch/2
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='CustomTitle', parent=styles['Title'], spaceAfter=16, textColor='#2c3e50'))
    styles.add(ParagraphStyle(name='CustomHeader', parent=styles['Heading2'], spaceBefore=16, spaceAfter=8, textColor='#34495e'))
    styles.add(ParagraphStyle(name='CustomSubHeader', parent=styles['Heading3'], spaceBefore=12, spaceAfter=6, textColor='#7f8c8d'))
    styles.add(ParagraphStyle(name='BulletPoint', parent=styles['Normal'], leftIndent=12, spaceAfter=2))
    
    story = []

    # --- Título Principal ---
    story.append(Paragraph("Reporte Automatizado de Ciberseguridad", styles['CustomTitle']))
    story.append(Paragraph(f"Generado el: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M UTC')}", styles['Normal']))
    story.append(Spacer(1, 24))

    # --- Sección 1: Gráfico de Categorías ---
    story.append(Paragraph("1. Resumen por Categorías de Amenaza", styles['CustomHeader']))
    if cat_chart_buffer:
        story.append(Paragraph("Distribución del volumen total de indicadores agrupados por categoría detectada.", styles['Normal']))
        story.append(Spacer(1, 12))
        img1 = Image(cat_chart_buffer, width=7*inch, height=3.5*inch, kind='proportional')
        story.append(img1)
        story.append(Spacer(1, 20))
    else:
        story.append(Paragraph("Sin datos de categorías disponibles.", styles['Normal']))

    # --- Sección 2: Gráfico de Top Scores ---
    story.append(PageBreak()) 
    story.append(Paragraph("2. Ranking de Riesgo (Top Scores)", styles['CustomHeader']))
    if top_scores_chart_buffer:
        story.append(Paragraph("Indicadores con los puntajes de riesgo más altos. Se recomienda priorizar su investigación.", styles['Normal']))
        story.append(Spacer(1, 12))
        img2 = Image(top_scores_chart_buffer, width=7.5*inch, height=8*inch, kind='proportional')
        story.append(img2)
    else:
        story.append(Paragraph("Sin datos de scores disponibles para el ranking.", styles['Normal']))

    # --- Sección 3: Geolocalización (NUEVA SECCIÓN) ---
    story.append(PageBreak())
    story.append(Paragraph("3. Análisis de Geolocalización de IPs", styles['CustomHeader']))

    if geo_data and geo_data['summary']:
        # Resumen Estadístico Geo
        summ = geo_data['summary']
        stats_text = (
            f"Se analizaron un total de <b>{summ.get('total', 'N/A')}</b> IPs, "
            f"con una tasa de éxito del <b>{summ.get('rate', 'N/A')}%</b>. "
            f"Se identificaron <b>{summ.get('countries', 'N/A')}</b> países únicos."
        )
        story.append(Paragraph(stats_text, styles['Normal']))
        story.append(Spacer(1, 12))

        # Detalles por país
        if geo_data['details']:
            for country, ips in geo_data['details'].items():
                # Encabezado del país con cantidad
                story.append(Paragraph(f"{country} ({len(ips)} IPs)", styles['CustomSubHeader']))
                # Lista de IPs
                bullet_list = []
                for item in ips:
                    # Formato: IP - Ubicación (ISP)
                    text = f"{item['ip']} - {item['location']} <font color=grey>({item['isp']})</font>"
                    bullet_list.append(ListItem(Paragraph(text, styles['BulletPoint'])))
                
                story.append(ListFlowable(bullet_list, bulletType='bullet', start='•', leftIndent=12))
                story.append(Spacer(1, 8))
        else:
             story.append(Paragraph("No hay detalles de distribución por país disponibles.", styles['Normal']))
    else:
        story.append(Paragraph("No se encontraron datos válidos de geolocalización.", styles['Normal']))

    # --- Guardar PDF ---
    try:
        doc.build(story)
        print(f"\n✅ ÉXITO: Reporte PDF generado correctamente en:\n   -> {output_path}")
    except PermissionError:
         print(f"\n❌ ERROR DE PERMISO: No se pudo escribir en '{output_path}'. Cerciórate de que no esté abierto.")
    except Exception as e:
         print(f"\n❌ Error inesperado al guardar el PDF: {e}")


# ==========================================
# BLOQUE PRINCIPAL DE EJECUCIÓN
# ==========================================
if __name__ == "__main__":
    os.system('cls' if os.name == 'nt' else 'clear')

    # 1. Configurar directorios
    input_dir, output_dir = setup_directories()

    print("=========================================")
    print("   Generador de Reportes de Seguridad    ")
    print("=========================================\n")
    print(f"ℹ️  Por favor, coloca tus 3 archivos TXT de reporte dentro de la carpeta:\n   -> {input_dir}\n")

    # 2. Solicitar nombres de archivo
    file_cat = input("1. Nombre del TXT 'Reporte por Categorías' (ej. cat.txt): ").strip()
    file_full = input("2. Nombre del TXT 'Reporte Completo' (ej. full.txt): ").strip()
    file_geo = input("3. Nombre del TXT 'Reporte de Geolocalización' (ej. geo.txt): ").strip()
    
    # 3. Definir rutas completas
    path_cat = os.path.join(input_dir, file_cat)
    path_full = os.path.join(input_dir, file_full)
    path_geo = os.path.join(input_dir, file_geo)
    
    # 4. Definir nombre de salida con timestamp
    output_filename = get_timestamped_filename("Reporte_Seguridad_Completo")
    output_path = os.path.join(output_dir, output_filename)

    # 5. Verificar y leer archivos
    print("\nVerificando archivos de entrada...")
    try:
        with open(path_cat, 'r', encoding='utf-8') as f: cat_text = f.read()
        print(f"  [OK] {file_cat}")
        with open(path_full, 'r', encoding='utf-8') as f: full_text = f.read()
        print(f"  [OK] {file_full}")
        with open(path_geo, 'r', encoding='utf-8') as f: geo_text = f.read()
        print(f"  [OK] {file_geo}")
            
        # 6. Ejecutar generación
        generate_pdf_report(output_path, cat_text, full_text, geo_text)

    except FileNotFoundError as e:
        print(f"\n❌ ERROR: No se encontró el archivo: {os.path.basename(e.filename)}")
        print(f"   Asegúrate de que esté dentro de la carpeta '{input_dir_name}'.")
    except Exception as e:
        print(f"\n❌ Ocurrió un error inesperado: {e}")

    input("\nPresiona Enter para salir...")