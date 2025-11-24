import re
import io
import os
import datetime
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.font_manager as fm
import seaborn as sns
# Importaciones de ReportLab
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, PageBreak, ListFlowable, ListItem
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER

# ==========================================
# CONFIGURACIÓN GLOBAL DE FUENTES (Para Emojis)
# ==========================================
# Intentamos configurar Matplotlib para que use fuentes que soporten emojis según el SO.
# Esto soluciona el problema de los cuadros "□□" en las banderas.
try:
    if os.name == 'nt': # Windows
        plt.rcParams['font.family'] = ['Segoe UI Emoji', 'sans-serif']
    elif os.sys.platform == 'darwin': # macOS
        plt.rcParams['font.family'] = ['Apple Color Emoji', 'sans-serif']
    else: # Linux/Otros (intento genérico)
        plt.rcParams['font.family'] = ['Noto Color Emoji', 'DejaVu Sans', 'sans-serif']
except Exception as e:
    print(f"⚠️ Advertencia: No se pudo configurar la fuente de emojis: {e}")
    # Si falla, los gráficos se generarán pero podrían faltar las banderas.


# ==========================================
# 0. FUNCIONES DE UTILIDAD Y CONFIGURACIÓN
# ==========================================

def setup_directories(input_dir_name="ENTRADA", output_dir_name="OUTPUT"):
    """Crea los directorios de entrada y salida si no existen."""
    base_path = os.path.dirname(os.path.abspath(__file__))
    input_path = os.path.join(base_path, input_dir_name)
    output_path = os.path.join(base_path, output_dir_name)
    os.makedirs(input_path, exist_ok=True)
    os.makedirs(output_path, exist_ok=True)
    return input_path, output_path

def get_timestamped_filename(base_name, extension=".pdf"):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{base_name}_{timestamp}{extension}"

def get_country_flag_emoji(country_name):
    """Devuelve el emoji de bandera para un país dado (Mapeo básico)."""
    c = country_name.strip()
    mapping = {
        "United States": "🇺🇸", "The Netherlands": "🇳🇱", "Germany": "🇩🇪",
        "China": "🇨🇳", "Spain": "🇪🇸", "Canada": "🇨🇦", "Singapore": "🇸🇬",
        "United Kingdom": "🇬🇧", "France": "🇫🇷", "Russia": "🇷🇺",
        "India": "🇮🇳", "Japan": "🇯🇵", "Brazil": "🇧🇷", "Mexico": "🇲🇽",
        "Italy": "🇮🇹", "Australia": "🇦🇺"
    }
    # Devuelve bandera blanca si no encuentra el país en la lista
    return mapping.get(c, "🏳️")

# ==========================================
# 1. FUNCIONES DE PARSING (Extracción de datos)
# ==========================================

def parse_categories_report(text_content):
    data = []
    # Regex flexible para espacios: \s* en lugar de espacios fijos
    regex = r"^\s*([^|=]+?)\s*\|\s*(\d+)\s*\|\s*([\d\.]+)"
    for line in text_content.splitlines():
        match = re.search(regex, line)
        if match:
            data.append({
                'Categoria': match.group(1).strip(),
                'Cantidad_IPs': int(match.group(2)),
                'Score_Promedio': float(match.group(3))
            })
    return pd.DataFrame(data)

def parse_full_report(text_content):
    """Extrae IPs y Scores. Versión mejorada y más robusta."""
    data = []
    # Usamos un separador que coincida con la línea de guiones
    separator = '------------------------------------------------------------'
    blocks = text_content.split(separator)
    
    print(f"   > Depuración: Se encontraron {len(blocks)} bloques potenciales en el reporte completo.")

    # Regex más flexibles: \s* permite 0 o más espacios
    ip_regex = r"🔍 IP:\s*(.*)"
    score_regex = r"📊 Mandiant Score:\s*(\d+)"
    
    count_matches = 0
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
            count_matches += 1
            
    print(f"   > Depuración: Se lograron extraer {count_matches} indicadores válidos con Score.")
    return pd.DataFrame(data)

def parse_geolocation_report(text_content):
    geo_data = {'summary': {}, 'details': {}, 'df_counts': pd.DataFrame()}
    
    # 1. Extraer Resumen Estadístico
    stats_regexs = {
        'total': r"Total de IPs analizadas:\s*(\d+)",
        'rate': r"Tasa de éxito:\s*([\d\.]+)%",
        'countries': r"Países únicos encontrados:\s*(\d+)"
    }
    for key, regex in stats_regexs.items():
        match = re.search(regex, text_content)
        if match: geo_data['summary'][key] = match.group(1)

    # 2. Extraer Distribución por País
    if "DISTRIBUCIÓN POR PAÍS:" in text_content:
        try:
            dist_section = text_content.split("DISTRIBUCIÓN POR PAÍS:")[1]
        except IndexError:
            print("⚠️ Advertencia: No se encontró la sección 'DISTRIBUCIÓN POR PAÍS' en el reporte de geo.")
            return geo_data

        country_header_regex = r"^\s*([A-Za-z\s]+)\s\((\d+)\sIPs\):"
        ip_line_regex = r"^\s*•\s*([\d\.]+)\s-\s(.*?)\s\((.*?)\)"

        current_country = None
        country_counts_list = []

        for line in dist_section.splitlines():
            line = line.strip()
            if not line: continue
            
            country_match = re.search(country_header_regex, line)
            if country_match:
                current_country = country_match.group(1).strip()
                count = int(country_match.group(2))
                geo_data['details'][current_country] = []
                country_counts_list.append({'Country': current_country, 'Count': count})
                continue
            
            if current_country and (ip_match := re.search(ip_line_regex, line)):
                geo_data['details'][current_country].append({
                    'ip': ip_match.group(1), 'location': ip_match.group(2), 'isp': ip_match.group(3)
                })
        
        geo_data['df_counts'] = pd.DataFrame(country_counts_list)

    return geo_data

# ==========================================
# 2. FUNCIONES DE GRÁFICOS (Visualización)
# ==========================================

def save_chart_to_buffer(fig):
    """Guarda una figura matplotlib en un buffer de memoria."""
    img_buffer = io.BytesIO()
    # Usamos bbox_inches='tight' para evitar que se corten etiquetas largas
    fig.savefig(img_buffer, format='png', dpi=300, bbox_inches='tight')
    img_buffer.seek(0)
    plt.close(fig)
    return img_buffer

def create_category_bar_chart(df):
    if df.empty: return None
    fig = plt.figure(figsize=(8, 4))
    sns.set_theme(style="whitegrid")
    # Re-aplicar fuente por si seaborn la sobrescribe
    if os.name == 'nt': plt.rcParams['font.family'] = ['Segoe UI Emoji', 'sans-serif']

    df_sorted = df.sort_values('Cantidad_IPs', ascending=False)
    ax = sns.barplot(data=df_sorted, x='Categoria', y='Cantidad_IPs', palette='viridis', hue='Categoria', legend=False)
    plt.title('Distribución de IoCs por Categoría', fontsize=14, fontweight='bold')
    plt.xlabel('Categoría', fontsize=11)
    plt.ylabel('Total IPs', fontsize=11)
    plt.xticks(rotation=15, ha='right')
    for i in ax.containers: ax.bar_label(i,)
    plt.tight_layout()
    return save_chart_to_buffer(fig)

def create_top_scores_chart(df, top_n=15):
    if df.empty: return None
    fig = plt.figure(figsize=(9, max(4, top_n * 0.4)))
    sns.set_theme(style="whitegrid")
    if os.name == 'nt': plt.rcParams['font.family'] = ['Segoe UI Emoji', 'sans-serif']

    df_sorted = df.sort_values(by='Score', ascending=False).head(top_n)
    
    ax = sns.barplot(data=df_sorted, y='IoC', x='Score', orient='h', hue='Score', palette='magma', legend=False, dodge=False)
    plt.title(f'Top {len(df_sorted)} Indicadores con Mayor Score de Riesgo', fontsize=14, fontweight='bold')
    plt.xlabel('Mandiant Score', fontsize=11)
    plt.ylabel('')
    # Asegurar que el eje X llegue al menos a 100
    ax.set_xlim(0, max(100, ax.get_xlim()[1] * 1.05))
    for i in ax.containers: ax.bar_label(i, padding=3, fmt='%d', fontweight='bold')
    plt.tight_layout()
    return save_chart_to_buffer(fig)

def create_geo_country_chart(df):
    if df.empty: return None
    fig = plt.figure(figsize=(8, max(3, len(df) * 0.5)))
    sns.set_theme(style="whitegrid")
    # Asegurar fuente de emojis para este gráfico específicamente
    if os.name == 'nt': plt.rcParams['font.family'] = ['Segoe UI Emoji', 'sans-serif']
    
    # Preparar etiquetas con banderas
    df_plot = df.copy()
    df_plot['Label'] = df_plot['Country'].apply(lambda x: f"{get_country_flag_emoji(x)}  {x}")
    df_sorted = df_plot.sort_values('Count', ascending=False)
    
    ax = sns.barplot(data=df_sorted, y='Label', x='Count', orient='h', palette='Spectral', hue='Count', legend=False)
    
    plt.title('Total de IPs Detectadas por País', fontsize=14, fontweight='bold')
    plt.xlabel('Cantidad de IPs', fontsize=11)
    plt.ylabel('')
    
    for i in ax.containers: ax.bar_label(i, padding=3, fontweight='bold')
    plt.tight_layout()
    
    return save_chart_to_buffer(fig)

# ==========================================
# 3. GENERACIÓN DE PDF (ReportLab)
# ==========================================

def generate_pdf_report(output_path, cat_text, full_text, geo_text):
    print("\n[PROCESANDO] Analizando archivos de entrada...")
    df_cats = parse_categories_report(cat_text)
    df_full = parse_full_report(full_text)
    geo_data = parse_geolocation_report(geo_text)

    # Verificación de datos críticos
    if df_full.empty:
        print("❌ ADVERTENCIA CRÍTICA: No se pudieron extraer Scores del reporte completo. Verifica el formato del archivo TXT.")

    if df_cats.empty and df_full.empty and geo_data['df_counts'].empty:
        print("\n[ERROR] No hay datos válidos en ninguno de los archivos. PDF cancelado.")
        return

    print("[GRÁFICOS] Generando visualizaciones en memoria...")
    # Se pasa la cantidad de datos disponibles a las funciones de gráficos
    chart_cats = create_category_bar_chart(df_cats)
    # Si df_full está vacío, create_top_scores_chart devuelve None y se maneja en el PDF
    chart_scores = create_top_scores_chart(df_full)
    chart_geo = create_geo_country_chart(geo_data['df_counts'])

    print(f"[PDF] Maquetando documento: {os.path.basename(output_path)}...")
    doc = SimpleDocTemplate(output_path, pagesize=letter, rightMargin=inch/2, leftMargin=inch/2, topMargin=inch/2, bottomMargin=inch/2)
    
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='CoverTitle', parent=styles['Title'], fontSize=24, leading=30, spaceAfter=20, alignment=TA_CENTER, textColor='#2c3e50'))
    styles.add(ParagraphStyle(name='CoverSubTitle', parent=styles['Heading2'], fontSize=16, leading=20, spaceAfter=40, alignment=TA_CENTER, textColor='#7f8c8d'))
    styles.add(ParagraphStyle(name='CoverTimestamp', parent=styles['Normal'], fontSize=12, alignment=TA_CENTER, textColor='#95a5a6'))
    styles.add(ParagraphStyle(name='SectionHeader', parent=styles['Heading2'], spaceBefore=16, spaceAfter=8, textColor='#34495e'))
    styles.add(ParagraphStyle(name='CountryHeader', parent=styles['Heading3'], spaceBefore=12, spaceAfter=4, textColor='#2980b9'))
    styles.add(ParagraphStyle(name='IPBullet', parent=styles['Normal'], leftIndent=12,leading=14))

    story = []
    timestamp_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M UTC')

    # --- PORTADA ---
    story.append(Spacer(1, 2*inch))
    story.append(Paragraph("Reporte Automatizado de Ciberseguridad", styles['CoverTitle']))
    story.append(Paragraph("con Mandiant Advance Threat Intelligence", styles['CoverSubTitle']))
    story.append(Spacer(1, 1*inch))
    story.append(Paragraph(f"Generado el: {timestamp_str}", styles['CoverTimestamp']))
    story.append(PageBreak())

    # --- SECCIÓN 1: Categorías ---
    story.append(Paragraph("1. Resumen por Categorías de Amenaza", styles['SectionHeader']))
    if chart_cats:
        img = Image(chart_cats, width=7*inch, height=3.5*inch, kind='proportional')
        story.append(img)
    else:
        story.append(Paragraph("Sin datos disponibles en el archivo de categorías.", styles['Normal']))
    story.append(Spacer(1, 20))

    # --- SECCIÓN 2: Top Scores ---
    story.append(Paragraph("2. Ranking de Riesgo (Top Scores)", styles['SectionHeader']))
    if chart_scores:
        # Altura proporcional a la cantidad de datos, máximo 8 pulgadas
        height_img = min(8, max(4, len(df_full) * 0.4)) * inch
        img = Image(chart_scores, width=7.5*inch, height=height_img, kind='proportional')
        story.append(img)
    else:
        story.append(Paragraph("Sin datos disponibles. No se pudieron extraer IPs y Scores del reporte completo.", styles['Normal']))

    # --- SECCIÓN 3: Geolocalización ---
    story.append(PageBreak())
    story.append(Paragraph("3. Análisis de Geolocalización de IPs", styles['SectionHeader']))

    if not geo_data['df_counts'].empty:
        summ = geo_data['summary']
        stats_txt = f"Se analizaron <b>{summ.get('total','0')}</b> IPs. Tasa de éxito: <b>{summ.get('rate','0')}%</b>. Países únicos: <b>{summ.get('countries','0')}</b>."
        story.append(Paragraph(stats_txt, styles['Normal']))
        story.append(Spacer(1, 12))
        
        if chart_geo:
            # Altura proporcional
            height_img = min(6, max(3, len(geo_data['df_counts']) * 0.5)) * inch
            img_geo = Image(chart_geo, width=7*inch, height=height_img, kind='proportional')
            story.append(img_geo)
            story.append(Spacer(1, 20))
        
        story.append(Paragraph("Detalle de IPs por Ubicación:", styles['Heading3']))
        for country, ips in geo_data['details'].items():
            flag = get_country_flag_emoji(country)
            story.append(Paragraph(f"{flag} {country} ({len(ips)} IPs)", styles['CountryHeader']))
            
            bullets = []
            for item in ips:
                txt = f"<b>{item['ip']}</b> - {item['location']} <font color=#7f8c8d size=9>({item['isp']})</font>"
                bullets.append(ListItem(Paragraph(txt, styles['IPBullet'])))
            story.append(ListFlowable(bullets, bulletType='bullet', start='•', leftIndent=10))
            story.append(Spacer(1, 6))
    else:
        story.append(Paragraph("No se encontraron datos válidos en el reporte de geolocalización.", styles['Normal']))

    try:
        doc.build(story)
        print(f"\n✅ [EXITO] PDF guardado en: {output_path}")
    except PermissionError:
         print(f"\n❌ [ERROR] No se pudo escribir en el PDF. Ciérralo si está abierto.")
    except Exception as e:
         print(f"\n❌ [ERROR] Inesperado al guardar PDF: {e}")

# ==========================================
# EJECUCIÓN PRINCIPAL
# ==========================================
if __name__ == "__main__":
    os.system('cls' if os.name == 'nt' else 'clear')
    input_dir, output_dir = setup_directories()

    print("=== Generador de Reportes con Mandiant ATI ===")
    print(f"🗂️ Coloca los 3 archivos TXT en la carpeta: ./{os.path.basename(input_dir)}/\n")

    # Valores por defecto para pruebas rápidas (puedes borrarlos)
    def_cat = "source_37.txt"
    def_full = "source_1.txt"
    def_geo = "source_189.txt"

    f_cat = input(f"1. TXT Categorías [{def_cat}]: ").strip() or def_cat
    f_full = input(f"2. TXT Completo [{def_full}]: ").strip() or def_full
    f_geo = input(f"3. TXT Geolocalización [{def_geo}]: ").strip() or def_geo
    
    p_cat = os.path.join(input_dir, f_cat)
    p_full = os.path.join(input_dir, f_full)
    p_geo = os.path.join(input_dir, f_geo)
    
    out_name = get_timestamped_filename("Reporte_Ciberseguridad_Mandiant")
    out_path = os.path.join(output_dir, out_name)

    try:
        print("\nVerificando entradas...")
        # Leemos con 'utf-8-sig' para manejar BOM si existe
        with open(p_cat, 'r', encoding='utf-8-sig') as f: t_cat = f.read()
        with open(p_full, 'r', encoding='utf-8-sig') as f: t_full = f.read()
        with open(p_geo, 'r', encoding='utf-8-sig') as f: t_geo = f.read()
        print("Archivos leídos correctamente.")
        
        generate_pdf_report(out_path, t_cat, t_full, t_geo)

    except FileNotFoundError as e:
        print(f"\n❌ [ERROR] Archivo no encontrado: {os.path.basename(e.filename)}")
        print("Verifica que el nombre sea correcto y esté en la carpeta de ENTRADA.")
    except UnicodeDecodeError as e:
         print(f"\n❌ [ERROR] Problema de codificación al leer un archivo: {e}")
         print("Intenta guardar tus TXT con codificación UTF-8.")
    except Exception as e:
        print(f"\n❌ [ERROR] Inesperado en el flujo principal: {e}")

    input("\nPresiona Enter para salir...")