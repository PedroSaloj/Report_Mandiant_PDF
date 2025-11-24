import re
import io
import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
# Importaciones necesarias de ReportLab para generar el PDF
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

# ==========================================
# 1. FUNCIONES DE PARSING (Extracción de datos)
# ==========================================

def parse_categories_report(text_content):
    """Extrae los datos de la tabla del reporte de categorías."""
    data = []
    # Regex para capturar: Nombre Categoria | Cantidad | Score Promedio
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
        print("Advertencia: No se encontraron datos válidos en el texto de categorías.")
        return pd.DataFrame(columns=['Categoria', 'Cantidad_IPs', 'Score_Promedio'])
        
    return pd.DataFrame(data)

def parse_full_report(text_content):
    """Extrae IPs/URLs y Scores del reporte completo."""
    data = []
    # Separador constante entre bloques
    separator = '------------------------------------------------------------'
    blocks = text_content.split(separator)
    
    # Regex para extraer IP y Score
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
        print("Advertencia: No se encontraron indicadores válidos en el texto del reporte completo.")
        return pd.DataFrame(columns=['IoC', 'Score'])

    return pd.DataFrame(data)

# ==========================================
# 2. FUNCIONES DE GRÁFICOS (Visualización)
# ==========================================

def create_category_bar_chart(df):
    """Genera gráfico de barras vertical de cantidad por categoría."""
    if df.empty: return None

    plt.figure(figsize=(8, 4))
    sns.set_theme(style="whitegrid")
    
    # Ordenar descendente
    df_sorted = df.sort_values('Cantidad_IPs', ascending=False)
    
    ax = sns.barplot(data=df_sorted, x='Categoria', y='Cantidad_IPs', palette='viridis', hue='Categoria', legend=False)
    
    plt.title('Distribución de IoCs por Categoría', fontsize=14, fontweight='bold')
    plt.xlabel('Categoría de Amenaza', fontsize=12)
    plt.ylabel('Cantidad Total', fontsize=12)
    plt.xticks(rotation=15, ha='right')
    
    # Etiquetas de datos (CORREGIDO AQUÍ)
    for i in ax.containers:
        ax.bar_label(i,)
        
    plt.tight_layout()
    
    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format='png', dpi=300, bbox_inches='tight')
    img_buffer.seek(0)
    plt.close()
    return img_buffer

def create_top_scores_chart(df, top_n=15):
    """Genera gráfico de barras HORIZONTAL para el ranking de scores."""
    if df.empty: return None
        
    # Ordenar y tomar el top N
    df_sorted = df.sort_values(by='Score', ascending=False)
    top_df = df_sorted.head(top_n)
    
    # Altura dinámica según cantidad de datos
    height_fig = max(4, len(top_df) * 0.4) 
    plt.figure(figsize=(9, height_fig))
    sns.set_theme(style="whitegrid")
    
    # Gráfico horizontal
    ax = sns.barplot(data=top_df, y='IoC', x='Score', orient='h', 
                     hue='Score', palette='magma', legend=False, dodge=False)
    
    plt.title(f'Top {len(top_df)} Indicadores con Mayor Score de Riesgo', fontsize=14, fontweight='bold')
    plt.xlabel('Mandiant Score', fontsize=12)
    plt.ylabel('')
    
    # Eje X mínimo hasta 100
    current_xmax = ax.get_xlim()[1]
    ax.set_xlim(0, max(100, current_xmax * 1.05))
    
    # Etiquetas de datos
    for i in ax.containers:
        ax.bar_label(i, padding=3, fmt='%d', fontweight='bold')

    plt.tight_layout()
    
    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format='png', dpi=300, bbox_inches='tight')
    img_buffer.seek(0)
    plt.close()
    return img_buffer

# ==========================================
# 3. FUNCIÓN DE GENERACIÓN DE PDF (ReportLab)
# ==========================================

def generate_pdf_report(output_filename, cat_text_content, full_text_content):
    print("\n--- Iniciando proceso de generación ---")
    print("Procesando datos de los archivos...")
    df_categories = parse_categories_report(cat_text_content)
    df_full = parse_full_report(full_text_content)

    if df_categories.empty and df_full.empty:
        print("\n❌ Error crítico: No se pudieron extraer datos de ninguno de los archivos proporcionados. El PDF no se generará.")
        return

    print("Generando gráficos estadísticos en memoria...")
    cat_chart_buffer = create_category_bar_chart(df_categories)
    top_scores_chart_buffer = create_top_scores_chart(df_full, top_n=15)

    print(f"Maquetando el documento PDF: {output_filename}...")
    doc = SimpleDocTemplate(
        output_filename, pagesize=letter,
        rightMargin=inch/2, leftMargin=inch/2,
        topMargin=inch/2, bottomMargin=inch/2
    )

    styles = getSampleStyleSheet()
    # Estilos personalizados
    styles.add(ParagraphStyle(name='CustomTitle', parent=styles['Title'], spaceAfter=16, textColor='#2c3e50'))
    styles.add(ParagraphStyle(name='CustomHeader', parent=styles['Heading2'], spaceBefore=16, spaceAfter=8, textColor='#34495e'))
    
    story = []

    # --- Título ---
    story.append(Paragraph("Reporte Automatizado de Indicadores de Compromiso", styles['CustomTitle']))
    story.append(Paragraph(f"Generado el: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M UTC')}", styles['Normal']))
    story.append(Spacer(1, 24))

    # --- Sección 1: Gráfico de Categorías ---
    story.append(Paragraph("1. Resumen por Categorías de Amenaza", styles['CustomHeader']))
    if cat_chart_buffer:
        story.append(Paragraph("Distribución del volumen total de indicadores agrupados por categoría.", styles['Normal']))
        story.append(Spacer(1, 12))
        img1 = Image(cat_chart_buffer, width=7*inch, height=3.5*inch, kind='proportional')
        story.append(img1)
        story.append(Spacer(1, 20))
    else:
        story.append(Paragraph("No hay datos suficientes en el archivo de categorías para generar este gráfico.", styles['Normal']))
        story.append(Spacer(1, 20))

    # --- Sección 2: Gráfico de Top Scores (Nueva página) ---
    story.append(PageBreak()) 
    story.append(Paragraph("2. Ranking de Riesgo (Top Scores)", styles['CustomHeader']))

    if top_scores_chart_buffer:
        story.append(Paragraph("Listado de los indicadores con los puntajes de riesgo más altos. Priorizar investigación.", styles['Normal']))
        story.append(Spacer(1, 12))
        # Usamos más altura disponible en la segunda página
        img2 = Image(top_scores_chart_buffer, width=7.5*inch, height=8*inch, kind='proportional')
        story.append(img2)
    else:
        story.append(Paragraph("No hay datos suficientes en el reporte completo para generar el ranking.", styles['Normal']))

    # --- Guardar PDF ---
    try:
        doc.build(story)
        print(f"\n✅ ÉXITO: Reporte PDF generado correctamente en:\n   -> {os.path.abspath(output_filename)}")
    except PermissionError:
         print(f"\n❌ ERROR DE PERMISO: No se pudo escribir en el archivo '{output_filename}'.")
         print("   Asegúrate de que el PDF no esté abierto actualmente en otro programa y vuelve a intentarlo.")
    except Exception as e:
         print(f"\n❌ Error inesperado al guardar el PDF: {e}")


# ==========================================
# BLOQUE PRINCIPAL DE EJECUCIÓN
# ==========================================
if __name__ == "__main__":
    # Limpiamos la consola para que se vea ordenado
    os.system('cls' if os.name == 'nt' else 'clear')

    print("=========================================")
    print("   Generador de Reportes de Seguridad    ")
    print("=========================================\n")
    print("Este programa requiere dos archivos TXT con formatos específicos para generar los gráficos.")
    print("Asegúrate de que los archivos estén en la misma carpeta que este script.\n")

    # --- SOLICITUD DE ARCHIVOS AL USUARIO ---
    # Usamos .strip() para eliminar espacios accidentales al principio o final
    file_categories_txt = input("1. Ingresa el nombre del TXT con el 'Reporte por Categorías' (ej. source_37.txt): ").strip()
    file_full_report_txt = input("2. Ingresa el nombre del TXT con el 'Reporte Completo' (ej. source_1.txt): ").strip()
    
    output_pdf = "Reporte_Grafico_Final.pdf"

    print("\nVerificando archivos y leyendo contenidos...")
    try:
        # Intentamos abrir y leer ambos archivos
        with open(file_categories_txt, 'r', encoding='utf-8') as f:
            cat_text = f.read()
        print(f"  -> Archivo '{file_categories_txt}' leído correctamente.")
            
        with open(file_full_report_txt, 'r', encoding='utf-8') as f:
            full_text = f.read()
        print(f"  -> Archivo '{file_full_report_txt}' leído correctamente.")
            
        # Si ambos se leen bien, ejecutamos la generación
        generate_pdf_report(output_pdf, cat_text, full_text)

    except FileNotFoundError as e:
        # Capturamos el error específico de que no existe el archivo
        print(f"\n❌ ERROR FATAL: No se encontró el archivo '{e.filename}'.")
        print("   Por favor verifica el nombre exacto y que el archivo exista en esta carpeta.")
    except Exception as e:
        print(f"\n❌ Ocurrió un error inesperado: {e}")

    input("\nPresiona Enter para salir...")