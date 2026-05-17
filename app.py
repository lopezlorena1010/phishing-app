import streamlit as st
import pandas as pd
import joblib

st.set_page_config(
    page_title="PhishGuard — Detector de URLs",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed",
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap');

html, body, [class*="css"] {
    font-family: 'IBM Plex Sans', sans-serif;
    background-color: #0f1117;
    color: #e2e8f0;
}
.stApp { background-color: #0f1117; }
#MainMenu, footer, header { visibility: hidden; }
.block-container {
    padding: 2.5rem 2rem 3rem 2rem !important;
    max-width: 860px !important;
    margin: 0 auto !important;
}

/* ── Header ── */
.header-wrap {
    display: flex; align-items: center; justify-content: space-between;
    border-bottom: 1px solid #1e2535; padding-bottom: 20px; margin-bottom: 32px;
}
.header-left { display: flex; align-items: center; gap: 14px; }
.shield-icon {
    width: 42px; height: 42px;
    background: linear-gradient(135deg, #1a56db, #0e9f6e);
    border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 20px;
}
.header-title { font-size: 20px; font-weight: 600; color: #f1f5f9; letter-spacing: -0.3px; }
.header-sub { font-size: 12px; color: #64748b; margin-top: 2px; font-family: 'IBM Plex Mono', monospace; }
.header-badge {
    font-family: 'IBM Plex Mono', monospace; font-size: 10px; padding: 4px 12px;
    border-radius: 4px; background: #1e2535; border: 1px solid #2d3748;
    color: #64748b; letter-spacing: 1px; text-transform: uppercase;
}

/* ── Section label ── */
.section-label {
    font-size: 10px; letter-spacing: 1.5px; text-transform: uppercase;
    color: #64748b; font-family: 'IBM Plex Mono', monospace;
    margin-bottom: 16px; margin-top: 28px;
    padding-bottom: 10px; border-bottom: 1px solid #1e2535;
}
.var-group-title {
    font-size: 10px; letter-spacing: 1.2px; text-transform: uppercase;
    color: #475569; font-family: 'IBM Plex Mono', monospace;
    margin-bottom: 10px; margin-top: 20px;
}

/* ── Result card ── */
.result-card {
    background: #161b27; border: 1px solid #1e2535;
    border-radius: 12px; padding: 28px; margin-top: 24px;
}
.result-score {
    font-family: 'IBM Plex Mono', monospace; font-size: 72px;
    font-weight: 500; line-height: 1; margin-bottom: 6px; letter-spacing: -2px;
}
.result-label {
    font-size: 11px; font-family: 'IBM Plex Mono', monospace;
    letter-spacing: 1.5px; text-transform: uppercase; margin-bottom: 24px; color: #94a3b8;
}
.gauge-track { height: 4px; background: #1e2535; border-radius: 2px; overflow: hidden; margin-bottom: 4px; }
.gauge-fill { height: 100%; border-radius: 2px; }
.gauge-ticks {
    display: flex; justify-content: space-between;
    font-family: 'IBM Plex Mono', monospace; font-size: 9px; color: #334155; margin-bottom: 24px;
}
.verdict {
    display: inline-flex; align-items: center; gap: 8px; padding: 7px 18px;
    border-radius: 6px; font-size: 12px; font-weight: 600;
    font-family: 'IBM Plex Mono', monospace; letter-spacing: 0.8px;
    text-transform: uppercase; margin-bottom: 28px;
}
.verdict-phishing { background: rgba(239,68,68,0.12); color: #f87171; border: 1px solid rgba(239,68,68,0.25); }
.verdict-legitimo  { background: rgba(16,185,129,0.10); color: #34d399; border: 1px solid rgba(16,185,129,0.20); }

/* ── Meta rows ── */
.meta-row {
    display: flex; justify-content: space-between; align-items: center;
    padding: 8px 0; border-bottom: 1px solid #1e2535;
}
.meta-key { font-family: 'IBM Plex Mono', monospace; color: #475569; font-size: 11px; }
.meta-val { font-family: 'IBM Plex Mono', monospace; color: #94a3b8; font-size: 11px; }
.meta-val-alert { color: #f87171 !important; }
.meta-val-ok    { color: #34d399 !important; }

/* ── Widget overrides ── */
div[data-testid="stNumberInput"] label,
div[data-testid="stSelectbox"] label {
    font-size: 12px !important; color: #94a3b8 !important;
    font-family: 'IBM Plex Sans', sans-serif !important;
}
div[data-testid="stNumberInput"] input {
    background: #0f1117 !important; border: 1px solid #2d3748 !important;
    color: #e2e8f0 !important; font-family: 'IBM Plex Mono', monospace !important;
}
div[data-testid="stButton"] button {
    width: 100%; background: #1a56db !important; color: white !important;
    border: none !important; border-radius: 8px !important;
    font-family: 'IBM Plex Sans', sans-serif !important; font-size: 13px !important;
    font-weight: 600 !important; padding: 12px !important; margin-top: 16px !important;
}
div[data-testid="stButton"] button:hover { background: #1e429f !important; }
</style>
""", unsafe_allow_html=True)

# ── Header ──
st.markdown("""
<div class="header-wrap">
  <div class="header-left">
    <div class="shield-icon">🛡️</div>
    <div>
      <div class="header-title">PhishGuard</div>
      <div class="header-sub">detector de urls maliciosas · xgboost + pipeline</div>
    </div>
  </div>
  <span class="header-badge">Modelo · XGBoost</span>
</div>
""", unsafe_allow_html=True)

# ── Modelo ──
@st.cache_resource
def load_model():
    return joblib.load("xgb_phishing.pkl")

model = load_model()

# ── Diccionario de variables ──
with st.expander("📖 Diccionario de variables"):
    st.markdown("""
    | Variable | Definición | Señal de phishing |
    |---|---|---|
    | **Links externos** | Porcentaje de links que apuntan a dominios externos | Valor bajo — sitios falsos evitan links externos para que la gente no salga del lugar|
    | **Redirecciones nulas** | Índice de riesgo de redirecciones a null o about:blank | Valor bajo — sitios falsos no tienen flujos de navegación reales |
    | **Error en dominio** | El dominio visible no coincide con el dominio real | Valor alto — dominio que no coincide es señal clara de fraude |
    | **Recursos externos** | Porcentaje de recursos (imágenes, CSS, JS) cargados desde dominios externos | Valor bajo — sitios falsos cargan pocos recursos externos legítimos |
    | **Links nulos** | Porcentaje de links sin destino (href vacío o "#") | Valor alto — sitios falsos tienen muchos links vacíos sin navegación real |
    | **Guiones en URL** | Cantidad de guiones (-) en la URL | Valor bajo — URLs con pocos guiones son más sospechosas |
    | **Riesgo meta externos** | Índice de riesgo combinado de elementos meta, scripts y links externos | Valor bajo — sitios falsos tienen pocos elementos externos |
    | **Números en URL** | Cantidad de números en la URL | Valor alto — URLs con muchos números son señal de fraude |
    | **Formularios inseguros** | Formularios que envían datos por HTTP sin cifrar | Valor alto — formulario inseguro indica intención de robo de datos |
    """)

# ── Inputs ──
st.markdown('<div class="section-label">Características de la URL</div>', unsafe_allow_html=True)

st.markdown('<div class="var-group-title">Links</div>', unsafe_allow_html=True)
c1, c2 = st.columns(2)
with c1:
    pct_links_ext = st.number_input(
        "Porcentaje de links externos",
        min_value=0.0, max_value=1.0, value=0.0, step=0.01, format="%.2f",
        help="Porcentaje de hipervínculos que apuntan a dominios externos. Ej: 0.75 = 75%"
    )
with c2:
    pct_links_nulos = st.number_input(
        "Porcentaje de links nulos",
        min_value=0.0, max_value=1.0, value=0.0, step=0.01, format="%.2f",
        help="Porcentaje de links que redirigen a sí mismos o están vacíos. Ej: 0.85 = 85%"
    )

pct_recursos_ext = st.number_input(
    "Porcentaje de recursos externos",
    min_value=0.0, max_value=1.0, value=0.0, step=0.01, format="%.2f",
    help="Porcentaje de recursos (imágenes, CSS, JS) cargados desde dominios externos. Ej: 0.80 = 80%"
)

st.markdown('<div class="var-group-title">Dominio y estructura</div>', unsafe_allow_html=True)
c3, c4 = st.columns(2)
with c3:
    mismatch_dominio_label = st.selectbox(
        "Error en dominio",
        options=["No", "Sí"],
        help="El dominio visible no coincide con el dominio real del enlace"
    )
    mismatch_dominio = 1 if mismatch_dominio_label == "Sí" else 0
with c4:
    form_inseguro_label = st.selectbox(
        "Formularios inseguros",
        options=["No", "Sí"],
        help="Presencia de formularios que envían datos sin cifrar (HTTP)"
    )
    form_inseguro = 1 if form_inseguro_label == "Sí" else 0

c5, c6 = st.columns(2)
with c5:
    n_numeros_url = st.number_input(
        "Números en la URL",
        min_value=0, max_value=50, value=0, step=1,
        help="Cantidad de caracteres numéricos en la URL"
    )
with c6:
    n_guiones = st.number_input(
        "Guiones en la URL",
        min_value=0, max_value=20, value=0, step=1,
        help="Cantidad de guiones (-) en la URL"
    )

st.markdown('<div class="var-group-title">Indicadores de riesgo</div>', unsafe_allow_html=True)
c7, c8 = st.columns(2)
with c7:
    riesgo_redir_label = st.selectbox(
        "Riesgo de redirecciones nulas",
        options=["Bajo (-1)", "Medio (0)", "Alto (1)"],
        help="Nivel de riesgo derivado del porcentaje de redirecciones nulas"
    )
    riesgo_redir_nula = -1 if "Bajo" in riesgo_redir_label else (0 if "Medio" in riesgo_redir_label else 1)
with c8:
    riesgo_meta_label = st.selectbox(
        "Riesgo de meta externos",
        options=["Bajo (-1)", "Medio (0)", "Alto (1)"],
        help="Nivel de riesgo derivado de meta, scripts o links externos"
    )
    riesgo_meta_ext = -1 if "Bajo" in riesgo_meta_label else (0 if "Medio" in riesgo_meta_label else 1)

analizar = st.button("Analizar URL")

# ── Resultado ──
if analizar:
    input_df = pd.DataFrame([{
        'pct_links_ext'    : pct_links_ext,
        'riesgo_redir_nula': riesgo_redir_nula,
        'mismatch_dominio' : mismatch_dominio,
        'pct_recursos_ext' : pct_recursos_ext,
        'pct_links_nulos'  : pct_links_nulos,
        'n_guiones'        : n_guiones,
        'riesgo_meta_ext'  : riesgo_meta_ext,
        'n_numeros_url'    : n_numeros_url,
        'form_inseguro'    : form_inseguro,
    }])

    prob     = float(model.predict_proba(input_df)[0][1])
    prob_pct = round(prob * 100, 1)
    es_phishing = prob_pct >= 50

    color_score = "#f87171" if es_phishing else "#34d399"
    gauge_color = "#ef4444" if es_phishing else "#10b981"

    def val_class(val, umbral, invertido=False):
        if invertido:
            return "meta-val-alert" if val <= umbral else "meta-val-ok"
        return "meta-val-alert" if val >= umbral else "meta-val-ok"

    verdict_html = '<div class="verdict verdict-phishing">⚠ URL Maliciosa — Phishing detectado</div>' if es_phishing else '<div class="verdict verdict-legitimo">✓ URL Legítima — Sin amenazas</div>'

    st.markdown(f"""
    <div class="result-card">
      <div class="result-score" style="color:{color_score}">{prob_pct}%</div>
      <div class="result-label">probabilidad de phishing</div>
      <div class="gauge-track">
        <div class="gauge-fill" style="width:{prob_pct}%; background:{gauge_color};"></div>
      </div>
      <div class="gauge-ticks">
        <span>0%</span><span>25%</span><span>50%</span><span>75%</span><span>100%</span>
      </div>
      {verdict_html}
      <div class="meta-row"><span class="meta-key">Links externos</span><span class="meta-val {val_class(pct_links_ext, 0.3, invertido=True)}">{pct_links_ext:.2f}</span></div>
      <div class="meta-row"><span class="meta-key">Links nulos</span><span class="meta-val {val_class(pct_links_nulos, 0.5)}">{pct_links_nulos:.2f}</span></div>
      <div class="meta-row"><span class="meta-key">Recursos externos</span><span class="meta-val {val_class(pct_recursos_ext, 0.3, invertido=True)}">{pct_recursos_ext:.2f}</span></div>
      <div class="meta-row"><span class="meta-key">Error en dominio</span><span class="meta-val {val_class(mismatch_dominio, 1)}">{mismatch_dominio_label}</span></div>
      <div class="meta-row"><span class="meta-key">Números en URL</span><span class="meta-val {val_class(n_numeros_url, 4)}">{int(n_numeros_url)}</span></div>
      <div class="meta-row"><span class="meta-key">Guiones en URL</span><span class="meta-val {val_class(n_guiones, 3)}">{int(n_guiones)}</span></div>
      <div class="meta-row"><span class="meta-key">Formularios inseguros</span><span class="meta-val {val_class(form_inseguro, 1)}">{form_inseguro_label}</span></div>
      <div class="meta-row"><span class="meta-key">Riesgo redirecciones</span><span class="meta-val {val_class(riesgo_redir_nula, 1)}">{riesgo_redir_label}</span></div>
      <div class="meta-row" style="border:none"><span class="meta-key">Riesgo meta externos</span><span class="meta-val {val_class(riesgo_meta_ext, 1)}">{riesgo_meta_label}</span></div>
    </div>
    """, unsafe_allow_html=True)
