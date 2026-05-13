import streamlit as st
import pandas as pd
import joblib
import re

# ──────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────
st.set_page_config(
    page_title="PhishGuard — Detector de URLs",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ──────────────────────────────────────────────
# CSS
# ──────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap');

html, body, [class*="css"] {
    font-family: 'IBM Plex Sans', sans-serif;
    background-color: #0f1117;
    color: #e2e8f0;
}

.stApp {
    background-color: #0f1117;
}

#MainMenu, footer, header { visibility: hidden; }

.block-container {
    padding: 2.5rem 3rem 3rem 3rem !important;
    max-width: 1200px !important;
    margin: 0 auto !important;
}

/* ── Header ── */
.header-wrap {
    display: flex;
    align-items: center;
    justify-content: space-between;
    border-bottom: 1px solid #1e2535;
    padding-bottom: 20px;
    margin-bottom: 36px;
}
.header-left {
    display: flex;
    align-items: center;
    gap: 14px;
}
.shield-icon {
    width: 42px; height: 42px;
    background: linear-gradient(135deg, #1a56db, #0e9f6e);
    border-radius: 10px;
    display: flex; align-items: center; justify-content: center;
    font-size: 20px;
}
.header-title {
    font-size: 20px;
    font-weight: 600;
    color: #f1f5f9;
    letter-spacing: -0.3px;
}
.header-sub {
    font-size: 12px;
    color: #64748b;
    margin-top: 2px;
    font-family: 'IBM Plex Mono', monospace;
}
.header-badge {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 10px;
    padding: 4px 12px;
    border-radius: 4px;
    background: #1e2535;
    border: 1px solid #2d3748;
    color: #64748b;
    letter-spacing: 1px;
    text-transform: uppercase;
}

/* ── URL Input area ── */
.url-label {
    font-size: 11px;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    color: #64748b;
    font-family: 'IBM Plex Mono', monospace;
    margin-bottom: 10px;
}

/* ── Panel ── */
.panel {
    background: #161b27;
    border: 1px solid #1e2535;
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 16px;
}
.panel-title {
    font-size: 11px;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    color: #64748b;
    font-family: 'IBM Plex Mono', monospace;
    margin-bottom: 20px;
    padding-bottom: 12px;
    border-bottom: 1px solid #1e2535;
}

/* ── Variable groups ── */
.var-group {
    margin-bottom: 6px;
}
.var-group-title {
    font-size: 10px;
    letter-spacing: 1.2px;
    text-transform: uppercase;
    color: #475569;
    font-family: 'IBM Plex Mono', monospace;
    margin-bottom: 12px;
    margin-top: 16px;
}

/* ── Result panel ── */
.result-empty {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 60px 20px;
    color: #334155;
    text-align: center;
}
.result-empty-icon {
    font-size: 40px;
    margin-bottom: 14px;
    opacity: 0.4;
}
.result-empty-text {
    font-size: 13px;
    font-family: 'IBM Plex Mono', monospace;
    color: #334155;
}

.result-score {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 72px;
    font-weight: 500;
    line-height: 1;
    margin-bottom: 6px;
    letter-spacing: -2px;
}
.result-label {
    font-size: 11px;
    font-family: 'IBM Plex Mono', monospace;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    margin-bottom: 24px;
    color: #94a3b8;
}

/* ── Gauge ── */
.gauge-track {
    height: 4px;
    background: #1e2535;
    border-radius: 2px;
    overflow: hidden;
    margin-bottom: 4px;
}
.gauge-fill {
    height: 100%;
    border-radius: 2px;
    transition: width 0.6s ease;
}
.gauge-ticks {
    display: flex;
    justify-content: space-between;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 9px;
    color: #334155;
    margin-bottom: 24px;
}

/* ── Verdict badge ── */
.verdict {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 7px 18px;
    border-radius: 6px;
    font-size: 12px;
    font-weight: 600;
    font-family: 'IBM Plex Mono', monospace;
    letter-spacing: 0.8px;
    text-transform: uppercase;
    margin-bottom: 28px;
}
.verdict-phishing { background: rgba(239,68,68,0.12); color: #f87171; border: 1px solid rgba(239,68,68,0.25); }
.verdict-legitimo  { background: rgba(16,185,129,0.10); color: #34d399; border: 1px solid rgba(16,185,129,0.20); }

/* ── Meta rows ── */
.meta-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 8px 0;
    border-bottom: 1px solid #1e2535;
    font-size: 12px;
}
.meta-key {
    font-family: 'IBM Plex Mono', monospace;
    color: #475569;
    font-size: 11px;
    letter-spacing: 0.3px;
}
.meta-val {
    font-family: 'IBM Plex Mono', monospace;
    color: #94a3b8;
    font-size: 11px;
}
.meta-val-alert { color: #f87171 !important; }
.meta-val-ok    { color: #34d399 !important; }

/* ── URL display ── */
.url-display {
    background: #0f1117;
    border: 1px solid #1e2535;
    border-radius: 8px;
    padding: 10px 14px;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 11px;
    color: #64748b;
    word-break: break-all;
    margin-bottom: 20px;
}

/* ── Widget overrides ── */
div[data-testid="stTextInput"] label,
div[data-testid="stNumberInput"] label,
div[data-testid="stSlider"] label {
    font-size: 11px !important;
    color: #475569 !important;
    font-family: 'IBM Plex Mono', monospace !important;
    letter-spacing: 0.3px !important;
}

div[data-testid="stTextInput"] input {
    background: #0f1117 !important;
    border: 1px solid #2d3748 !important;
    border-radius: 8px !important;
    color: #e2e8f0 !important;
    font-family: 'IBM Plex Mono', monospace !important;
    font-size: 13px !important;
}

div[data-testid="stNumberInput"] input {
    background: #0f1117 !important;
    border: 1px solid #2d3748 !important;
    color: #e2e8f0 !important;
    font-family: 'IBM Plex Mono', monospace !important;
}

div[data-testid="stButton"] button {
    width: 100%;
    background: #1a56db !important;
    color: white !important;
    border: none !important;
    border-radius: 8px !important;
    font-family: 'IBM Plex Sans', sans-serif !important;
    font-size: 13px !important;
    font-weight: 600 !important;
    padding: 12px !important;
    letter-spacing: 0.3px !important;
    margin-top: 8px !important;
}
div[data-testid="stButton"] button:hover {
    background: #1e429f !important;
}

div[data-testid="stSlider"] > div {
    padding-top: 4px !important;
}
</style>
""", unsafe_allow_html=True)

# ──────────────────────────────────────────────
# HEADER
# ──────────────────────────────────────────────
st.markdown("""
<div class="header-wrap">
  <div class="header-left">
    <div class="shield-icon">🛡️</div>
    <div>
      <div class="header-title">PhishGuard</div>
      <div class="header-sub">detector de urls maliciosas · xgboost v2</div>
    </div>
  </div>
  <span class="header-badge">Modelo · XGBoost + Pipeline</span>
</div>
""", unsafe_allow_html=True)

# ──────────────────────────────────────────────
# CARGAR MODELO
# ──────────────────────────────────────────────
@st.cache_resource
def load_model():
    return joblib.load("xgb_phishing.pkl")

model = load_model()

# ──────────────────────────────────────────────
# LAYOUT
# ──────────────────────────────────────────────
col_left, col_right = st.columns([1.1, 0.9], gap="large")

# ── IZQUIERDA: INPUTS ─────────────────────────
with col_left:

    # URL input
    st.markdown('<div class="url-label">URL a analizar</div>', unsafe_allow_html=True)
    url_input = st.text_input(
        label="url",
        placeholder="https://ejemplo.com/pagina",
        label_visibility="collapsed"
    )

    st.markdown('<div class="panel">', unsafe_allow_html=True)
    st.markdown('<div class="panel-title">Variables extraídas de la URL</div>', unsafe_allow_html=True)

    # Grupo 1 — Links
    st.markdown('<div class="var-group-title">Links</div>', unsafe_allow_html=True)
    c1, c2 = st.columns(2)
    with c1:
        pct_links_ext   = st.number_input("pct_links_ext",   min_value=0.0, max_value=1.0, value=0.0, step=0.01, format="%.2f")
    with c2:
        pct_links_nulos = st.number_input("pct_links_nulos", min_value=0.0, max_value=1.0, value=0.0, step=0.01, format="%.2f")

    # Grupo 2 — Recursos y dominio
    st.markdown('<div class="var-group-title">Recursos y dominio</div>', unsafe_allow_html=True)
    c3, c4 = st.columns(2)
    with c3:
        pct_recursos_ext = st.number_input("pct_recursos_ext", min_value=0.0, max_value=1.0, value=0.0, step=0.01, format="%.2f")
    with c4:
        mismatch_dominio = st.number_input("mismatch_dominio", min_value=0, max_value=1, value=0, step=1)

    # Grupo 3 — Estructura URL
    st.markdown('<div class="var-group-title">Estructura de la URL</div>', unsafe_allow_html=True)
    c5, c6 = st.columns(2)
    with c5:
        n_numeros_url = st.number_input("n_numeros_url", min_value=0, max_value=50, value=0, step=1)
    with c6:
        n_guiones     = st.number_input("n_guiones",     min_value=0, max_value=20, value=0, step=1)

    # Grupo 4 — Riesgos
    st.markdown('<div class="var-group-title">Indicadores de riesgo</div>', unsafe_allow_html=True)
    c7, c8, c9 = st.columns(3)
    with c7:
        riesgo_redir_nula = st.number_input("riesgo_redir_nula", min_value=0, max_value=1, value=0, step=1)
    with c8:
        riesgo_meta_ext   = st.number_input("riesgo_meta_ext",   min_value=0, max_value=1, value=0, step=1)
    with c9:
        form_inseguro     = st.number_input("form_inseguro",     min_value=0, max_value=1, value=0, step=1)

    st.markdown('</div>', unsafe_allow_html=True)

    analizar = st.button("Analizar URL")

# ── DERECHA: RESULTADO ────────────────────────
with col_right:

    st.markdown('<div class="panel" style="min-height: 520px;">', unsafe_allow_html=True)
    st.markdown('<div class="panel-title">Resultado del análisis</div>', unsafe_allow_html=True)

    if not analizar:
        st.markdown("""
        <div class="result-empty">
          <div class="result-empty-icon">🔍</div>
          <div class="result-empty-text">Ingresa una URL y completa<br>las variables para analizar</div>
        </div>
        """, unsafe_allow_html=True)

    else:
        # Construir input
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

        prob     = model.predict_proba(input_df)[0][1]
        prob_pct = round(prob * 100, 1)
        es_phishing = prob_pct >= 50

        color_score = "#f87171" if es_phishing else "#34d399"
        gauge_class = "gauge-fill-ph" if es_phishing else "gauge-fill-ok"
        gauge_color = "#ef4444" if es_phishing else "#10b981"

        # URL display
        if url_input:
            st.markdown(f'<div class="url-display">{url_input}</div>', unsafe_allow_html=True)

        # Score
        st.markdown(f"""
        <div class="result-score" style="color:{color_score}">{prob_pct}%</div>
        <div class="result-label">probabilidad de phishing</div>

        <div class="gauge-track">
          <div class="gauge-fill" style="width:{prob_pct}%; background:{gauge_color};"></div>
        </div>
        <div class="gauge-ticks">
          <span>0%</span><span>25%</span><span>50%</span><span>75%</span><span>100%</span>
        </div>
        """, unsafe_allow_html=True)

        # Verdict
        if es_phishing:
            st.markdown('<div class="verdict verdict-phishing">⚠ URL Maliciosa — Phishing detectado</div>', unsafe_allow_html=True)
        else:
            st.markdown('<div class="verdict verdict-legitimo">✓ URL Legítima — Sin amenazas</div>', unsafe_allow_html=True)

        # Variables destacadas
        def val_class(val, umbral, invertido=False):
            if invertido:
                return "meta-val-alert" if val <= umbral else "meta-val-ok"
            return "meta-val-alert" if val >= umbral else "meta-val-ok"

        st.markdown(f"""
        <div class="meta-row">
          <span class="meta-key">pct_links_ext</span>
          <span class="meta-val {val_class(pct_links_ext, 0.3, invertido=True)}">{pct_links_ext:.2f}</span>
        </div>
        <div class="meta-row">
          <span class="meta-key">pct_links_nulos</span>
          <span class="meta-val {val_class(pct_links_nulos, 0.5)}">{pct_links_nulos:.2f}</span>
        </div>
        <div class="meta-row">
          <span class="meta-key">pct_recursos_ext</span>
          <span class="meta-val {val_class(pct_recursos_ext, 0.3, invertido=True)}">{pct_recursos_ext:.2f}</span>
        </div>
        <div class="meta-row">
          <span class="meta-key">mismatch_dominio</span>
          <span class="meta-val {val_class(mismatch_dominio, 1)}">{int(mismatch_dominio)}</span>
        </div>
        <div class="meta-row">
          <span class="meta-key">n_numeros_url</span>
          <span class="meta-val {val_class(n_numeros_url, 4)}">{int(n_numeros_url)}</span>
        </div>
        <div class="meta-row">
          <span class="meta-key">form_inseguro</span>
          <span class="meta-val {val_class(form_inseguro, 1)}">{int(form_inseguro)}</span>
        </div>
        <div class="meta-row">
          <span class="meta-key">riesgo_redir_nula</span>
          <span class="meta-val {val_class(riesgo_redir_nula, 1)}">{int(riesgo_redir_nula)}</span>
        </div>
        <div class="meta-row">
          <span class="meta-key">riesgo_meta_ext</span>
          <span class="meta-val {val_class(riesgo_meta_ext, 1)}">{int(riesgo_meta_ext)}</span>
        </div>
        <div class="meta-row" style="border:none">
          <span class="meta-key">n_guiones</span>
          <span class="meta-val {val_class(n_guiones, 3)}">{int(n_guiones)}</span>
        </div>
        """, unsafe_allow_html=True)

    st.markdown('</div>', unsafe_allow_html=True)
