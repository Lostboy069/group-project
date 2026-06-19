from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import hashlib
import requests
import os
import datetime
import traceback
from io import BytesIO
from fpdf import FPDF
from dotenv import load_dotenv
import sys
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')
from matplotlib.patches import Circle

from ai_module.threat_detector import ThreatDetector

load_dotenv()
app = Flask(__name__)
CORS(app)
detector = ThreatDetector()
VT_API_KEY = os.getenv("VT_API_KEY")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BACKGROUND_IMAGE = os.path.join(BASE_DIR, "ai_module", "page.jpg")

FRONTEND_DIR = os.path.join(BASE_DIR, "..", "cyber-shield-frontend")
if os.path.exists(FRONTEND_DIR):
    @app.route('/')
    def index():
        return send_file(os.path.join(FRONTEND_DIR, 'index.html'))
    
    @app.route('/<path:path>')
    def static_files(path):
        return send_file(os.path.join(FRONTEND_DIR, path))

@app.route('/api/scan', methods=['POST'])
def scan():
    try:
        scan_type = request.form.get('type')
        if scan_type == 'message':
            text = request.form.get('message', '')
            result = detector.analyze_message(text)
        elif scan_type == 'link':
            url = request.form.get('url', '')
            result = detector.analyze_url(url)
        elif scan_type == 'file':
            file = request.files.get('file')
            if not file or file.filename == '':
                return jsonify({"error": "No file uploaded"}), 400
            file_content = file.read()
            sha256 = hashlib.sha256(file_content).hexdigest()
            result = _scan_file_vt(sha256, file.filename)
        else:
            return jsonify({"error": "Invalid scan type"}), 400
        return jsonify(result)
    except Exception as e:
        print(f"Scan error: {e}")
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route('/api/report', methods=['POST'])
def generate_report():
    try:
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"error": "Invalid JSON data"}), 400

        scan_type = str(data.get("type", "unknown"))[:20]
        risk = str(data.get("risk", "LOW")).upper()[:10]
        score = int(data.get("score", 0))
        details = str(data.get("details", "N/A"))[:300]
        input_data = str(data.get("input_data", "N/A"))[:150]

        pdf_buffer = _create_pdf_in_memory(scan_type, input_data, risk, score, details)
        
        return send_file(
            pdf_buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f"CyberShield_Report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        )
    except Exception as e:
        error_msg = f"{type(e).__name__}: {str(e)}"
        print(f"Report error: {error_msg}")
        traceback.print_exc()
        return jsonify({"error": error_msg}), 500

def _scan_file_vt(sha256, filename):
    if not VT_API_KEY:
        return {"risk": "LOW", "score": 10, "prediction": "API_MISSING", 
                "details": f"File: {filename} - VT key missing"}
    headers = {"x-apikey": VT_API_KEY}
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    try:
        res = requests.get(url, headers=headers, timeout=10)
        if res.status_code == 200:
            stats = res.json()["data"]["attributes"]["last_analysis_stats"]
            mal, sus, safe = stats.get("malicious",0), stats.get("suspicious",0), stats.get("harmless",0)
            score = min((mal*12 + sus*6), 100)
            risk = "HIGH" if mal>0 else "MEDIUM" if sus>2 else "LOW"
            return {"risk":risk, "score":score, "prediction":"MALICIOUS" if risk=="HIGH" else "SUSPICIOUS" if risk=="MEDIUM" else "CLEAN",
                    "details":f"VT: {mal} malicious, {sus} suspicious, {safe} clean | Hash:{sha256[:16]}..."}
        elif res.status_code == 404:
            return {"risk":"UNKNOWN","score":30,"prediction":"NOT_IN_DB","details":f"Not in VT yet"}
        else:
            return {"risk":"LOW","score":10,"prediction":"API_ERROR","details":f"VT error {res.status_code}"}
    except Exception as e:
        return {"risk":"LOW","score":10,"prediction":"VT_ERROR","details":f"VT failed: {str(e)[:60]}"}

def _clean_for_pdf(text):
    if not isinstance(text, str): text = str(text)
    replacements = {
        '[ALERT]': '[ALERT]', '[WARN]': '[WARN]', '[OK]': '[OK]', '[ERR]': '[ERR]',
        '[AI]': '[AI]', '[RULE]': '[RULE]', '[INFO]': '[INFO]', '[SHIELD]': '[SHIELD]',
        '[BLOCK]': '[BLOCK]', '[FILE]': '[FILE]', '[LINK]': '[LINK]', '[MSG]': '[MSG]',
        '[CHART]': '[CHART]', '[PDF]': '[PDF]', '[TARGET]': '[TARGET]', '[FAST]': '[FAST]',
        '[RED]': '[RED]', '[YELLOW]': '[YELLOW]', '[GREEN]': '[GREEN]',
        '—': '-', '–': '-', '…': '...', '•': '*', '°': ' deg',
        '(c)': '(c)', '(R)': '(R)', '(TM)': '(TM)', 'EUR': 'EUR', 'GBP': 'GBP',
        '\u200b': '', '\u200c': '', '\u200d': '', '\ufeff': '',
    }
    for emoji, repl in replacements.items(): text = text.replace(emoji, repl)
    cleaned = text.encode('latin-1', errors='replace').decode('latin-1')
    return cleaned.replace('?', '[?]')

def _create_pdf_in_memory(scan_type, input_data, risk, score, details):
    try:
        A4_W, A4_H = 210, 297
        pdf = FPDF(orientation='P', unit='mm', format='A4')
        pdf.add_page()
        pdf.set_auto_page_break(auto=False)
        
        if os.path.exists(BACKGROUND_IMAGE):
            pdf.image(BACKGROUND_IMAGE, x=0, y=0, w=A4_W, h=A4_H)
        
        CONTENT_X, CONTENT_Y, LINE_HEIGHT = 25, 40, 7
        
        pdf.set_xy(CONTENT_X, CONTENT_Y)
        pdf.set_font("Helvetica", "B", 16)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 8, "        ", ln=True)
        
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(80, 80, 80)
        pdf.cell(0, 5, f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}", ln=True)
        pdf.ln(3)
        
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 7, "Scan Summary", ln=True)
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, LINE_HEIGHT, f"Type: {scan_type.capitalize()}", ln=True)
        safe_input = _clean_for_pdf(str(input_data)[:70] + ("..." if len(str(input_data))>70 else ""))
        pdf.cell(0, LINE_HEIGHT, f"Input: {safe_input}", ln=True)
        pdf.ln(4)
        
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 7, "Threat Analysis", ln=True)
        pdf.set_font("Helvetica", "", 10)
        
        if risk == "HIGH": pdf.set_text_color(200, 0, 0)
        elif risk == "MEDIUM": pdf.set_text_color(220, 150, 0)
        else: pdf.set_text_color(0, 150, 0)
        
        pdf.cell(0, LINE_HEIGHT, f"Risk Level: {risk}", ln=True)
        pdf.set_text_color(0, 0, 0)
        
        if risk == "HIGH": risk_advice = "[BLOCK] High risk to open - Avoid"
        elif risk == "MEDIUM": risk_advice = "[WARN] Moderate risk - Verify source first"
        else: risk_advice = "[OK] Low risk - Generally safe to open"
        
        pdf.cell(0, LINE_HEIGHT, f"Risk to Open: {score}/100", ln=True)
        pdf.set_font("Helvetica", "I", 9)
        pdf.set_text_color(80, 80, 80)
        pdf.cell(0, LINE_HEIGHT-2, risk_advice, ln=True)
        pdf.set_font("Helvetica", "", 10)
        pdf.ln(2)
        
        verdict = "MALICIOUS" if risk=="HIGH" else "SUSPICIOUS" if risk=="MEDIUM" else "SAFE"
        pdf.cell(0, LINE_HEIGHT, f"Verdict: {verdict}", ln=True)
        pdf.ln(4)
        
        pdf.set_font("Helvetica", "I", 9)
        clean_details = _clean_for_pdf(details)
        pdf.multi_cell(0, LINE_HEIGHT-1, f"Details: {clean_details}")
        pdf.ln(5)
        
        chart_bytes = _create_chart_in_memory(risk, score)
        if chart_bytes:
            chart_y = pdf.get_y()
            if chart_y + 80 > A4_H - 25:
                pdf.add_page()
                if os.path.exists(BACKGROUND_IMAGE):
                    pdf.image(BACKGROUND_IMAGE, x=0, y=0, w=A4_W, h=A4_H)
                chart_y = CONTENT_Y + 10
            pdf.set_font("Helvetica", "B", 11)
            pdf.set_text_color(0, 0, 0)
            pdf.set_xy(CONTENT_X, chart_y)
            pdf.cell(0, 6, "Threat Distribution", ln=True)
            import tempfile
            with tempfile.NamedTemporaryFile(suffix='.jpg', delete=False) as tmp:
                tmp.write(chart_bytes)
                tmp_path = tmp.name
            try:
                pdf.image(tmp_path, x=40, y=pdf.get_y(), w=130)
                pdf.ln(75)
            finally:
                if os.path.exists(tmp_path): os.unlink(tmp_path)
        
        pdf.set_y(A4_H - 20)
        pdf.set_font("Helvetica", "I", 8)
        pdf.set_text_color(120, 120, 120)
        pdf.cell(0, 5, "AI Cyber Shield | Educational Project", ln=True, align="C")
        
        pdf_buffer = BytesIO()
        pdf_output = pdf.output(dest='S').encode('latin-1')
        pdf_buffer.write(pdf_output)
        pdf_buffer.seek(0)
        return pdf_buffer
        
    except Exception as e:
        print(f"PDF memory generation failed: {e}")
        traceback.print_exc()
        raise

def _create_chart_in_memory(risk, score):
    try:
        if risk == "HIGH":
            values = [score, max(0, 100-score-5), 5]
            labels = ['[BLOCK] Dont Open', '[WARN] Caution', '[OK] Safe']
            colors = ['#ff4d6d', '#ffb703', '#00f5d4']
        elif risk == "MEDIUM":
            values = [score, max(0, score-40), 100-score-max(0,score-40)]
            labels = ['[WARN] Caution', '[BLOCK] Dont Open', '[OK] Safe']
            colors = ['#ffb703', '#ff4d6d', '#00f5d4']
        else:
            values = [score, max(0, 100-score-10), 10]
            labels = ['[OK] Safe', '[WARN] Caution', '[BLOCK] Dont Open']
            colors = ['#00f5d4', '#ffb703', '#ff4d6d']
        
        fig, ax = plt.subplots(figsize=(5,5), facecolor='white')
        ax.set_facecolor('white')
        ax.pie(values, labels=labels, colors=colors, autopct='%1.0f%%',
               startangle=90, textprops={'fontsize':9, 'color':'black', 'weight':'bold'})
        ax.add_artist(Circle((0,0), 0.70, fc='white', ec='#ddd', linewidth=1))
        risk_label = "HIGH RISK" if risk=="HIGH" else "CAUTION" if risk=="MEDIUM" else "LOW RISK"
        ax.set_title(f'Risk to Open: {score}/100 ({risk_label})', fontsize=11, fontweight='bold', pad=15, color='black')
        ax.axis('equal')
        plt.tight_layout()
        
        buf = BytesIO()
        plt.savefig(buf, format='jpg', dpi=150, bbox_inches='tight', facecolor='white')
        buf.seek(0)
        chart_bytes = buf.read()
        buf.close()
        plt.close(fig)
        return chart_bytes
    except Exception as e:
        print(f"Chart memory error: {e}")
        return None

@app.route('/health')
def health():
    return jsonify({"status": "ok", "model_loaded": detector.model_loaded})

if __name__ == '__main__':
    print("AI Cyber Shield starting...")
    port = int(os.getenv('PORT', 5000))
    debug_mode = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(debug=debug_mode, host='0.0.0.0', port=port)