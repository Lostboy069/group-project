// 🔗 API Base URL - YOUR RAILWAY BACKEND
const API_BASE = 'https://ai-cyber-shield-production-619e.up.railway.app';

document.addEventListener('DOMContentLoaded', () => {
    const tabs = document.querySelectorAll('.tab-btn');
    const contents = document.querySelectorAll('.tab-content');
    const resultsPanel = document.getElementById('results');
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('file-input');

    // Tab switching
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            tabs.forEach(t => t.classList.remove('active'));
            contents.forEach(c => c.classList.remove('active'));
            tab.classList.add('active');
            document.getElementById(`${tab.dataset.tab}-tab`).classList.add('active');
            resultsPanel.innerHTML = '';
        });
    });

    // File drop zone
    dropZone.addEventListener('click', () => fileInput.click());
    dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
    dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
    dropZone.addEventListener('drop', e => {
        e.preventDefault(); dropZone.classList.remove('drag-over');
        if (e.dataTransfer.files.length) {
            fileInput.files = e.dataTransfer.files;
            dropZone.querySelector('span:last-of-type').textContent = `Selected: ${e.dataTransfer.files[0].name}`;
        }
    });
    fileInput.addEventListener('change', () => {
        if (fileInput.files.length) dropZone.querySelector('span:last-of-type').textContent = `Selected: ${fileInput.files[0].name}`;
    });

    // Form submission → Flask backend
    document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            showLoading();

            const formData = new FormData(form);
            const type = form.id.replace('-form', '');
            formData.append('type', type);

            try {
                const res = await fetch(`${API_BASE}/api/scan`, {
                    method: 'POST',
                    body: formData
                });

                const contentType = res.headers.get("content-type");
                if (!contentType || !contentType.includes("application/json")) {
                    throw new Error("Backend returned non-JSON. Check if Flask is running.");
                }

                const data = await res.json();
                if (!res.ok) throw new Error(data.error || 'Scan failed');
                renderResult(data, type);
            } catch (err) {
                renderError(err.message);
            }
        });
    });

    function showLoading() {
        resultsPanel.innerHTML = `
            <div class="loader-wrap">
                <div class="loader"></div>
                <p class="scan-text">Analyzing threat patterns &amp; running AI scoring</p>
            </div>`;
    }

    function renderResult(data, type) {
        const riskClass = `risk-${data.risk.toLowerCase()}`;
        const riskColor = data.risk === 'HIGH' ? 'var(--accent-2)' : data.risk === 'MEDIUM' ? 'var(--warn)' : 'var(--accent)';
        const tag = data.risk === 'HIGH' ? '[ ALERT ]' : data.risk === 'MEDIUM' ? '[ CAUTION ]' : '[ CLEAR ]';
        const score = Math.max(0, Math.min(100, Number(data.score) || 0));

        const safeDetails = data.details
            .replace(/\\/g, '\\\\')
            .replace(/'/g, "\\'")
            .replace(/"/g, '&quot;')
            .replace(/\n/g, '\\n')
            .replace(/\r/g, '');

        resultsPanel.innerHTML = `
            <div class="result-card ${riskClass}">
                <h3><span style="color:${riskColor}">${tag}</span> ${type.charAt(0).toUpperCase() + type.slice(1)} Analysis Complete</h3>
                <div class="result-meta">
                    <span>Risk Level: <strong style="color: ${riskColor};">${data.risk}</strong></span>
                    <span class="pill">Threat Score: ${data.score}/100</span>
                </div>
                <div class="threat-meter">
                    <div class="threat-meter-fill" id="meter-fill" style="background: ${riskColor}; color: ${riskColor};"></div>
                </div>
                <div class="result-body">
                    ${data.details}
                </div>
                <button class="download-btn" onclick="downloadReport('${type}', '${data.risk}', ${data.score}, '${safeDetails}')">&#9660; Download Report</button>
            </div>
        `;

        requestAnimationFrame(() => {
            const fill = document.getElementById('meter-fill');
            if (fill) fill.style.width = `${score}%`;
        });
    }

    function renderError(msg) {
        resultsPanel.innerHTML = `
            <div class="result-card risk-high">
                <h3 style="color: var(--accent-2)">[ ERROR ] Scan Failed</h3>
                <div class="result-body">${msg}</div>
                <p style="margin-top:0.7rem; color: var(--text-dim); font-size:0.8rem; font-family: var(--mono);">Check console output, or confirm the Flask server is running.</p>
            </div>`;
    }

    window.downloadReport = async (type, risk, score, actualDetails) => {
        try {
            let inputData = "File Upload";
            if (type === 'link') {
                inputData = document.getElementById('link-input').value;
            } else if (type === 'message') {
                inputData = document.getElementById('msg-input').value;
            }

            const res = await fetch(`${API_BASE}/api/report`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    type: type,
                    risk: risk,
                    score: score,
                    input_data: inputData,
                    details: actualDetails || "Scan completed by AI Cyber Shield."
                })
            });

            if (!res.ok) {
                const errData = await res.json().catch(() => ({}));
                throw new Error(errData.error || "Report generation failed");
            }

            const blob = await res.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `CyberShield_Report_${Date.now()}.pdf`;
            document.body.appendChild(a);
            a.click();
            a.remove();
            window.URL.revokeObjectURL(url);
        } catch (err) {
            alert("Error: " + err.message);
        }
    };
});