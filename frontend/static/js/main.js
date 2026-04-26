// ─────────────────────────────────────────────
// ShieldScan — Main Frontend JS
// ─────────────────────────────────────────────

const API_BASE = window.location.origin;

// ─── TAB SWITCHING ───
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById(`tab-${tab.dataset.tab}`).classList.add('active');
  });
});

// ─── DROP ZONE ───
const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('apk-file');
const fileInfo = document.getElementById('file-info');
let selectedFile = null;

dropZone.addEventListener('click', () => fileInput.click());
dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
dropZone.addEventListener('drop', e => {
  e.preventDefault();
  dropZone.classList.remove('drag-over');
  const f = e.dataTransfer.files[0];
  if (f) setFile(f);
});
fileInput.addEventListener('change', e => { if (e.target.files[0]) setFile(e.target.files[0]); });

function setFile(f) {
  selectedFile = f;
  fileInfo.textContent = `✓ ${f.name} — ${(f.size/1024/1024).toFixed(2)} MB`;
  if (!document.getElementById('app-name').value) {
    document.getElementById('app-name').value = f.name.replace('.apk','').replace('.zip','');
  }
}

// ─── APK FORM SUBMIT ───
document.getElementById('apk-form').addEventListener('submit', async e => {
  e.preventDefault();
  if (!selectedFile) { alert('Please select an APK or ZIP file first.'); return; }

  const formData = new FormData();
  formData.append('file', selectedFile);
  formData.append('app_name', document.getElementById('app-name').value || selectedFile.name);
  formData.append('developer', document.getElementById('developer').value || 'Unknown');
  formData.append('description', document.getElementById('description').value || '');

  await runAnalysis(() => fetch(`${API_BASE}/api/analyze`, { method: 'POST', body: formData }));
});

// ─── URL FORM SUBMIT ───
document.getElementById('url-form').addEventListener('submit', async e => {
  e.preventDefault();
  const payload = {
    app_name: document.getElementById('url-app-name').value,
    developer: document.getElementById('url-developer').value || 'Unknown',
    url: document.getElementById('app-url').value || '',
    description: document.getElementById('url-description').value || '',
  };

  await runAnalysis(() => fetch(`${API_BASE}/api/analyze-url`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  }));
});

// ─── MAIN ANALYSIS RUNNER ───
async function runAnalysis(fetchFn) {
  showLoading();
  try {
    const steps = ['step1','step2','step3','step4'];
    const delays = [400, 900, 1500, 2100];
    steps.forEach((s, i) => setTimeout(() => activateStep(s), delays[i]));

    const res = await fetchFn();
    const data = await res.json();

    if (data.error) { alert('Error: ' + data.error); hideLoading(); return; }

    // Mark all done
    setTimeout(() => {
      steps.forEach(s => {
        const el = document.getElementById(s);
        el.classList.remove('active');
        el.classList.add('done');
      });
      setTimeout(() => renderResults(data), 600);
    }, 2800);

  } catch (err) {
    alert('Connection error: ' + err.message);
    hideLoading();
  }
}

function activateStep(id) {
  const el = document.getElementById(id);
  el.classList.add('active');
}

function showLoading() {
  document.getElementById('loading').style.display = 'block';
  document.getElementById('results').style.display = 'none';
  document.querySelector('.analyze-section').style.display = 'none';
  ['step1','step2','step3','step4'].forEach(s => {
    const el = document.getElementById(s);
    el.classList.remove('active','done');
  });
  setTimeout(() => document.getElementById('loading').scrollIntoView({ behavior: 'smooth' }), 100);
}

function hideLoading() {
  document.getElementById('loading').style.display = 'none';
  document.querySelector('.analyze-section').style.display = 'block';
}

function resetAnalysis() {
  document.getElementById('results').style.display = 'none';
  document.querySelector('.analyze-section').style.display = 'block';
  selectedFile = null;
  fileInfo.textContent = '';
  document.querySelector('.analyze-section').scrollIntoView({ behavior: 'smooth' });
}

// ─── RENDER RESULTS ───
function renderResults(data) {
  document.getElementById('loading').style.display = 'none';
  document.getElementById('results').style.display = 'block';
  setTimeout(() => document.getElementById('results').scrollIntoView({ behavior: 'smooth' }), 100);

  const meta = data.meta;
  const v = data.verdict;
  const m1 = data.module1_preprocessing;
  const m2 = data.module2_permissions;
  const m3 = data.module3_dark_patterns;
  const m4 = data.module4_fake_detection;

  // META
  document.getElementById('results-meta').innerHTML = `
    <strong>${meta.app_name}</strong> by ${meta.developer} 
    · ${meta.file_size_kb ? meta.file_size_kb+'KB' : 'URL Analysis'} 
    · Analyzed in ${meta.analysis_time_sec}s
    · <span style="font-size:0.65rem">${meta.md5}</span>
  `;

  // VERDICT
  const vCard = document.getElementById('verdict-card');
  vCard.style.borderColor = verdictColor(v.overall_verdict);
  document.getElementById('verdict-badge').className = `verdict-badge ${v.overall_verdict}`;
  document.getElementById('verdict-badge').innerHTML = `
    ${verdictEmoji(v.overall_verdict)} ${v.overall_verdict} <br>
    <span style="font-size:1rem">${v.overall_score}/100</span>
  `;
  document.getElementById('verdict-scores').innerHTML = `
    ${scoreHtml('Permission Risk', v.permission_risk, riskColor(v.permission_risk))}
    ${scoreHtml('Dark Pattern Risk', v.dark_pattern_risk, riskColor(v.dark_pattern_risk))}
    ${scoreHtml('Fake App Risk', v.fake_app_risk, riskColor(v.fake_app_risk))}
  `;
  document.getElementById('verdict-recommendation').textContent = v.recommendation;

  // MODULE 1
  document.getElementById('m1-status').textContent = m1.status;
  document.getElementById('m1-body').innerHTML = `
    ${dataRow('Valid APK/ZIP', m1.is_valid_apk ? '<span class="tag tag-ok">YES</span>' : '<span class="tag tag-bad">NO</span>')}
    ${dataRow('AndroidManifest.xml', m1.has_manifest ? '<span class="tag tag-ok">FOUND</span>' : '<span class="tag tag-warn">NOT FOUND</span>')}
    ${dataRow('DEX Code', m1.has_dex_code ? '<span class="tag tag-ok">FOUND</span>' : '<span class="tag tag-info">NONE</span>')}
    ${dataRow('Native Libraries', m1.has_native_libs ? '<span class="tag tag-warn">PRESENT</span>' : '<span class="tag tag-ok">NONE</span>')}
    ${dataRow('Total Files', `<span class="data-val">${m1.total_files || '—'}</span>`)}
    ${dataRow('Analysis Type', `<span class="data-val">${m1.analysis_type || 'APK Binary'}</span>`)}
  `;

  // MODULE 2
  document.getElementById('m2-status').textContent = m2.status;
  const pBar = riskBar('Permission Risk Score', m2.risk_score);
  document.getElementById('m2-body').innerHTML = `
    ${dataRow('Total Permissions', `<span class="data-val">${m2.total_permissions}</span>`)}
    ${dataRow('High Risk', `<span class="tag tag-bad">${m2.high_risk_count} perms</span>`)}
    ${dataRow('Medium Risk', `<span class="tag tag-warn">${m2.medium_risk_count} perms</span>`)}
    ${dataRow('Low Risk', `<span class="tag tag-info">${m2.low_risk_count} perms</span>`)}
    ${pBar}
  `;

  // MODULE 3
  document.getElementById('m3-status').textContent = m3.status;
  const dpDetails = m3.details;
  const dpKeys = Object.keys(dpDetails);
  document.getElementById('m3-body').innerHTML = `
    ${dataRow('Dark Score', `<span class="data-val" style="color:${riskColor(m3.dark_score)}">${m3.dark_score}/100</span>`)}
    ${dataRow('Patterns Detected', `<span class="data-val">${m3.patterns_detected}</span>`)}
    ${m3.is_dark ? '<div class="tag tag-bad" style="margin:0.5rem 0">⚠️ DARK PATTERNS DETECTED</div>' : '<div class="tag tag-ok" style="margin:0.5rem 0">✓ No Major Dark Patterns</div>'}
    <div class="dp-grid" style="margin-top:1rem">
      ${dpKeys.length > 0 ? dpKeys.map(k => `
        <div class="dp-item">
          <div class="dp-name">${k.replace(/_/g,' ')}</div>
          <div class="dp-match">Matches: ${dpDetails[k].matches.join(', ')}</div>
          <span class="tag ${dpDetails[k].severity === 'HIGH' ? 'tag-bad' : 'tag-warn'}" style="margin-top:0.3rem;display:inline-block">${dpDetails[k].severity}</span>
        </div>
      `).join('') : '<div class="no-patterns">✓ No dark patterns found in provided text</div>'}
    </div>
  `;

  // MODULE 4
  document.getElementById('m4-status').textContent = m4.status;
  document.getElementById('m4-body').innerHTML = `
    ${dataRow('Fake Score', `<span class="data-val" style="color:${riskColor(m4.fake_score)}">${m4.fake_score}/100</span>`)}
    ${dataRow('Indicators Found', `<span class="data-val">${m4.indicators_found}</span>`)}
    ${m4.is_fake ? '<div class="tag tag-bad" style="margin:0.5rem 0">🚨 LIKELY FAKE/MALICIOUS APP</div>' : '<div class="tag tag-ok" style="margin:0.5rem 0">✓ No Fake App Signatures Detected</div>'}
    <div class="fi-list" style="margin-top:1rem">
      ${m4.indicators.length > 0 ? m4.indicators.map(i => `
        <div class="fi-item">
          <span class="fi-sev ${i.severity}">${i.severity}</span>
          <div>
            <div class="fi-type">${i.type.replace(/_/g,' ')}</div>
            <div class="fi-detail">${i.detail}</div>
          </div>
        </div>
      `).join('') : '<div class="no-patterns">✓ No fake app indicators detected</div>'}
    </div>
  `;

  // FULL PERMISSION TABLE
  renderPermissionTable(m2.breakdown);
}

function renderPermissionTable(breakdown) {
  const all = [
    ...breakdown.HIGH.map(p => ({...p, risk:'HIGH'})),
    ...breakdown.MEDIUM.map(p => ({...p, risk:'MEDIUM'})),
    ...breakdown.LOW.map(p => ({...p, risk:'LOW'})),
    ...breakdown.UNKNOWN.map(p => ({...p, risk:'UNKNOWN'})),
  ];

  const tagClass = {HIGH:'tag-bad', MEDIUM:'tag-warn', LOW:'tag-info', UNKNOWN:'tag-info'};
  const html = `<div class="perm-table-grid">
    ${all.map(p => `
      <div class="pti">
        <span class="pti-risk tag ${tagClass[p.risk] || 'tag-info'}">${p.risk}</span>
        <span class="pti-name">${p.short_name}</span>
        <span class="pti-desc">${p.description || '—'}</span>
        <span class="pti-full">${p.permission}</span>
      </div>
    `).join('')}
  </div>`;
  document.getElementById('perm-table').innerHTML = html;
}

// ─── HELPERS ───
function dataRow(label, val) {
  return `<div class="data-row"><span class="data-label">${label}</span>${val}</div>`;
}

function riskBar(label, score) {
  const color = riskColor(score);
  return `
    <div class="risk-bar-wrap">
      <div class="risk-bar-label"><span>${label}</span><span style="color:${color}">${score}/100</span></div>
      <div class="risk-bar-bg"><div class="risk-bar-fill" style="width:${score}%;background:${color}"></div></div>
    </div>`;
}

function scoreHtml(label, val, color) {
  return `<div class="vscore">
    <span class="vscore-val" style="color:${color}">${val}</span>
    <span class="vscore-label">${label}</span>
  </div>`;
}

function riskColor(score) {
  if (score >= 70) return 'var(--danger)';
  if (score >= 40) return 'var(--warning)';
  if (score >= 20) return 'var(--caution)';
  return 'var(--safe)';
}

function verdictColor(v) {
  return {DANGEROUS:'var(--danger)', SUSPICIOUS:'var(--warning)', CAUTION:'var(--caution)', SAFE:'var(--safe)'}[v] || 'var(--border)';
}

function verdictEmoji(v) {
  return {DANGEROUS:'⛔', SUSPICIOUS:'⚠️', CAUTION:'🔶', SAFE:'✅'}[v] || '?';
}

// ─── LOAD STATS ───
async function loadStats() {
  try {
    const res = await fetch(`${API_BASE}/api/stats`);
    const d = await res.json();
    document.getElementById('s-total').textContent = d.total_analyzed.toLocaleString();
    document.getElementById('s-fake').textContent = d.fake_detected.toLocaleString();
    document.getElementById('s-dark').textContent = d.dark_patterns.toLocaleString();
    document.getElementById('s-safe').textContent = d.safe_apps.toLocaleString();
  } catch {}
}

loadStats();
