/* ═══════════════════════════════════════════════════════════════
   QR SENTINEL — script.js  |  Full Working Build
   All features functional: camera scan, file upload, URL analysis,
   live preview, copy button, history log, danger modal.
   ═══════════════════════════════════════════════════════════════ */

document.addEventListener('DOMContentLoaded', () => {

  /* ─────────────────────────────────────────────────────────────
     CONFIG: THREAT DATABASES
  ───────────────────────────────────────────────────────────── */
  const DANGEROUS_EXT = [
    '.exe','.apk','.bat','.msi','.vbs','.cmd','.com',
    '.scr','.pif','.jar','.ps1','.reg','.hta',
    '.wsf','.dmg','.sh','.dll','.sys','.drv','.lnk',
    '.iso','.img','.rar','.7z','.cab'
  ];

  const PHISHING_KEYWORDS = [
    'login','signin','sign-in','verify','account','secure',
    'update','confirm','wallet','bank','paypal','password',
    'credential','unlock','claim','prize','free-gift',
    'winner','click-here','limited-offer','urgent','suspended'
  ];

  const BAD_TLDS = [
    '.xyz','.top','.click','.link','.live','.online',
    '.download','.stream','.gq','.cf','.ml','.tk','.ga',
    '.pw','.win','.review','.bid','.trade','.loan','.date',
    '.men','.racing','.kim','.country','.party'
  ];

  /* ─────────────────────────────────────────────────────────────
     STATE
  ───────────────────────────────────────────────────────────── */
  let scanner      = null;
  let isScanning   = false;
  let lastUrl      = '';
  let history      = [];
  let fileScannerReady = true; // guard against double init

  /* ─────────────────────────────────────────────────────────────
     DOM REFS
  ───────────────────────────────────────────────────────────── */
  const $  = id => document.getElementById(id);
  const $$ = sel => document.querySelectorAll(sel);

  const startBtn      = $('startScanBtn');
  const stopBtn       = $('stopScanBtn');
  const fileInput     = $('fileInput');
  const uploadZone    = $('uploadZone');
  const uploadContent = $('uploadContent');
  const idleView      = $('viewfinderIdle');
  const scanLine      = $('scanLine');
  const brackets      = [$$('#cb1,#cb2,#cb3,#cb4')[0], $$('#cb1,#cb2,#cb3,#cb4')[1], $$('#cb1,#cb2,#cb3,#cb4')[2], $$('#cb1,#cb2,#cb3,#cb4')[3]];
  const resultArea    = $('resultArea');
  const rawUrlWrap    = $('rawUrlContainer');
  const rawUrlEl      = $('rawUrlText');
  const copyBtn       = $('copyUrlBtn');
  const threatDetails = $('threatDetails');
  const actionBtns    = $('actionButtons');
  const previewUrlBtn = $('analyzeUrlBtn');
  const clearBtn      = $('clearResultBtn');
  const manualInput   = $('manualUrlInput');
  const manualBtn     = $('manualAnalyzeBtn');
  const previewSec    = $('previewSection');
  const previewFrame  = $('previewFrame');
  const iframeUrlBar  = $('iframeUrlBar');
  const closePrevBtn  = $('closePreviewBtn');
  const historyLog    = $('historyLog');
  const clearHistBtn  = $('clearHistoryBtn');
  const dangerModal   = $('dangerModal');
  const dangerBox     = $('dangerModalBox');
  const dangerExt     = $('dangerExtension');
  const dangerUrlEl   = $('dangerUrl');
  const closeModalBtn = $('closeDangerBtn');
  const statusDot     = $('statusDot');
  const statusText    = $('statusText');
  const toast         = $('toast');

  /* Fix: get corner brackets properly */
  const allBrackets = document.querySelectorAll('.corner-bracket');

  /* ─────────────────────────────────────────────────────────────
     UTILS
  ───────────────────────────────────────────────────────────── */
  function setStatus(state, txt) {
    statusDot.className = 'status-dot';
    if (state === 'active') statusDot.classList.add('active');
    if (state === 'danger') statusDot.classList.add('danger');
    statusText.textContent = txt;
  }

  let toastTimer = null;
  function showToast(msg, type = '') {
    if (toastTimer) clearTimeout(toastTimer);
    toast.textContent = msg;
    toast.className   = 'toast-notif';
    if (type) toast.classList.add('t-' + type);
    requestAnimationFrame(() => requestAnimationFrame(() => toast.classList.add('show')));
    toastTimer = setTimeout(() => toast.classList.remove('show'), 3800);
  }

  function setViewfinder(active) {
    idleView.style.display = active ? 'none' : 'flex';
    scanLine.style.display = active ? 'block' : 'none';
    allBrackets.forEach(el => { el.style.display = active ? 'block' : 'none'; });
  }

  function truncate(str, n = 60) {
    return str.length > n ? str.slice(0, n) + '…' : str;
  }

  /* ─────────────────────────────────────────────────────────────
     SECURITY ANALYSIS ENGINE
  ───────────────────────────────────────────────────────────── */
  function analyzeUrl(raw) {
    const r = {
      raw,
      isUrl: false, isHttps: false, isHttp: false,
      domain: null, path: null,
      dangerExt: null, badTld: null,
      phishWords: [],
      score: 0, level: 'UNKNOWN'
    };

    const low = raw.toLowerCase().trim();
    r.isUrl   = low.startsWith('http://') || low.startsWith('https://') || low.startsWith('ftp://') || /\.[a-z]{2,}/i.test(low);
    r.isHttps = low.startsWith('https://');
    r.isHttp  = low.startsWith('http://') && !r.isHttps;

    try {
      const u    = new URL(low.includes('://') ? low : 'https://' + low);
      r.domain   = u.hostname;
      r.path     = u.pathname;
    } catch (_) {
      r.domain = low.split('/')[0];
    }

    // Dangerous extension check
    for (const ext of DANGEROUS_EXT) {
      const stripped = low.split('?')[0].split('#')[0];
      if (stripped.endsWith(ext)) {
        r.dangerExt = ext;
        r.score += 100;
        break;
      }
    }

    // Phishing keywords
    for (const kw of PHISHING_KEYWORDS) {
      if (low.includes(kw)) { r.phishWords.push(kw); r.score += 12; }
    }

    // Bad TLD
    if (r.domain) {
      for (const tld of BAD_TLDS) {
        if (r.domain.endsWith(tld)) { r.badTld = tld; r.score += 30; break; }
      }
    }

    // HTTP penalty
    if (r.isHttp) r.score += 10;

    // Extra long URL penalty
    if (raw.length > 200) r.score += 10;

    // IP-based URL (not domain)
    if (r.domain && /^\d{1,3}(\.\d{1,3}){3}$/.test(r.domain)) r.score += 35;

    // Risk level
    if (r.dangerExt)       r.level = 'CRITICAL';
    else if (r.score >= 50) r.level = 'HIGH';
    else if (r.score >= 25) r.level = 'MEDIUM';
    else if (r.isHttps)     r.level = 'LOW';
    else if (r.isHttp)      r.level = 'MODERATE';
    else                    r.level = 'UNKNOWN';

    return r;
  }

  /* ─────────────────────────────────────────────────────────────
     RESULT RENDERER
  ───────────────────────────────────────────────────────────── */
  const COLORS = {
    CRITICAL: { text: '#f43f5e', bg: 'rgba(244,63,94,0.08)', border: 'rgba(244,63,94,0.3)' },
    HIGH:     { text: '#fb923c', bg: 'rgba(251,146,60,0.08)', border: 'rgba(251,146,60,0.3)' },
    MEDIUM:   { text: '#d4a017', bg: 'rgba(212,160,23,0.08)', border: 'rgba(212,160,23,0.3)' },
    MODERATE: { text: '#c084fc', bg: 'rgba(192,132,252,0.08)', border: 'rgba(192,132,252,0.3)' },
    LOW:      { text: '#10b981', bg: 'rgba(16,185,129,0.08)',  border: 'rgba(16,185,129,0.3)' },
    UNKNOWN:  { text: '#64748b', bg: 'rgba(100,116,139,0.08)', border: 'rgba(100,116,139,0.3)' },
  };

  const ICONS = {
    CRITICAL: '☠', HIGH: '⚠', MEDIUM: '◈', MODERATE: '◇', LOW: '✓', UNKNOWN: '?'
  };
  const LABELS = {
    CRITICAL: ['FILE BERBAHAYA', 'Ekstensi malware terdeteksi!'],
    HIGH:     ['RISIKO TINGGI',  'Indikator phishing ditemukan'],
    MEDIUM:   ['RISIKO SEDANG',  'Perlu verifikasi manual'],
    MODERATE: ['RISIKO RENDAH',  'URL HTTP tidak terenkripsi'],
    LOW:      ['URL AMAN',       'Tidak ada ancaman yang terdeteksi'],
    UNKNOWN:  ['DATA QR CODE',   'Bukan URL — teks biasa'],
  };

  function renderResult(a) {
    const c  = COLORS[a.level];
    const lbl = LABELS[a.level];
    const isSafe = a.level === 'LOW' || a.level === 'MODERATE';

    // Result icon area
    resultArea.innerHTML = `
      <div class="result-reveal" style="text-align:center; padding-bottom:4px;">
        <div style="width:72px;height:72px;border-radius:50%;background:${c.bg};
          border:2px solid ${c.border};display:flex;align-items:center;
          justify-content:center;margin:0 auto 12px;font-size:30px;
          color:${c.text};box-shadow:0 0 24px ${c.border};">
          ${ICONS[a.level]}
        </div>
        <p style="font-family:'Fira Code',monospace;font-size:11px;letter-spacing:0.2em;color:${c.text};margin-bottom:5px;">${lbl[0]}</p>
        <p style="font-family:'Playfair Display',serif;font-size:14px;color:rgba(148,163,184,0.65);font-style:italic;">${lbl[1]}</p>
      </div>`;

    // Risk bar + detail rows
    const barW = Math.min(a.score, 100);
    let rows = '';
    rows += row('PROTOKOL', a.isHttps ? '🔒 HTTPS' : a.isHttp ? '⚠ HTTP' : 'N/A',
                a.isHttps ? 'r-safe' : a.isHttp ? 'r-warn' : '');
    if (a.domain)      rows += row('DOMAIN', a.domain, 'r-safe');
    if (a.path && a.path !== '/') rows += row('PATH', truncate(a.path, 40), '');
    if (a.dangerExt)   rows += row('EXT BERBAHAYA', a.dangerExt.toUpperCase(), 'r-danger');
    if (a.badTld)      rows += row('TLD MENCURIGAKAN', a.badTld, 'r-warn');
    if (a.phishWords.length) rows += row('KATA PHISHING', a.phishWords.slice(0,3).join(', '), 'r-warn');
    rows += row('RISK LEVEL', `<span style="color:${c.text};font-weight:500;">${a.level}</span>`,
                a.level === 'LOW' ? 'r-safe' : a.level === 'HIGH' || a.level === 'CRITICAL' ? 'r-danger' : 'r-warn');

    threatDetails.innerHTML = `
      <div class="risk-bar-wrap">
        <div style="display:flex;justify-content:space-between;align-items:center;">
          <span class="row-label">RISK SCORE</span>
          <span style="font-family:'Fira Code',monospace;font-size:11px;color:${c.text};">${Math.min(a.score,100)}<span style="opacity:0.4;">/100</span></span>
        </div>
        <div class="risk-bar-track">
          <div class="risk-bar-fill" style="width:${barW}%;background:linear-gradient(90deg,${c.border},${c.text});"></div>
        </div>
      </div>
      ${rows}`;

    // Show URL + detail + actions
    rawUrlEl.textContent    = a.raw;
    rawUrlWrap.style.display   = 'block';
    threatDetails.style.display = 'block';
    actionBtns.style.display   = 'flex';

    // Show "open preview" only for safe URLs
    previewUrlBtn.style.display = (isSafe && a.isUrl) ? 'inline-flex' : 'none';
  }

  function row(label, value, cls = '') {
    return `<div class="threat-row ${cls}">
      <span class="row-label">${label}</span>
      <span class="row-value">${value}</span>
    </div>`;
  }

  /* ─────────────────────────────────────────────────────────────
     HISTORY
  ───────────────────────────────────────────────────────────── */
  function addHistory(url, level) {
    const ts  = new Date().toLocaleTimeString('id-ID');
    const c   = COLORS[level];
    const ok  = level === 'LOW' || level === 'MODERATE';
    const bad = level === 'CRITICAL' || level === 'HIGH';
    const cls = ok ? 'h-safe' : bad ? 'h-danger' : 'h-warn';
    const icon = ok ? '✓' : bad ? '✕' : '◈';
    const iconBg = ok
      ? 'rgba(16,185,129,0.1);border-color:rgba(16,185,129,0.3)'
      : bad
        ? 'rgba(244,63,94,0.1);border-color:rgba(244,63,94,0.3)'
        : 'rgba(212,160,23,0.1);border-color:rgba(212,160,23,0.3)';

    const el = document.createElement('div');
    el.className = `history-item ${cls}`;
    el.innerHTML = `
      <div class="h-icon" style="background:${iconBg};color:${c.text};border:1px solid;">${icon}</div>
      <div style="flex:1;min-width:0;">
        <p style="font-family:'Fira Code',monospace;font-size:11px;color:rgba(240,237,248,0.75);
          white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${truncate(url, 52)}</p>
        <div style="display:flex;gap:14px;margin-top:3px;">
          <span style="font-family:'Fira Code',monospace;font-size:9px;color:${c.text};letter-spacing:0.1em;">${level}</span>
          <span style="font-family:'Fira Code',monospace;font-size:9px;color:rgba(100,116,139,0.5);">${ts}</span>
        </div>
      </div>`;

    const empty = $('historyEmpty');
    if (empty) empty.remove();
    historyLog.prepend(el);
    history.unshift({ url, level, ts });
  }

  /* ─────────────────────────────────────────────────────────────
     PROCESS SCAN RESULT
  ───────────────────────────────────────────────────────────── */
  function processScan(text) {
    if (text === lastUrl) return;
    lastUrl = text;

    const a = analyzeUrl(text);
    renderResult(a);
    addHistory(text, a.level);

    if (a.dangerExt) {
      showDanger(text, a.dangerExt);
      showToast('⚠ ANCAMAN KRITIS — File berbahaya terdeteksi!', 'danger');
      previewSec.style.display = 'none';
    } else if (a.level === 'HIGH') {
      showToast('⚠ Risiko tinggi — Indikator phishing terdeteksi', 'danger');
    } else if (a.level === 'LOW') {
      showToast('✓ URL tampak aman', 'safe');
    } else {
      showToast('Scan selesai — Periksa hasil analisis', 'gold');
    }

    setStatus('idle', 'SCAN SELESAI');
  }

  /* ─────────────────────────────────────────────────────────────
     DANGER MODAL
  ───────────────────────────────────────────────────────────── */
  function showDanger(url, ext) {
    dangerExt.textContent   = ext.toUpperCase() + '  —  Ekstensi Malware!';
    dangerUrlEl.textContent = truncate(url, 90);
    dangerModal.style.display = 'flex';
    document.body.style.overflow = 'hidden';
    setStatus('danger', 'ANCAMAN KRITIS TERDETEKSI');
  }

  function hideDanger() {
    dangerModal.style.display = 'none';
    document.body.style.overflow = '';
    setStatus('idle', 'SYSTEM IDLE');
  }

  closeModalBtn.addEventListener('click', hideDanger);
  dangerModal.addEventListener('click', e => { if (e.target === dangerModal) hideDanger(); });
  document.addEventListener('keydown', e => { if (e.key === 'Escape' && dangerModal.style.display !== 'none') hideDanger(); });

  /* ─────────────────────────────────────────────────────────────
     CAMERA SCANNER — START
  ───────────────────────────────────────────────────────────── */
  startBtn.addEventListener('click', () => {
    if (isScanning) return;

    // Clean up any previous instance
    if (scanner) {
      try { scanner.clear(); } catch(_) {}
      scanner = null;
    }

    scanner = new Html5Qrcode('qr-reader');

    scanner.start(
      { facingMode: 'environment' },
      { fps: 12, qrbox: { width: 220, height: 220 }, aspectRatio: 1.0 },
      (text) => { processScan(text); },
      (_err) => { /* silent — frame without QR */ }
    ).then(() => {
      isScanning = true;
      startBtn.disabled = true;
      stopBtn.disabled  = false;
      setViewfinder(true);
      setStatus('active', 'KAMERA AKTIF — SCANNING...');
      showToast('Kamera aktif. Arahkan ke QR Code.', '');
    }).catch(err => {
      console.error('[QR Sentinel] Kamera gagal:', err);
      showToast('Gagal akses kamera. Periksa izin browser.', 'danger');
    });
  });

  /* ─────────────────────────────────────────────────────────────
     CAMERA SCANNER — STOP
  ───────────────────────────────────────────────────────────── */
  stopBtn.addEventListener('click', () => {
    if (!isScanning || !scanner) return;

    scanner.stop().then(() => {
      scanner.clear();
      scanner    = null;
      isScanning = false;
      startBtn.disabled = false;
      stopBtn.disabled  = true;
      setViewfinder(false);
      setStatus('idle', 'SYSTEM IDLE');
      lastUrl = '';
      showToast('Kamera dihentikan.', '');
    }).catch(err => {
      console.error('[QR Sentinel] Stop gagal:', err);
    });
  });

  /* ─────────────────────────────────────────────────────────────
     FILE UPLOAD
  ───────────────────────────────────────────────────────────── */
  uploadZone.addEventListener('click', (e) => {
    if (e.target === fileInput) return;
    fileInput.click();
  });

  fileInput.addEventListener('change', e => {
    const file = e.target.files[0];
    if (file) scanFile(file);
    fileInput.value = '';
  });

  uploadZone.addEventListener('dragover',  e => { e.preventDefault(); uploadZone.classList.add('dragging'); });
  uploadZone.addEventListener('dragleave', () => uploadZone.classList.remove('dragging'));
  uploadZone.addEventListener('drop', e => {
    e.preventDefault();
    uploadZone.classList.remove('dragging');
    const file = e.dataTransfer.files[0];
    if (file && file.type.startsWith('image/')) scanFile(file);
    else showToast('Hanya file gambar yang didukung.', 'danger');
  });

  function scanFile(file) {
    if (!fileScannerReady) return;
    fileScannerReady = false;

    uploadContent.innerHTML = `
      <div style="font-size:26px;color:#9333ea;opacity:0.6;animation:idleBreath 1s infinite;">↺</div>
      <p style="font-family:'Fira Code',monospace;font-size:10px;color:rgba(148,163,184,0.5);letter-spacing:0.1em;margin-top:8px;">MEMPROSES GAMBAR...</p>`;
    setStatus('active', 'MEMINDAI GAMBAR...');

    // Ensure temp element exists
    let tempEl = $('_qr_file_scan_temp');
    if (!tempEl) {
      tempEl = document.createElement('div');
      tempEl.id = '_qr_file_scan_temp';
      tempEl.style.cssText = 'position:absolute;left:-9999px;top:-9999px;width:1px;height:1px;overflow:hidden;';
      document.body.appendChild(tempEl);
    }

    const fs = new Html5Qrcode('_qr_file_scan_temp');
    fs.scanFile(file, /* showImage= */ false)
      .then(text => {
        processScan(text);
        showToast('QR Code berhasil dibaca dari gambar!', 'safe');
      })
      .catch(_err => {
        showToast('Tidak ada QR Code yang terdeteksi dalam gambar.', 'danger');
        setStatus('idle', 'SYSTEM IDLE');
      })
      .finally(() => {
        try { fs.clear(); } catch(_) {}
        fileScannerReady = true;
        resetUpload();
      });
  }

  function resetUpload() {
    uploadContent.innerHTML = `
      <div class="upload-arrow">↑</div>
      <p style="font-family:'Tenor Sans',sans-serif;font-size:11px;color:rgba(148,163,184,0.45);letter-spacing:0.1em;margin-top:8px;">UPLOAD GAMBAR QR CODE</p>
      <p style="font-family:'Playfair Display',serif;font-size:13px;color:rgba(148,163,184,0.25);font-style:italic;margin-top:4px;">Klik atau seret file ke sini</p>`;
  }

  /* ─────────────────────────────────────────────────────────────
     COPY URL BUTTON
  ───────────────────────────────────────────────────────────── */
  copyBtn.addEventListener('click', () => {
    if (!lastUrl) return;
    navigator.clipboard.writeText(lastUrl).then(() => {
      copyBtn.classList.add('copied');
      copyBtn.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>`;
      setTimeout(() => {
        copyBtn.classList.remove('copied');
        copyBtn.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`;
      }, 2000);
      showToast('URL disalin ke clipboard.', 'safe');
    }).catch(() => {
      showToast('Gagal menyalin URL.', 'danger');
    });
  });

  /* ─────────────────────────────────────────────────────────────
     OPEN LIVE PREVIEW
  ───────────────────────────────────────────────────────────── */
  previewUrlBtn.addEventListener('click', () => {
    if (!lastUrl) return;
    const full = lastUrl.startsWith('http') ? lastUrl : 'https://' + lastUrl;
    previewFrame.src = full;
    iframeUrlBar.textContent = full;
    previewSec.style.display = 'block';
    previewSec.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    showToast('Preview dimuat dalam sandbox terisolasi.', 'safe');
  });

  closePrevBtn.addEventListener('click', () => {
    previewSec.style.display = 'none';
    previewFrame.src = 'about:blank';
    iframeUrlBar.textContent = '—';
  });

  /* ─────────────────────────────────────────────────────────────
     CLEAR RESULT
  ───────────────────────────────────────────────────────────── */
  clearBtn.addEventListener('click', () => {
    resultArea.innerHTML = `
      <div style="text-align:center;padding:40px 0;">
        <div class="radar-ring">
          <div class="radar-sweep"></div>
          <div class="radar-center"></div>
        </div>
        <p style="font-family:'Fira Code',monospace;font-size:10px;color:rgba(100,116,139,0.3);letter-spacing:0.15em;margin-top:20px;">MENUNGGU DATA INPUT...</p>
      </div>`;
    rawUrlWrap.style.display    = 'none';
    threatDetails.style.display = 'none';
    actionBtns.style.display    = 'none';
    previewSec.style.display    = 'none';
    previewFrame.src  = 'about:blank';
    iframeUrlBar.textContent = '—';
    lastUrl = '';
    setStatus('idle', 'SYSTEM IDLE');
    showToast('Hasil direset.', '');
  });

  /* ─────────────────────────────────────────────────────────────
     MANUAL URL ANALYZER
  ───────────────────────────────────────────────────────────── */
  function runManual() {
    const url = manualInput.value.trim();
    if (!url) { showToast('Masukkan URL terlebih dahulu.', 'danger'); return; }
    lastUrl = url;
    processScan(url);
    manualInput.value = '';
  }

  manualBtn.addEventListener('click', runManual);
  manualInput.addEventListener('keydown', e => { if (e.key === 'Enter') runManual(); });

  /* ─────────────────────────────────────────────────────────────
     CLEAR HISTORY
  ───────────────────────────────────────────────────────────── */
  clearHistBtn.addEventListener('click', () => {
    history = [];
    historyLog.innerHTML = `
      <div id="historyEmpty" style="text-align:center;padding:32px 0;">
        <p style="font-family:'Fira Code',monospace;font-size:10px;color:rgba(100,116,139,0.2);letter-spacing:0.15em;">BELUM ADA RIWAYAT SCAN</p>
      </div>`;
    showToast('Riwayat scan dihapus.', '');
  });

  /* ─────────────────────────────────────────────────────────────
     INIT
  ───────────────────────────────────────────────────────────── */
  setStatus('idle', 'SYSTEM IDLE');
  setViewfinder(false);

  console.log('%c ◈ QR SENTINEL v2.4.1 READY ◈ ', 'background:#1a0a3a;color:#d4a017;font-family:monospace;font-size:13px;padding:6px 16px;border-radius:6px;border:1px solid #6b21a8;');

}); // END DOMContentLoaded
