/* ═══════════════════════════════════════════════════════════════
   QR SENTINEL — script.js
   Core Scanner Logic + Cybersecurity Analysis Engine
   ═══════════════════════════════════════════════════════════════ */

document.addEventListener('DOMContentLoaded', () => {

  /* ─────────────────────────────────────────────────────────────
     CONFIGURATION
  ───────────────────────────────────────────────────────────── */
  const DANGEROUS_EXTENSIONS = [
    '.exe', '.apk', '.bat', '.msi', '.vbs', '.cmd', '.com',
    '.scr', '.pif', '.jar', '.ps1', '.reg', '.hta', '.js',
    '.wsf', '.dmg', '.sh', '.py', '.rb', '.php', '.asp',
    '.aspx', '.cgi', '.pl', '.dll', '.sys', '.drv', '.lnk'
  ];

  const SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'account', 'secure', 'update',
    'confirm', 'wallet', 'bank', 'paypal', 'password', 'credential',
    'unlock', 'claim', 'prize', 'free', 'winner', 'click-here'
  ];

  const SUSPICIOUS_TLDS = [
    '.xyz', '.top', '.click', '.link', '.live', '.online',
    '.download', '.stream', '.gq', '.cf', '.ml', '.tk', '.ga',
    '.pw', '.win', '.review', '.bid', '.trade'
  ];

  /* ─────────────────────────────────────────────────────────────
     STATE
  ───────────────────────────────────────────────────────────── */
  let html5QrCode = null;
  let isScanning  = false;
  let scanHistory = [];
  let lastScannedUrl = '';

  /* ─────────────────────────────────────────────────────────────
     DOM ELEMENT REFERENCES
  ───────────────────────────────────────────────────────────── */
  const startScanBtn      = document.getElementById('startScanBtn');
  const stopScanBtn       = document.getElementById('stopScanBtn');
  const fileInput         = document.getElementById('fileInput');
  const uploadZone        = document.getElementById('uploadZone');
  const uploadContent     = document.getElementById('uploadContent');
  const viewfinderIdle    = document.getElementById('viewfinderIdle');
  const scanLine          = document.getElementById('scanLine');
  const cornerBrackets    = document.querySelectorAll('[id^="cornerBrackets"]');
  const resultArea        = document.getElementById('resultArea');
  const rawUrlContainer   = document.getElementById('rawUrlContainer');
  const rawUrlText        = document.getElementById('rawUrlText');
  const threatDetails     = document.getElementById('threatDetails');
  const actionButtons     = document.getElementById('actionButtons');
  const analyzeUrlBtn     = document.getElementById('analyzeUrlBtn');
  const clearResultBtn    = document.getElementById('clearResultBtn');
  const manualUrlInput    = document.getElementById('manualUrlInput');
  const manualAnalyzeBtn  = document.getElementById('manualAnalyzeBtn');
  const previewSection    = document.getElementById('previewSection');
  const previewFrame      = document.getElementById('previewFrame');
  const closePreviewBtn   = document.getElementById('closePreviewBtn');
  const historyLog        = document.getElementById('historyLog');
  const clearHistoryBtn   = document.getElementById('clearHistoryBtn');
  const dangerModal       = document.getElementById('dangerModal');
  const dangerModalBox    = document.getElementById('dangerModalBox');
  const dangerExtension   = document.getElementById('dangerExtension');
  const dangerUrl         = document.getElementById('dangerUrl');
  const closeDangerBtn    = document.getElementById('closeDangerBtn');
  const statusDot         = document.getElementById('statusDot');
  const statusText        = document.getElementById('statusText');
  const toast             = document.getElementById('toast');

  /* ─────────────────────────────────────────────────────────────
     UTILITY: STATUS BAR
  ───────────────────────────────────────────────────────────── */
  function setStatus(state, text) {
    statusDot.className = 'status-dot';
    if (state === 'active')  statusDot.classList.add('active');
    if (state === 'danger')  statusDot.classList.add('danger');
    statusText.textContent = text;
  }

  /* ─────────────────────────────────────────────────────────────
     UTILITY: TOAST NOTIFICATION
  ───────────────────────────────────────────────────────────── */
  let toastTimer = null;
  function showToast(message, type = 'neutral') {
    if (toastTimer) clearTimeout(toastTimer);
    toast.textContent = message;
    toast.className = 'toast';
    if (type === 'safe')   toast.classList.add('toast-safe');
    if (type === 'danger') toast.classList.add('toast-danger');
    requestAnimationFrame(() => {
      requestAnimationFrame(() => { toast.classList.add('show'); });
    });
    toastTimer = setTimeout(() => {
      toast.classList.remove('show');
    }, 3500);
  }

  /* ─────────────────────────────────────────────────────────────
     UTILITY: VIEWFINDER TOGGLE
  ───────────────────────────────────────────────────────────── */
  function showViewfinderActive() {
    viewfinderIdle.style.display = 'none';
    scanLine.style.display = 'block';
    cornerBrackets.forEach(el => { el.style.display = 'block'; });
  }

  function showViewfinderIdle() {
    viewfinderIdle.style.display = 'flex';
    scanLine.style.display = 'none';
    cornerBrackets.forEach(el => { el.style.display = 'none'; });
  }

  /* ─────────────────────────────────────────────────────────────
     SECURITY ENGINE: URL DISSECTION
  ───────────────────────────────────────────────────────────── */
  function analyzeUrl(url) {
    const result = {
      url,
      isUrl: false,
      hasDangerousExt: false,
      dangerousExt: null,
      isSuspiciousKeyword: false,
      suspiciousWords: [],
      hasSuspiciousTld: false,
      suspiciousTld: null,
      isHttp: false,
      isHttps: false,
      domain: null,
      protocol: null,
      path: null,
      riskScore: 0,
      riskLevel: 'UNKNOWN',
    };

    const urlLower = url.toLowerCase().trim();

    // Check if URL
    result.isUrl = urlLower.startsWith('http://') ||
                   urlLower.startsWith('https://') ||
                   urlLower.startsWith('ftp://') ||
                   urlLower.includes('.');

    result.isHttps = urlLower.startsWith('https://');
    result.isHttp  = urlLower.startsWith('http://') && !result.isHttps;

    // Parse URL
    try {
      const parsed = new URL(url.includes('://') ? url : 'https://' + url);
      result.domain   = parsed.hostname;
      result.protocol = parsed.protocol;
      result.path     = parsed.pathname;
    } catch (_) {
      result.domain = urlLower.split('/')[0];
    }

    // Check dangerous extensions
    for (const ext of DANGEROUS_EXTENSIONS) {
      if (urlLower.endsWith(ext) || urlLower.includes(ext + '?') || urlLower.includes(ext + '#')) {
        result.hasDangerousExt = true;
        result.dangerousExt = ext;
        result.riskScore += 100;
        break;
      }
    }

    // Check suspicious keywords
    for (const kw of SUSPICIOUS_KEYWORDS) {
      if (urlLower.includes(kw)) {
        result.suspiciousWords.push(kw);
        result.riskScore += 15;
      }
    }
    result.isSuspiciousKeyword = result.suspiciousWords.length > 0;

    // Check suspicious TLDs
    for (const tld of SUSPICIOUS_TLDS) {
      if (result.domain && result.domain.endsWith(tld)) {
        result.hasSuspiciousTld = true;
        result.suspiciousTld = tld;
        result.riskScore += 25;
        break;
      }
    }

    // HTTP penalty
    if (result.isHttp) result.riskScore += 10;

    // Risk level calculation
    if (result.hasDangerousExt) {
      result.riskLevel = 'CRITICAL';
    } else if (result.riskScore >= 40) {
      result.riskLevel = 'HIGH';
    } else if (result.riskScore >= 20) {
      result.riskLevel = 'MEDIUM';
    } else if (result.isHttps) {
      result.riskLevel = 'LOW';
    } else {
      result.riskLevel = 'MODERATE';
    }

    return result;
  }

  /* ─────────────────────────────────────────────────────────────
     DANGER MODAL: Show & Hide
  ───────────────────────────────────────────────────────────── */
  function showDangerModal(url, ext) {
    dangerExtension.textContent = ext.toUpperCase() + ' — File Berbahaya Terdeteksi!';
    dangerUrl.textContent = url.length > 80 ? url.slice(0, 80) + '...' : url;
    dangerModal.style.display = 'flex';
    dangerModalBox.classList.add('blink-alert');
    setStatus('danger', 'ANCAMAN TERDETEKSI');
    document.body.style.overflow = 'hidden';
  }

  function hideDangerModal() {
    dangerModal.style.display = 'none';
    dangerModalBox.classList.remove('blink-alert');
    document.body.style.overflow = '';
    setStatus('idle', 'SYSTEM IDLE');
  }

  closeDangerBtn.addEventListener('click', hideDangerModal);

  // Close on overlay click
  dangerModal.addEventListener('click', (e) => {
    if (e.target === dangerModal) hideDangerModal();
  });

  // Close on Escape
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && dangerModal.style.display !== 'none') {
      hideDangerModal();
    }
  });

  /* ─────────────────────────────────────────────────────────────
     RESULT RENDERER
  ───────────────────────────────────────────────────────────── */
  function getRiskColor(level) {
    const map = {
      CRITICAL: { text: '#ff2244', bg: 'rgba(255,34,68,0.08)', border: 'rgba(255,34,68,0.3)' },
      HIGH:     { text: '#ff6b35', bg: 'rgba(255,107,53,0.08)', border: 'rgba(255,107,53,0.3)' },
      MEDIUM:   { text: '#ffd700', bg: 'rgba(255,215,0,0.08)',  border: 'rgba(255,215,0,0.3)' },
      MODERATE: { text: '#c77dff', bg: 'rgba(199,125,255,0.08)', border: 'rgba(199,125,255,0.3)' },
      LOW:      { text: '#00d68f', bg: 'rgba(0,214,143,0.08)', border: 'rgba(0,214,143,0.3)' },
      UNKNOWN:  { text: '#a8a8b3', bg: 'rgba(168,168,179,0.08)', border: 'rgba(168,168,179,0.3)' },
    };
    return map[level] || map.UNKNOWN;
  }

  function renderResult(analysis) {
    const colors = getRiskColor(analysis.riskLevel);
    const isSafe = analysis.riskLevel === 'LOW' || analysis.riskLevel === 'MODERATE';

    // Radar result area
    let icon, iconColor, headline, subline;
    if (analysis.hasDangerousExt) {
      icon = '☠'; iconColor = '#ff2244';
      headline = 'FILE BERBAHAYA';
      subline  = 'Ekstensi malware terdeteksi';
    } else if (analysis.riskLevel === 'HIGH') {
      icon = '⚠'; iconColor = '#ff6b35';
      headline = 'RISIKO TINGGI';
      subline  = 'Beberapa indikator phishing ditemukan';
    } else if (analysis.riskLevel === 'MEDIUM') {
      icon = '◈'; iconColor = '#ffd700';
      headline = 'RISIKO SEDANG';
      subline  = 'Perlu verifikasi manual';
    } else if (isSafe) {
      icon = '✓'; iconColor = '#00d68f';
      headline = 'URL TAMPAK AMAN';
      subline  = 'Tidak ada ancaman yang terdeteksi';
    } else {
      icon = '?'; iconColor = '#c77dff';
      headline = 'DATA QR CODE';
      subline  = 'Bukan URL, teks biasa';
    }

    resultArea.innerHTML = `
      <div style="text-align:center; margin-bottom:16px; animation: resultReveal 0.4s ease-out;">
        <div style="
          width:64px; height:64px; border-radius:50%;
          background:${colors.bg}; border:2px solid ${colors.border};
          display:flex; align-items:center; justify-content:center;
          font-size:28px; margin:0 auto 12px; color:${iconColor};
          box-shadow: 0 0 20px ${colors.border};
        ">${icon}</div>
        <p style="font-family:'JetBrains Mono',monospace; font-size:11px; letter-spacing:0.2em; color:${iconColor}; margin-bottom:4px;">${headline}</p>
        <p style="font-family:'Cormorant Garamond',serif; font-size:13px; color:rgba(168,168,179,0.7); font-style:italic;">${subline}</p>
      </div>
    `;

    // Risk Score Bar
    const barWidth = Math.min(analysis.riskScore, 100);
    threatDetails.innerHTML = `
      <div style="margin-bottom:10px;">
        <div style="display:flex; justify-content:space-between; margin-bottom:6px;">
          <span style="font-family:'JetBrains Mono',monospace; font-size:10px; color:rgba(168,168,179,0.5); letter-spacing:0.1em;">RISK SCORE</span>
          <span style="font-family:'JetBrains Mono',monospace; font-size:11px; color:${iconColor};">${Math.min(analysis.riskScore, 100)}/100</span>
        </div>
        <div style="background:rgba(6,6,10,0.6); border-radius:4px; height:6px; overflow:hidden;">
          <div style="width:${barWidth}%; height:100%; background:linear-gradient(90deg, ${colors.border}, ${iconColor}); border-radius:4px; transition:width 1s ease;"></div>
        </div>
      </div>
      ${buildDetailRows(analysis, iconColor)}
    `;

    rawUrlText.textContent = analysis.url;
    rawUrlContainer.style.display = 'block';
    threatDetails.style.display = 'block';
    actionButtons.style.display = 'flex';

    // Show live preview if safe URL
    if (isSafe && analysis.isUrl) {
      analyzeUrlBtn.style.display = 'flex';
    } else {
      analyzeUrlBtn.style.display = 'none';
    }
  }

  function buildDetailRows(analysis, iconColor) {
    const rows = [];

    rows.push(buildRow('PROTOKOL',
      analysis.isHttps ? '🔒 HTTPS (Terenkripsi)' : analysis.isHttp ? '⚠ HTTP (Tidak Terenkripsi)' : 'N/A',
      analysis.isHttps ? 'safe-row' : 'warn-row'
    ));

    if (analysis.domain) {
      rows.push(buildRow('DOMAIN', analysis.domain, 'safe-row'));
    }

    if (analysis.hasDangerousExt) {
      rows.push(buildRow('EKSTENSI BERBAHAYA', analysis.dangerousExt.toUpperCase(), 'danger-row'));
    }

    if (analysis.hasSuspiciousTld) {
      rows.push(buildRow('TLD MENCURIGAKAN', analysis.suspiciousTld, 'warn-row'));
    }

    if (analysis.suspiciousWords.length > 0) {
      rows.push(buildRow('KATA MENCURIGAKAN', analysis.suspiciousWords.join(', '), 'warn-row'));
    }

    rows.push(buildRow('LEVEL RISIKO',
      `<span style="color:${iconColor}; font-weight:500;">${analysis.riskLevel}</span>`,
      analysis.riskLevel === 'LOW' || analysis.riskLevel === 'MODERATE' ? 'safe-row' :
      analysis.riskLevel === 'MEDIUM' ? 'warn-row' : 'danger-row'
    ));

    return rows.join('');
  }

  function buildRow(label, value, rowClass) {
    return `
      <div class="threat-info-row ${rowClass}">
        <span style="font-family:'JetBrains Mono',monospace; font-size:10px; color:rgba(168,168,179,0.5); letter-spacing:0.08em;">${label}</span>
        <span style="font-family:'JetBrains Mono',monospace; font-size:11px; color:rgba(232,232,240,0.85);">${value}</span>
      </div>
    `;
  }

  /* ─────────────────────────────────────────────────────────────
     HISTORY LOG
  ───────────────────────────────────────────────────────────── */
  function addToHistory(url, riskLevel) {
    const timestamp = new Date().toLocaleTimeString('id-ID', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    const isSafe = riskLevel === 'LOW' || riskLevel === 'MODERATE';
    const isDanger = riskLevel === 'CRITICAL' || riskLevel === 'HIGH';
    const shortUrl = url.length > 50 ? url.slice(0, 50) + '...' : url;

    const colors = getRiskColor(riskLevel);
    const itemClass = isSafe ? 'safe-item' : isDanger ? 'danger-item' : '';
    const iconClass = isSafe ? 'safe-icon-bg' : 'danger-icon-bg';
    const iconChar  = isSafe ? '✓' : isDanger ? '✗' : '◈';
    const iconColor = isSafe ? '#00d68f' : isDanger ? '#ff2244' : '#c77dff';

    scanHistory.unshift({ url, riskLevel, timestamp });

    const entry = document.createElement('div');
    entry.className = `history-item ${itemClass}`;
    entry.innerHTML = `
      <div class="history-icon ${iconClass}" style="color:${iconColor}; font-size:13px;">${iconChar}</div>
      <div style="flex:1; min-width:0;">
        <p style="font-family:'JetBrains Mono',monospace; font-size:11px; color:rgba(232,232,240,0.8); white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${shortUrl}</p>
        <div style="display:flex; gap:12px; margin-top:3px;">
          <span style="font-family:'JetBrains Mono',monospace; font-size:9px; color:${colors.text}; letter-spacing:0.1em;">${riskLevel}</span>
          <span style="font-family:'JetBrains Mono',monospace; font-size:9px; color:rgba(168,168,179,0.4);">${timestamp}</span>
        </div>
      </div>
    `;

    // Remove empty state message
    const emptyMsg = historyLog.querySelector('.text-center');
    if (emptyMsg) historyLog.innerHTML = '';

    historyLog.prepend(entry);
  }

  /* ─────────────────────────────────────────────────────────────
     MAIN: PROCESS SCAN RESULT
  ───────────────────────────────────────────────────────────── */
  function processScanResult(decodedText) {
    if (decodedText === lastScannedUrl) return;
    lastScannedUrl = decodedText;

    const analysis = analyzeUrl(decodedText);

    renderResult(analysis);
    addToHistory(decodedText, analysis.riskLevel);

    if (analysis.hasDangerousExt) {
      showDangerModal(decodedText, analysis.dangerousExt);
      showToast('⚠ ANCAMAN TERDETEKSI! File berbahaya ditemukan.', 'danger');
      previewSection.style.display = 'none';
    } else if (analysis.riskLevel === 'LOW' || analysis.riskLevel === 'MODERATE') {
      showToast('✓ Scan selesai — URL tampak aman.', 'safe');
    } else {
      showToast('⚠ Scan selesai — Ditemukan risiko. Waspada!', 'neutral');
      previewSection.style.display = 'none';
    }

    setStatus('idle', 'SCAN SELESAI');
  }

  /* ─────────────────────────────────────────────────────────────
     CAMERA SCANNER: Start
  ───────────────────────────────────────────────────────────── */
  startScanBtn.addEventListener('click', () => {
    if (isScanning) return;

    html5QrCode = new Html5Qrcode('qr-reader');

    const config = {
      fps: 15,
      qrbox: { width: 220, height: 220 },
      aspectRatio: 1.0,
      formatsToSupport: [Html5QrcodeSupportedFormats.QR_CODE],
    };

    html5QrCode.start(
      { facingMode: 'environment' },
      config,
      (decodedText) => {
        processScanResult(decodedText);
      },
      (errorMessage) => {
        // Scan error — silently ignored (no QR detected in frame)
      }
    ).then(() => {
      isScanning = true;
      startScanBtn.disabled = true;
      stopScanBtn.disabled  = false;
      showViewfinderActive();
      setStatus('active', 'KAMERA AKTIF — SCANNING...');
      showToast('Kamera aktif. Arahkan ke QR Code.', 'neutral');
    }).catch((err) => {
      console.error('Gagal memulai kamera:', err);
      showToast('Gagal akses kamera. Periksa izin browser.', 'danger');
    });
  });

  /* ─────────────────────────────────────────────────────────────
     CAMERA SCANNER: Stop
  ───────────────────────────────────────────────────────────── */
  stopScanBtn.addEventListener('click', () => {
    if (!isScanning || !html5QrCode) return;

    html5QrCode.stop().then(() => {
      html5QrCode.clear();
      html5QrCode = null;
      isScanning = false;
      startScanBtn.disabled = false;
      stopScanBtn.disabled  = true;
      showViewfinderIdle();
      setStatus('idle', 'SYSTEM IDLE');
      lastScannedUrl = '';
      showToast('Kamera dihentikan.', 'neutral');
    }).catch((err) => {
      console.error('Gagal menghentikan scanner:', err);
    });
  });

  /* ─────────────────────────────────────────────────────────────
     FILE UPLOAD SCANNER
  ───────────────────────────────────────────────────────────── */
  uploadZone.addEventListener('click', () => fileInput.click());

  fileInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file) return;
    scanImageFile(file);
  });

  uploadZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    uploadZone.classList.add('dragging');
  });

  uploadZone.addEventListener('dragleave', () => {
    uploadZone.classList.remove('dragging');
  });

  uploadZone.addEventListener('drop', (e) => {
    e.preventDefault();
    uploadZone.classList.remove('dragging');
    const file = e.dataTransfer.files[0];
    if (file && file.type.startsWith('image/')) {
      scanImageFile(file);
    } else {
      showToast('File harus berupa gambar (PNG, JPG, GIF, dll).', 'danger');
    }
  });

  function scanImageFile(file) {
    uploadContent.innerHTML = `
      <div class="upload-icon" style="animation: idlePulse 1s ease-in-out infinite;">↺</div>
      <p style="font-family:'JetBrains Mono',monospace; font-size:11px; color:rgba(168,168,179,0.6); letter-spacing:0.1em; margin-top:8px;">MEMPROSES GAMBAR...</p>
    `;
    setStatus('active', 'MEMINDAI GAMBAR...');

    const tempScanner = new Html5Qrcode('qr-reader-file-temp');

    // We need a hidden temp div for file scanning
    let tempDiv = document.getElementById('qr-reader-file-temp');
    if (!tempDiv) {
      tempDiv = document.createElement('div');
      tempDiv.id = 'qr-reader-file-temp';
      tempDiv.style.display = 'none';
      document.body.appendChild(tempDiv);
    }

    const fileScanner = new Html5Qrcode('qr-reader-file-temp');

    fileScanner.scanFile(file, true)
      .then((decodedText) => {
        processScanResult(decodedText);
        resetUploadZone();
      })
      .catch((err) => {
        console.warn('QR tidak terdeteksi dalam gambar:', err);
        showToast('Tidak ada QR Code yang terdeteksi dalam gambar ini.', 'danger');
        resetUploadZone();
        setStatus('idle', 'SYSTEM IDLE');
      });

    fileInput.value = '';
  }

  function resetUploadZone() {
    uploadContent.innerHTML = `
      <div class="upload-icon">↑</div>
      <p style="font-family:'JetBrains Mono',monospace; font-size:11px; color:rgba(168,168,179,0.5); letter-spacing:0.1em; margin-top:8px;">UPLOAD GAMBAR QR CODE</p>
      <p style="font-family:'Cormorant Garamond',serif; font-size:13px; color:rgba(168,168,179,0.3); font-style:italic; margin-top:4px;">Klik atau seret file ke sini</p>
    `;
  }

  /* ─────────────────────────────────────────────────────────────
     ANALYZE URL BUTTON (Show Live Preview)
  ───────────────────────────────────────────────────────────── */
  analyzeUrlBtn.addEventListener('click', () => {
    if (!lastScannedUrl) return;
    showLivePreview(lastScannedUrl);
  });

  function showLivePreview(url) {
    const fullUrl = url.startsWith('http') ? url : 'https://' + url;
    previewFrame.src = fullUrl;
    previewSection.style.display = 'block';
    previewSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    showToast('Preview dimuat dalam sandbox aman.', 'safe');
  }

  closePreviewBtn.addEventListener('click', () => {
    previewSection.style.display = 'none';
    previewFrame.src = 'about:blank';
  });

  /* ─────────────────────────────────────────────────────────────
     CLEAR RESULT BUTTON
  ───────────────────────────────────────────────────────────── */
  clearResultBtn.addEventListener('click', () => {
    resultArea.innerHTML = `
      <div style="text-align:center; padding:32px 0;">
        <div class="radar-ring">
          <div class="radar-sweep"></div>
          <div class="radar-dot"></div>
        </div>
        <p style="font-family:'JetBrains Mono',monospace; font-size:11px; color:rgba(168,168,179,0.4); letter-spacing:0.1em; margin-top:16px;">MENUNGGU DATA INPUT...</p>
      </div>
    `;
    rawUrlContainer.style.display = 'none';
    threatDetails.style.display   = 'none';
    actionButtons.style.display   = 'none';
    previewSection.style.display  = 'none';
    previewFrame.src = 'about:blank';
    lastScannedUrl = '';
    setStatus('idle', 'SYSTEM IDLE');
    showToast('Hasil direset.', 'neutral');
  });

  /* ─────────────────────────────────────────────────────────────
     MANUAL URL ANALYZER
  ───────────────────────────────────────────────────────────── */
  function runManualAnalysis() {
    const url = manualUrlInput.value.trim();
    if (!url) {
      showToast('Masukkan URL terlebih dahulu.', 'danger');
      return;
    }
    lastScannedUrl = url;
    processScanResult(url);
    manualUrlInput.value = '';
  }

  manualAnalyzeBtn.addEventListener('click', runManualAnalysis);

  manualUrlInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') runManualAnalysis();
  });

  /* ─────────────────────────────────────────────────────────────
     CLEAR HISTORY BUTTON
  ───────────────────────────────────────────────────────────── */
  clearHistoryBtn.addEventListener('click', () => {
    scanHistory = [];
    historyLog.innerHTML = `
      <div style="text-align:center; padding:24px 0;">
        <p style="font-family:'JetBrains Mono',monospace; font-size:11px; color:rgba(168,168,179,0.3); letter-spacing:0.1em;">BELUM ADA RIWAYAT SCAN</p>
      </div>
    `;
    showToast('Riwayat scan dihapus.', 'neutral');
  });

  /* ─────────────────────────────────────────────────────────────
     INITIAL STATE
  ───────────────────────────────────────────────────────────── */
  setStatus('idle', 'SYSTEM IDLE');
  showViewfinderIdle();

  // Log startup
  console.log('%c QR SENTINEL INITIALIZED ', 'background:#5a189a; color:#fff; font-family:monospace; font-size:12px; padding:4px 12px; border-radius:4px;');
  console.log('%c Cybersecurity QR Scanner v2.4.1 — Ready ', 'color:#9d4edd; font-family:monospace; font-size:11px;');

}); // END DOMContentLoaded
