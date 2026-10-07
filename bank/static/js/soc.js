// ShorlyNot SOC Live Radar & OpenWrt Archer C6 Router Guard Telemetry
// Interactive Cyber Threat Monitoring & Defense Simulation Console

document.addEventListener('DOMContentLoaded', () => {
  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // -------------------------------------------------------------------------
  // Telemetry DOM Elements
  // -------------------------------------------------------------------------
  const stageSElem = document.getElementById('soc-stage-s');
  const stageQElem = document.getElementById('soc-stage-q');
  const stageSDescElem = document.getElementById('soc-stage-s-desc');
  const stageQDescElem = document.getElementById('soc-stage-q-desc');
  const lastThreatElem = document.getElementById('soc-last-threat');
  const mismatchValElem = document.getElementById('soc-mismatch-val');
  const tauValElem = document.getElementById('soc-tau-val');
  const meterFillElem = document.getElementById('soc-meter-fill');
  const tauMarkerElem = document.getElementById('soc-tau-marker');
  const feedBodyElem = document.getElementById('soc-feed-body');

  const pforgeBadgeElem = document.getElementById('soc-pforge-badge');
  const tauParamValElem = document.getElementById('soc-tau-param-val');
  const socNValElem = document.getElementById('soc-n-val');
  const socDeltaValElem = document.getElementById('soc-delta-val');

  // Top Strip Elements
  const stripQkdDot = document.getElementById('soc-strip-qkd-dot');
  const stripQkdText = document.getElementById('soc-strip-qkd-text');
  const stripBoundText = document.getElementById('soc-strip-bound-text');
  const stripThreatPosture = document.getElementById('soc-strip-threat-posture');

  // OpenWrt Router Guard Elements
  const routerStatusDot = document.getElementById('router-status-dot');
  const routerModeBadge = document.getElementById('router-mode-badge');
  const routerQberVal = document.getElementById('router-qber-val');
  const routerKeyRateVal = document.getElementById('router-keyrate-val');
  const routerActionVal = document.getElementById('router-action-val');
  const routerQberFill = document.getElementById('router-qber-fill');
  const routerQberStatusText = document.getElementById('router-qber-status-text');
  const routerDropCounter = document.getElementById('router-drop-counter');
  const iptablesOutputElem = document.getElementById('iptables-terminal-output');
  const socRemoteStateElem = document.getElementById('soc-remote-state');

  // Posture Banners
  const activePostureElem = document.getElementById('soc-active-posture');
  const activeRouterStateElem = document.getElementById('soc-active-router-state');

  // Toast
  const toastElem = document.getElementById('soc-toast');

  let autoDemoActive = false;
  let currentRouterStatus = 'GREEN';
  let currentQber = 1.4;
  let currentKeyRate = 2420;
  let currentMismatch = 0.0;
  let currentTau = 0.2097;
  let currentN = 64;
  let currentDelta = 0.01;

  // -------------------------------------------------------------------------
  // Web Audio API Synthesizer (Sci-Fi Cyber Sound Effects)
  // -------------------------------------------------------------------------
  let audioContext = null;
  let audioEnabled = false;

  function initAudio() {
    if (!audioContext) {
      const AudioContextClass = window.AudioContext || window.webkitAudioContext;
      if (AudioContextClass) {
        audioContext = new AudioContextClass();
      }
    }
    if (audioContext && audioContext.state === 'suspended') {
      audioContext.resume();
    }
  }

  function playTone(freq, type = 'sine', duration = 0.15, gainVal = 0.08) {
    if (!audioEnabled || !audioContext) return;
    try {
      const osc = audioContext.createOscillator();
      const gain = audioContext.createGain();
      osc.type = type;
      osc.frequency.setValueAtTime(freq, audioContext.currentTime);
      gain.gain.setValueAtTime(gainVal, audioContext.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.0001, audioContext.currentTime + duration);
      osc.connect(gain);
      gain.connect(audioContext.destination);
      osc.start();
      osc.stop(audioContext.currentTime + duration);
    } catch (e) {
      console.debug('Audio playback error', e);
    }
  }

  function playClickSound() {
    playTone(880, 'triangle', 0.04, 0.04);
  }

  function playShieldChime() {
    if (!audioEnabled) return;
    playTone(523.25, 'sine', 0.2, 0.06); // C5
    setTimeout(() => playTone(659.25, 'sine', 0.25, 0.06), 80); // E5
    setTimeout(() => playTone(783.99, 'sine', 0.35, 0.07), 160); // G5
  }

  function playAlertSiren() {
    if (!audioEnabled || !audioContext) return;
    try {
      const osc = audioContext.createOscillator();
      const gain = audioContext.createGain();
      osc.type = 'sawtooth';
      osc.frequency.setValueAtTime(440, audioContext.currentTime);
      osc.frequency.linearRampToValueAtTime(880, audioContext.currentTime + 0.18);
      gain.gain.setValueAtTime(0.08, audioContext.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, audioContext.currentTime + 0.22);
      osc.connect(gain);
      gain.connect(audioContext.destination);
      osc.start();
      osc.stop(audioContext.currentTime + 0.22);
    } catch (e) {
      console.debug(e);
    }
  }

  const audioToggleBtn = document.getElementById('btn-audio-toggle');
  const audioIcon = document.getElementById('audio-icon');
  const audioText = document.getElementById('audio-text');

  if (audioToggleBtn) {
    audioToggleBtn.addEventListener('click', () => {
      initAudio();
      audioEnabled = !audioEnabled;
      if (audioEnabled) {
        audioIcon.textContent = '🔊';
        audioText.textContent = 'AUDIO: ON';
        audioToggleBtn.style.borderColor = 'var(--soc-accent)';
        audioToggleBtn.style.color = 'var(--soc-accent)';
        showToast('Cyber Sound FX Enabled');
        playShieldChime();
      } else {
        audioIcon.textContent = '🔇';
        audioText.textContent = 'AUDIO: OFF';
        audioToggleBtn.style.borderColor = '';
        audioToggleBtn.style.color = '';
        showToast('Audio Muted');
      }
    });
  }

  // -------------------------------------------------------------------------
  // Toast Helper
  // -------------------------------------------------------------------------
  let toastTimeout = null;
  function showToast(message) {
    if (!toastElem) return;
    toastElem.textContent = message;
    toastElem.classList.remove('hidden');
    if (toastTimeout) clearTimeout(toastTimeout);
    toastTimeout = setTimeout(() => {
      toastElem.classList.add('hidden');
    }, 2800);
  }

  // -------------------------------------------------------------------------
  // Real-Time Oscilloscope Waveform (Canvas)
  // -------------------------------------------------------------------------
  const oscCanvas = document.getElementById('soc-oscilloscope');
  const oscCtx = oscCanvas ? oscCanvas.getContext('2d') : null;
  const oscHistory = [];
  const maxHistoryPoints = 60;

  for (let i = 0; i < maxHistoryPoints; i++) {
    oscHistory.push({ qber: 1.4, mismatch: 0.0, tau: 0.2097 });
  }

  function renderOscilloscope() {
    if (!oscCanvas || !oscCtx) return;
    const w = oscCanvas.width;
    const h = oscCanvas.height;

    // Clear
    oscCtx.fillStyle = '#050811';
    oscCtx.fillRect(0, 0, w, h);

    // Draw grid
    oscCtx.strokeStyle = 'rgba(30, 41, 59, 0.45)';
    oscCtx.lineWidth = 1;
    for (let x = 0; x < w; x += 40) {
      oscCtx.beginPath();
      oscCtx.moveTo(x, 0);
      oscCtx.lineTo(x, h);
      oscCtx.stroke();
    }
    for (let y = 0; y < h; y += 25) {
      oscCtx.beginPath();
      oscCtx.moveTo(0, y);
      oscCtx.lineTo(w, y);
      oscCtx.stroke();
    }

    // Cutoff Threshold Line at 11% (relative to 22% max scale)
    const cutoffY = h - (11.0 / 22.0) * h;
    oscCtx.strokeStyle = 'rgba(255, 0, 85, 0.4)';
    oscCtx.setLineDash([4, 4]);
    oscCtx.beginPath();
    oscCtx.moveTo(0, cutoffY);
    oscCtx.lineTo(w, cutoffY);
    oscCtx.stroke();
    oscCtx.setLineDash([]);

    // Warning Line at 4%
    const warnY = h - (4.0 / 22.0) * h;
    oscCtx.strokeStyle = 'rgba(245, 158, 11, 0.3)';
    oscCtx.setLineDash([2, 4]);
    oscCtx.beginPath();
    oscCtx.moveTo(0, warnY);
    oscCtx.lineTo(w, warnY);
    oscCtx.stroke();
    oscCtx.setLineDash([]);

    const stepX = w / (maxHistoryPoints - 1);

    // 1. Draw Mismatch Rate Curve (cyan)
    oscCtx.strokeStyle = '#38bdf8';
    oscCtx.lineWidth = 2;
    oscCtx.beginPath();
    for (let i = 0; i < oscHistory.length; i++) {
      const x = i * stepX;
      // scale mismatch from 0 to 0.60
      const normMismatch = Math.min(1.0, oscHistory[i].mismatch / 0.60);
      const y = h - (normMismatch * (h - 10)) - 5;
      if (i === 0) oscCtx.moveTo(x, y);
      else oscCtx.lineTo(x, y);
    }
    oscCtx.stroke();

    // 2. Draw QBER Curve (green if clean, yellow if drift, red if attack)
    const lastQber = oscHistory[oscHistory.length - 1].qber;
    let strokeCol = '#34d399';
    if (lastQber >= 11.0) strokeCol = '#ef4444';
    else if (lastQber >= 4.0) strokeCol = '#fbbf24';

    oscCtx.strokeStyle = strokeCol;
    oscCtx.lineWidth = 2.5;
    oscCtx.shadowColor = strokeCol;
    oscCtx.shadowBlur = 8;
    oscCtx.beginPath();
    for (let i = 0; i < oscHistory.length; i++) {
      const x = i * stepX;
      const normQber = Math.min(1.0, oscHistory[i].qber / 22.0);
      const y = h - (normQber * (h - 10)) - 5;
      if (i === 0) oscCtx.moveTo(x, y);
      else oscCtx.lineTo(x, y);
    }
    oscCtx.stroke();
    oscCtx.shadowBlur = 0;
  }

  function pushOscData(qber, mismatch, tau) {
    oscHistory.shift();
    // Add tiny realistic jitter for alive look
    const jitter = (Math.random() - 0.5) * 0.08;
    oscHistory.push({
      qber: Math.max(0.1, qber + jitter),
      mismatch: Math.max(0.0, mismatch),
      tau: tau
    });
    renderOscilloscope();
  }

  // -------------------------------------------------------------------------
  // Interactive Topology Radar SVG
  // -------------------------------------------------------------------------
  const linkRouterKms = document.getElementById('link-router-kms');
  const packet2 = document.getElementById('packet-2');
  const nodeEveCircle = document.getElementById('node-eve-circle');
  const linkEveQkd = document.getElementById('link-eve-qkd');
  const nodeRouterCircle = document.getElementById('node-router-circle');
  const topoInspector = document.getElementById('topo-inspector');
  const inspectorTitle = document.getElementById('inspector-title');
  const inspectorBody = document.getElementById('inspector-body');

  function updateTopologyState(status, qber) {
    if (!linkRouterKms) return;
    if (status === 'RED') {
      linkRouterKms.setAttribute('class', 'topo-link topo-link-red');
      if (packet2) packet2.setAttribute('class', 'packet packet-red');
      if (nodeEveCircle) {
        nodeEveCircle.style.stroke = '#ef4444';
        nodeEveCircle.style.filter = 'drop-shadow(0 0 12px #ef4444)';
      }
      if (linkEveQkd) linkEveQkd.classList.add('active');
      if (nodeRouterCircle) {
        nodeRouterCircle.style.stroke = '#ef4444';
        nodeRouterCircle.style.filter = 'drop-shadow(0 0 10px #ef4444)';
      }
    } else if (status === 'YELLOW') {
      linkRouterKms.setAttribute('class', 'topo-link topo-link-yellow');
      if (packet2) packet2.setAttribute('class', 'packet packet-green');
      if (linkEveQkd) linkEveQkd.classList.remove('active');
      if (nodeRouterCircle) {
        nodeRouterCircle.style.stroke = '#f59e0b';
        nodeRouterCircle.style.filter = 'drop-shadow(0 0 8px #f59e0b)';
      }
    } else {
      linkRouterKms.setAttribute('class', 'topo-link topo-link-green');
      if (packet2) packet2.setAttribute('class', 'packet packet-green');
      if (linkEveQkd) linkEveQkd.classList.remove('active');
      if (nodeEveCircle) {
        nodeEveCircle.style.stroke = '';
        nodeEveCircle.style.filter = '';
      }
      if (nodeRouterCircle) {
        nodeRouterCircle.style.stroke = '#10b981';
        nodeRouterCircle.style.filter = 'drop-shadow(0 0 8px #10b981)';
      }
    }
  }

  // Node Click Handlers for Live Inspection
  const topoNodes = {
    'node-alice': {
      title: '🖥️ Alice (Client Node)',
      desc: 'IP: 192.168.1.100<br>Role: Quantum Signer (Profile T1)<br>Key Pair: alice-key-1 (Kyber/Dilithium + QDS)<br>Status: Connected'
    },
    'node-router': {
      title: '🛡️ OpenWrt Archer C6 Guard',
      desc: () => `IP: 192.168.1.1<br>Firewall: fw4 (nftables)<br>State: <strong>${currentRouterStatus}</strong><br>Relay Port 8765: ${currentRouterStatus === 'RED' ? '<span style="color:#ef4444">DROPPING</span>' : '<span style="color:#34d399">FORWARDING</span>'}`
    },
    'node-kms': {
      title: '⚛️ QKD Key Management Server',
      desc: () => `URL: http://192.168.1.2:8000<br>Status: <strong>${currentRouterStatus}</strong><br>Current QBER: ${currentQber.toFixed(1)}%<br>Key Gen Rate: ${currentKeyRate.toLocaleString()} bps`
    },
    'node-bank': {
      title: '🏦 ShorlyNot Bank Core Ledger',
      desc: 'Port: 8081 (FastAPI)<br>Double-entry quantum ledger<br>Enforces Stage S0 - S4 locks'
    },
    'node-eve': {
      title: '🕵️ Eve (Quantum Eavesdropper)',
      desc: () => `Threat State: ${currentRouterStatus === 'RED' ? '<span style="color:#ef4444">ACTIVE INTERCEPTION</span>' : 'Passive Monitoring'}<br>Detection Bound: BB84 QBER ≥ 11.0%`
    }
  };

  Object.keys(topoNodes).forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;
    el.addEventListener('click', (ev) => {
      ev.stopPropagation();
      playClickSound();
      const nodeInfo = topoNodes[id];
      inspectorTitle.textContent = nodeInfo.title;
      inspectorBody.innerHTML = typeof nodeInfo.desc === 'function' ? nodeInfo.desc() : nodeInfo.desc;
      topoInspector.classList.remove('hidden');
    });
  });

  document.addEventListener('click', (ev) => {
    if (topoInspector && !topoInspector.contains(ev.target)) {
      topoInspector.classList.add('hidden');
    }
  });

  // -------------------------------------------------------------------------
  // Syntax Highlight Helper
  // -------------------------------------------------------------------------
  function highlightNftables(raw) {
    if (!raw) return '';
    return raw
      .replace(/(#.*$)/gm, '<span class="term-dim">$1</span>')
      .replace(/\b(table|chain|type|hook|priority|policy|accept|drop|log|comment)\b/g, '<span class="term-cyan">$1</span>')
      .replace(/\b(inet|fw4|forward|router_guard_forward)\b/g, '<span class="term-bold">$1</span>')
      .replace(/\b(drop)\b/g, '<span class="term-red">$1</span>')
      .replace(/\b(accept)\b/g, '<span class="term-green">$1</span>')
      .replace(/\b(GREEN)\b/g, '<span class="term-green">$1</span>')
      .replace(/\b(YELLOW)\b/g, '<span class="term-yellow">$1</span>')
      .replace(/\b(RED)\b/g, '<span class="term-red">$1</span>');
  }

  // -------------------------------------------------------------------------
  // Fetch OpenWrt Router Telemetry
  // -------------------------------------------------------------------------
  async function fetchRouterTelemetry() {
    try {
      const res = await fetch('/api/router/status');
      if (!res.ok) return;
      const data = await res.json();

      const status = data.status || 'GREEN';
      const qber = typeof data.qber === 'number' ? data.qber : 1.4;
      const keyRate = data.key_rate || 2420;
      const drops = data.dropped_packets || 0;
      const action = data.router_action || 'ALLOW';

      currentRouterStatus = status;
      currentQber = qber;
      currentKeyRate = keyRate;
      autoDemoActive = !!data.auto_demo;

      // Update QBER & Key Rate
      if (routerQberVal) routerQberVal.textContent = `${qber.toFixed(1)}%`;
      if (routerKeyRateVal) routerKeyRateVal.textContent = `${keyRate.toLocaleString()} bps`;
      if (routerActionVal) routerActionVal.textContent = action;
      if (routerDropCounter) routerDropCounter.textContent = `DROPPED RELAY PKTS: ${drops}`;

      // Update QBER Bar visualizer (scale to 22% max)
      const qberPct = Math.min(100, Math.max(4, (qber / 22.0) * 100));
      if (routerQberFill) {
        routerQberFill.style.width = `${qberPct}%`;
        routerQberFill.className = `qber-fill state-${status}`;
      }

      // Sync tactile slider readout without overriding user dragging
      const sliderReadout = document.getElementById('slider-readout');
      if (sliderReadout && !document.getElementById('qber-tactile-slider')?.matches(':active')) {
        sliderReadout.innerHTML = `Current Physical Link QBER: <strong>${qber.toFixed(1)}%</strong>`;
        const tactileSlider = document.getElementById('qber-tactile-slider');
        if (tactileSlider && Math.abs(parseFloat(tactileSlider.value) - qber) > 1.0) {
          tactileSlider.value = qber;
        }
      }

      // Update Status Pills & Badges
      const remoteState = data.physical_router_state || status;
      if (socRemoteStateElem) {
        socRemoteStateElem.textContent = remoteState;
      }

      if (status === 'GREEN') {
        if (routerStatusDot) routerStatusDot.style.backgroundColor = 'var(--soc-green)';
        if (routerModeBadge) {
          routerModeBadge.innerHTML = `STATUS: GREEN (${data.physical_router_ip || '192.168.1.1'}: ${remoteState})`;
          routerModeBadge.style.color = 'var(--soc-green)';
          routerModeBadge.style.borderColor = 'rgba(16, 185, 129, 0.4)';
          routerModeBadge.style.background = 'rgba(16, 185, 129, 0.15)';
        }
        if (socRemoteStateElem) socRemoteStateElem.style.color = '#34d399';
        if (routerQberVal) routerQberVal.style.color = '#34d399';
        if (routerActionVal) routerActionVal.style.color = '#34d399';
        if (routerQberStatusText) {
          routerQberStatusText.textContent = 'CHANNEL CLEAN (< 4.0%)';
          routerQberStatusText.style.color = '#34d399';
        }
        if (stripQkdDot) stripQkdDot.style.backgroundColor = 'var(--soc-green)';
        if (stripQkdText) {
          stripQkdText.textContent = `GREEN (${qber.toFixed(1)}% QBER)`;
          stripQkdText.style.color = '#34d399';
        }
      } else if (status === 'YELLOW') {
        if (routerStatusDot) routerStatusDot.style.backgroundColor = 'var(--soc-yellow)';
        if (routerModeBadge) {
          routerModeBadge.innerHTML = `STATUS: YELLOW (${data.physical_router_ip || '192.168.1.1'}: ${remoteState})`;
          routerModeBadge.style.color = 'var(--soc-yellow)';
          routerModeBadge.style.borderColor = 'rgba(245, 158, 11, 0.4)';
          routerModeBadge.style.background = 'rgba(245, 158, 11, 0.15)';
        }
        if (socRemoteStateElem) socRemoteStateElem.style.color = '#fbbf24';
        if (routerQberVal) routerQberVal.style.color = '#fbbf24';
        if (routerActionVal) routerActionVal.style.color = '#fbbf24';
        if (routerQberStatusText) {
          routerQberStatusText.textContent = 'OPTICAL NOISE DRIFT (4 - 11%)';
          routerQberStatusText.style.color = '#fbbf24';
        }
        if (stripQkdDot) stripQkdDot.style.backgroundColor = 'var(--soc-yellow)';
        if (stripQkdText) {
          stripQkdText.textContent = `YELLOW (${qber.toFixed(1)}% QBER)`;
          stripQkdText.style.color = '#fbbf24';
        }
      } else { // RED
        if (routerStatusDot) routerStatusDot.style.backgroundColor = 'var(--soc-red)';
        if (routerModeBadge) {
          routerModeBadge.innerHTML = `STATUS: RED (${data.physical_router_ip || '192.168.1.1'}: ${remoteState})`;
          routerModeBadge.style.color = 'var(--soc-red)';
          routerModeBadge.style.borderColor = 'rgba(239, 68, 68, 0.4)';
          routerModeBadge.style.background = 'rgba(239, 68, 68, 0.15)';
        }
        if (socRemoteStateElem) socRemoteStateElem.style.color = '#f87171';
        if (routerQberVal) routerQberVal.style.color = '#f87171';
        if (routerActionVal) routerActionVal.style.color = '#f87171';
        if (routerQberStatusText) {
          routerQberStatusText.textContent = 'EAVESDROPPER INTERCEPTED (≥ 11.0%)';
          routerQberStatusText.style.color = '#f87171';
        }
        if (stripQkdDot) stripQkdDot.style.backgroundColor = 'var(--soc-red)';
        if (stripQkdText) {
          stripQkdText.textContent = `RED (${qber.toFixed(1)}% QBER - BLOCKED)`;
          stripQkdText.style.color = '#f87171';
        }
      }

      // Update Terminal Body with syntax highlighted nftables
      if (iptablesOutputElem && data.nftables_output) {
        iptablesOutputElem.innerHTML = highlightNftables(data.nftables_output);
      }

      // Update Topology SVG colors
      updateTopologyState(status, qber);

      // Push to Oscilloscope
      pushOscData(qber, currentMismatch, currentTau);

      // Auto Demo Button state
      const cycleBtn = document.getElementById('btn-router-cycle-demo');
      if (cycleBtn) {
        if (autoDemoActive) {
          cycleBtn.textContent = 'STOP DEMO';
          cycleBtn.style.background = 'rgba(239, 68, 68, 0.3)';
          cycleBtn.style.color = '#f87171';
        } else {
          cycleBtn.textContent = 'AUTO DEMO';
          cycleBtn.style.background = '';
          cycleBtn.style.color = '';
        }
      }
    } catch (err) {
      console.debug('Error polling router status:', err);
    }
  }

  // -------------------------------------------------------------------------
  // Fetch Skeleton Security Stage Feed & Threat Stream
  // -------------------------------------------------------------------------
  async function fetchSocFeed() {
    try {
      const res = await fetch('/api/soc/feed');
      if (!res.ok) return;
      const data = await res.json();

      const s = data.stages.stage_s;
      const q = data.stages.stage_q;
      
      stageSElem.textContent = `S${s}`;
      stageSElem.className = `stage-value stage-s${s}`;

      const sDescriptions = {
        0: 'Normal · All Services Operational',
        1: 'Anomaly Warning · Transfers Allowed',
        2: 'Active Threat · Transfers Blocked',
        3: 'Pattern Attack · Read-Only Mode',
        4: 'CRITICAL LOCKDOWN · Bank Locked'
      };
      stageSDescElem.textContent = sDescriptions[s] || 'Unknown';

      stageQElem.textContent = `Q${q}`;
      const qDescriptions = {
        0: 'QBER < 5% (Optimal Link)',
        1: 'QBER 5-8% (Watch)',
        2: 'QBER 8-11% (Elevated Noise)',
        3: 'QBER 11-20% (Compromised)',
        4: 'QBER >= 20% (Eve Interception)'
      };
      stageQDescElem.textContent = qDescriptions[q] || 'Link Active';

      // Update Mismatch and Tau
      const mismatch = data.stages.last_mismatch || 0.0;
      const tau = data.stages.tau || 0.2097;
      currentMismatch = mismatch;
      currentTau = tau;

      mismatchValElem.textContent = mismatch.toFixed(4);
      tauValElem.textContent = tau.toFixed(4);
      if (tauParamValElem) tauParamValElem.textContent = tau.toFixed(4);
      if (stripBoundText) stripBoundText.textContent = `Hoeffding Bound (τ=${tau.toFixed(4)})`;

      if (stripThreatPosture) {
        if (s >= 4 || currentRouterStatus === 'RED') {
          stripThreatPosture.textContent = `CRITICAL LOCKDOWN (S${s})`;
          stripThreatPosture.style.color = '#ef4444';
        } else if (s > 0 || currentRouterStatus === 'YELLOW') {
          stripThreatPosture.textContent = `THREAT ELEVATED (S${s})`;
          stripThreatPosture.style.color = '#fbbf24';
        } else {
          stripThreatPosture.textContent = `DEFENSES ACTIVE (S0)`;
          stripThreatPosture.style.color = '#34d399';
        }
      }

      // Meter fill (scale to 0.60 max)
      const fillPct = Math.min(100, Math.max(2, (mismatch / 0.60) * 100));
      const tauPct = Math.min(100, Math.max(5, (tau / 0.60) * 100));

      meterFillElem.style.width = `${fillPct}%`;
      if (mismatch > tau) {
        meterFillElem.classList.add('danger');
      } else {
        meterFillElem.classList.remove('danger');
      }
      tauMarkerElem.style.left = `${tauPct}%`;

      // Threat Tag
      const threat = data.stages.last_threat || 'OK';
      lastThreatElem.textContent = threat;
      lastThreatElem.className = `soc-tag tag-${threat.toLowerCase().replace('_', '-')}`;

      // Update Feed Table with Filter Support
      renderFilteredFeed(data.events || []);

    } catch (err) {
      console.error('Error polling SOC feed:', err);
    }
  }

  // -------------------------------------------------------------------------
  // Event Filter & Interactive Search
  // -------------------------------------------------------------------------
  let activeFilterTag = 'ALL';
  let activeSearchQuery = '';
  let cachedEvents = [];

  const searchInput = document.getElementById('feed-search-input');
  const filterButtons = document.querySelectorAll('.filter-tag');

  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      activeSearchQuery = e.target.value.toLowerCase().trim();
      renderFilteredFeed(cachedEvents);
    });
  }

  filterButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      playClickSound();
      filterButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      activeFilterTag = btn.getAttribute('data-filter');
      renderFilteredFeed(cachedEvents);
    });
  });

  function renderFilteredFeed(events) {
    cachedEvents = events;
    if (!feedBodyElem) return;

    let filtered = events.filter(e => {
      const matchTag = (activeFilterTag === 'ALL')
        || (activeFilterTag === 'THREATS' && e.threat_label !== 'OK')
        || (activeFilterTag === 'HARDWARE' && (e.threat_label.includes('ROUTER') || (e.details && (e.details.toLowerCase().includes('router') || e.details.toLowerCase().includes('hardware') || e.details.toLowerCase().includes('archer')))))
        || (e.threat_label.toUpperCase().includes(activeFilterTag));
      
      const textToMatch = `${e.threat_label} ${e.actor} ${e.details}`.toLowerCase();
      const matchSearch = !activeSearchQuery || textToMatch.includes(activeSearchQuery);
      return matchTag && matchSearch;
    });

    if (filtered.length === 0) {
      feedBodyElem.innerHTML = `<tr><td colspan="7" style="text-align:center; color:#64748b; padding:1.5rem;">No matching event records in stream.</td></tr>`;
      return;
    }

    feedBodyElem.innerHTML = filtered.map(e => {
      const isThreat = (e.threat_label !== 'OK');
      const rowClass = isThreat ? 'feed-row-threat clickable-event' : 'clickable-event';
      const tagClass = `tag-${e.threat_label.toLowerCase().replace('_', '-')}`;
      const timeShort = e.timestamp.split('T')[1].substring(0, 8);
      return `
        <tr class="${rowClass}" data-event='${escapeHtml(JSON.stringify(e))}'>
          <td>${escapeHtml(timeShort)}</td>
          <td><span class="soc-tag ${tagClass}">${escapeHtml(e.threat_label)}</span></td>
          <td>S${e.stage_s} / Q${e.stage_q}</td>
          <td>${e.mismatch_rate.toFixed(4)}</td>
          <td>${e.tau.toFixed(4)}</td>
          <td>${escapeHtml(e.actor || 'system')}</td>
          <td><button type="button" class="btn-inspect-event">🔍 Inspect</button></td>
        </tr>
      `;
    }).join('');

    // Attach click listeners for Inspect
    feedBodyElem.querySelectorAll('.clickable-event').forEach(row => {
      row.addEventListener('click', () => {
        playClickSound();
        const rawJson = row.getAttribute('data-event');
        if (rawJson) {
          try {
            openForensicModal(JSON.parse(rawJson));
          } catch (err) {
            console.error(err);
          }
        }
      });
    });
  }

  // -------------------------------------------------------------------------
  // Forensic Modal
  // -------------------------------------------------------------------------
  const forensicModal = document.getElementById('forensic-modal');
  const modalContent = document.getElementById('modal-content');
  const modalCloseBtn = document.getElementById('modal-close-btn');
  const modalDismissBtn = document.getElementById('btn-modal-dismiss');
  const copyForensicJsonBtn = document.getElementById('btn-copy-forensic-json');
  let activeEventForModal = null;

  function openForensicModal(ev) {
    activeEventForModal = ev;
    const isThreat = ev.threat_label !== 'OK';
    modalContent.innerHTML = `
      <div style="margin-bottom:0.75rem;">
        <span style="font-size:0.7rem; color:var(--soc-text-dim); text-transform:uppercase;">INCIDENT VERDICT:</span><br>
        <strong style="font-size:1.1rem; color:${isThreat ? '#f87171' : '#34d399'};">${escapeHtml(ev.threat_label)}</strong>
      </div>
      <table class="params-table" style="margin-bottom:1rem;">
        <tr><td>Timestamp</td><td>${escapeHtml(ev.timestamp)}</td></tr>
        <tr><td>Actor / Target</td><td>${escapeHtml(ev.actor || 'system')}</td></tr>
        <tr><td>Cryptographic Stage</td><td>Stage S${ev.stage_s} (QKD Link Q${ev.stage_q})</td></tr>
        <tr><td>Observed Mismatch Rate (p̂)</td><td style="color:${ev.mismatch_rate > ev.tau ? '#ff0055' : '#38bdf8'}">${ev.mismatch_rate.toFixed(4)}</td></tr>
        <tr><td>Hoeffding Bound (τ)</td><td>${ev.tau.toFixed(4)}</td></tr>
        <tr><td>Security Margin (p̂ - τ)</td><td style="color:${ev.mismatch_rate > ev.tau ? '#ff0055' : '#34d399'}">${(ev.mismatch_rate - ev.tau).toFixed(4)}</td></tr>
      </table>
      <div style="background:#090e1a; padding:0.75rem; border-radius:6px; border:1px solid #1e293b; margin-bottom:0.75rem;">
        <div style="font-size:0.7rem; color:var(--soc-text-dim); margin-bottom:0.25rem;">EVENT DETAILS & MITIGATION:</div>
        <div>${escapeHtml(ev.details || '')}</div>
      </div>
      <div style="font-size:0.72rem; color:#94a3b8;">
        Hardware Netfilter Action: <strong>${ev.stage_s >= 2 || isThreat ? 'Port 8765 Severed (DROP Active)' : 'Normal Packet Forwarding (ACCEPT)'}</strong>
      </div>
    `;
    forensicModal.classList.remove('hidden');
  }

  function closeForensicModal() {
    forensicModal.classList.add('hidden');
  }

  if (modalCloseBtn) modalCloseBtn.addEventListener('click', closeForensicModal);
  if (modalDismissBtn) modalDismissBtn.addEventListener('click', closeForensicModal);
  if (copyForensicJsonBtn) {
    copyForensicJsonBtn.addEventListener('click', () => {
      if (activeEventForModal) {
        navigator.clipboard.writeText(JSON.stringify(activeEventForModal, null, 2));
        showToast('Forensic Report Copied to Clipboard!');
      }
    });
  }

  // -------------------------------------------------------------------------
  // Interactive Tactile QBER Slider
  // -------------------------------------------------------------------------
  const qberSlider = document.getElementById('qber-tactile-slider');
  const sliderReadout = document.getElementById('slider-readout');

  if (qberSlider) {
    qberSlider.addEventListener('input', async (e) => {
      const val = parseFloat(e.target.value);
      let statusStr = 'Clean Link (< 4%)';
      if (val >= 11.0) statusStr = '⚠️ BB84 Eavesdropper Cutoff (≥ 11%)';
      else if (val >= 4.0) statusStr = '⚡ Optical Drift (4 - 11%)';

      sliderReadout.innerHTML = `Injecting: <strong>${val.toFixed(1)}% QBER</strong> — ${statusStr}`;

      try {
        await fetch('/api/router/set_qber', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ qber: val })
        });
        if (val >= 11.0) playAlertSiren();
        await fetchRouterTelemetry();
      } catch (err) {
        console.debug(err);
      }
    });
  }

  // -------------------------------------------------------------------------
  // Interactive Parameter Sandbox (Qubits n & False-Reject delta)
  // -------------------------------------------------------------------------
  const btnGroupN = document.querySelectorAll('#btn-group-n .btn-param');
  const btnGroupDelta = document.querySelectorAll('#btn-group-delta .btn-param');

  async function updateBoundSandbox() {
    try {
      const res = await fetch(`/api/soc/recalc_bound?n=${currentN}&delta=${currentDelta}`);
      if (!res.ok) return;
      const data = await res.json();

      currentTau = data.tau;
      if (tauValElem) tauValElem.textContent = data.tau.toFixed(4);
      if (tauParamValElem) tauParamValElem.textContent = data.tau.toFixed(4);
      if (socNValElem) socNValElem.textContent = `${currentN} Qubits`;
      if (socDeltaValElem) socDeltaValElem.textContent = `${((1 - currentDelta) * 100).toFixed(1)}% (δ = ${currentDelta})`;
      if (pforgeBadgeElem) pforgeBadgeElem.innerHTML = `P_forge: ${data.p_forge_str}`;

      const tauPct = Math.min(100, Math.max(5, (data.tau / 0.60) * 100));
      if (tauMarkerElem) tauMarkerElem.style.left = `${tauPct}%`;

      showToast(`Hoeffding Bound recalculated: τ=${data.tau.toFixed(4)} (P_forge=${data.p_forge_str})`);
    } catch (err) {
      console.error(err);
    }
  }

  btnGroupN.forEach(btn => {
    btn.addEventListener('click', () => {
      playClickSound();
      btnGroupN.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentN = parseInt(btn.getAttribute('data-n'));
      updateBoundSandbox();
    });
  });

  btnGroupDelta.forEach(btn => {
    btn.addEventListener('click', () => {
      playClickSound();
      btnGroupDelta.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentDelta = parseFloat(btn.getAttribute('data-delta'));
      updateBoundSandbox();
    });
  });

  // -------------------------------------------------------------------------
  // In-SOC Flight Simulator ("FIRE TEST TRANSACTION")
  // -------------------------------------------------------------------------
  const fireSimBtn = document.getElementById('btn-sim-fire-transfer');
  const simResultBox = document.getElementById('sim-flight-result');
  const simResultHeader = document.getElementById('sim-result-header');
  const simResultDetails = document.getElementById('sim-result-details');
  const simAmountInput = document.getElementById('sim-transfer-amount');
  const simRecipientInput = document.getElementById('sim-transfer-recipient');

  if (fireSimBtn) {
    fireSimBtn.addEventListener('click', async () => {
      playClickSound();
      fireSimBtn.textContent = 'PROBING NETWORK...';
      const amount = parseFloat(simAmountInput?.value || '500');
      const recipient = simRecipientInput?.value?.trim() || 'bob';

      try {
        const resp = await fetch('/api/soc/test_transfer', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ amount: amount, to_user: recipient })
        });
        const result = await resp.json();

        simResultBox.classList.remove('hidden', 'pass', 'drop');

        if (result.success) {
          playShieldChime();
          simResultBox.classList.add('pass');
          simResultHeader.textContent = '🟢 TRANSACTION ACCEPTED & QUANTUM-COMMITTED';
          simResultDetails.innerHTML = `
            <strong>Tx ID:</strong> ${escapeHtml(result.tx_id)}<br>
            <strong>Status:</strong> Quantum signature verified (Profile T1). Mismatch p̂=${result.mismatch_rate.toFixed(4)} &lt; τ=${result.tau.toFixed(4)}.<br>
            <strong>Router Netfilter:</strong> Forwarding allowed on Port 8765 (Channel GREEN). ₹${escapeHtml(amount)} transferred to ${escapeHtml(recipient)}.
          `;
          showToast(`Test Transaction Passed: ₹${amount} to ${recipient}`);
        } else {
          playAlertSiren();
          simResultBox.classList.add('drop');
          simResultHeader.textContent = '🔴 TRANSACTION BLOCKED BY HARDWARE/CRYPTOGRAPHIC DEFENSE';
          simResultDetails.innerHTML = `
            <strong>Blocked By:</strong> ${escapeHtml(result.blocked_by || 'POLICY')}<br>
            <strong>Reason:</strong> ${escapeHtml(result.reason)}<br>
            <strong>Action:</strong> ${escapeHtml(result.action)} on Port 8765 | Router Status: <span style="color:#ef4444">${escapeHtml(result.router_status)}</span>
          `;
          showToast('Test Transaction Blocked!');
        }
        await fetchSocFeed();
        await fetchRouterTelemetry();
      } catch (err) {
        console.error(err);
      } finally {
        fireSimBtn.textContent = '⚡ FIRE TEST TRANSACTION';
      }
    });
  }

  // -------------------------------------------------------------------------
  // Terminal Quick Queries & Copy SSH
  // -------------------------------------------------------------------------
  document.querySelectorAll('.btn-term-cmd').forEach(btn => {
    btn.addEventListener('click', async () => {
      const cmd = btn.getAttribute('data-cmd');
      if (cmd) {
        playClickSound();
        try {
          const res = await fetch('/api/router/cmd', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ command: cmd })
          });
          const data = await res.json();
          if (iptablesOutputElem) {
            iptablesOutputElem.innerHTML = highlightNftables(data.output);
          }
          showToast(`Executed: ${data.command}`);
        } catch (err) {
          console.error(err);
        }
      }
    });
  });

  const copySshBtn = document.getElementById('btn-copy-ssh');
  if (copySshBtn) {
    copySshBtn.addEventListener('click', () => {
      navigator.clipboard.writeText('ssh root@192.168.1.1');
      showToast('Copied: ssh root@192.168.1.1');
      playClickSound();
    });
  }

  // -------------------------------------------------------------------------
  // Interactive Attack Weapons & Threat Dossier
  // -------------------------------------------------------------------------
  const dossierTitle = document.getElementById('dossier-title');
  const dossierDesc = document.getElementById('dossier-desc');
  const dossierLayer = document.getElementById('dossier-layer');

  const attackButtons = document.querySelectorAll('.btn-attack');
  attackButtons.forEach(btn => {
    // Hover to update Threat Dossier
    btn.addEventListener('mouseenter', () => {
      if (dossierTitle) dossierTitle.textContent = btn.getAttribute('data-title');
      if (dossierDesc) dossierDesc.textContent = btn.getAttribute('data-desc');
      if (dossierLayer) dossierLayer.textContent = btn.getAttribute('data-layer');
    });

    btn.addEventListener('click', async () => {
      playAlertSiren();
      attackButtons.forEach(b => b.classList.remove('active-weapon'));
      btn.classList.add('active-weapon');

      const atkType = btn.getAttribute('data-attack');
      const originalHtml = btn.innerHTML;
      btn.innerHTML = `Injecting ${atkType.toUpperCase()}...`;
      
      // Update posture banner immediately
      if (activePostureElem) {
        activePostureElem.textContent = `THREAT DETECTED: ${atkType.toUpperCase()} (RED)`;
        activePostureElem.style.color = '#f87171';
      }
      if (activeRouterStateElem) {
        activeRouterStateElem.textContent = 'RELAY SEVERED (RED)';
        activeRouterStateElem.style.color = '#f87171';
      }

      try {
        const resp = await fetch(`/soc/attack/${atkType}`, { method: 'POST' });
        if (resp.status === 401) {
          alert('Operator authentication required. Please log in with ops / ops123.');
        }

        // Also directly tell the router KMS to turn RED immediately
        await fetch('/api/router/set_state', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ state: 'RED' })
        });

        showToast(`Attack Injected: ${atkType.toUpperCase()} (Router Turned RED)`);
        await fetchSocFeed();
        await fetchRouterTelemetry();
      } catch (err) {
        console.error(err);
      } finally {
        btn.innerHTML = originalHtml;
      }
    });
  });

  // -------------------------------------------------------------------------
  // Reset All Defenses Button
  // -------------------------------------------------------------------------
  const resetBtn = document.getElementById('soc-reset-btn');
  if (resetBtn) {
    const originalResetHtml = resetBtn.innerHTML;
    resetBtn.addEventListener('click', async () => {
      playShieldChime();
      resetBtn.textContent = 'Restoring Baseline to GREEN...';
      
      if (activePostureElem) {
        activePostureElem.textContent = 'BASELINE (GREEN)';
        activePostureElem.style.color = '#34d399';
      }
      if (activeRouterStateElem) {
        activeRouterStateElem.textContent = 'FORWARDING (GREEN)';
        activeRouterStateElem.style.color = '#34d399';
      }

      try {
        const resp = await fetch('/soc/reset', { method: 'POST' });
        if (resp.status === 401) {
          alert('Operator authentication required. Please log in with ops / ops123.');
        }
        await fetch('/api/router/set_state', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ state: 'GREEN' })
        });
        showToast('All Quantum Defenses Restored: State GREEN');
        await fetchSocFeed();
        await fetchRouterTelemetry();
      } catch (err) {
        console.error(err);
      } finally {
        resetBtn.innerHTML = originalResetHtml;
      }
    });
  }

  // -------------------------------------------------------------------------
  // Router Action Buttons
  // -------------------------------------------------------------------------
  const btnForceGreen = document.getElementById('btn-router-force-green');
  if (btnForceGreen) {
    btnForceGreen.addEventListener('click', async () => {
      playShieldChime();
      await fetch('/api/router/set_state', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ state: 'GREEN' })
      });
      showToast('Router Forced to GREEN');
      await fetchRouterTelemetry();
    });
  }

  const btnInjectYellow = document.getElementById('btn-router-inject-yellow');
  if (btnInjectYellow) {
    btnInjectYellow.addEventListener('click', async () => {
      playClickSound();
      await fetch('/api/router/set_qber', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ qber: 6.8 })
      });
      showToast('Optical Fiber Drift Injected (QBER = 6.8%)');
      await fetchRouterTelemetry();
    });
  }

  const btnInjectRed = document.getElementById('btn-router-inject-red');
  if (btnInjectRed) {
    btnInjectRed.addEventListener('click', async () => {
      playAlertSiren();
      await fetch('/api/router/set_qber', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ qber: 16.5 })
      });
      showToast('Quantum Eavesdropper Injected (QBER = 16.5% ≥ 11%)');
      await fetchRouterTelemetry();
    });
  }

  const btnCycleDemo = document.getElementById('btn-router-cycle-demo');
  if (btnCycleDemo) {
    btnCycleDemo.addEventListener('click', async () => {
      playClickSound();
      await fetch('/api/router/demo_toggle', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ active: !autoDemoActive })
      });
      showToast(autoDemoActive ? 'Auto Demo Stopped' : 'Auto Demo Cycle Started');
      await fetchRouterTelemetry();
    });
  }

  // -------------------------------------------------------------------------
  // 1-Click Guided Demo Tour
  // -------------------------------------------------------------------------
  const guidedTourBtn = document.getElementById('btn-guided-tour');
  const tourBanner = document.getElementById('tour-narrative-banner');
  const tourStepCounter = document.getElementById('tour-step-counter');
  const tourText = document.getElementById('tour-text');
  const tourSkipBtn = document.getElementById('btn-tour-skip');

  let tourTimer = null;
  let tourCurrentStep = 0;

  const tourStages = [
    {
      title: 'STAGE 1 / 5 · CLEAN BASELINE',
      text: 'Starting Baseline: Clean BB84 QKD channel (QBER = 1.4% < 4%), Hoeffding bound τ=0.2097. Router forward policy ACCEPT.',
      action: async () => {
        await fetch('/soc/reset', { method: 'POST' });
        await fetch('/api/router/set_state', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ state: 'GREEN' }) });
      }
    },
    {
      title: 'STAGE 2 / 5 · FIBER OPTICAL DRIFT',
      text: 'Simulating Environmental Noise: QBER drifts to 6.8%. Warning threshold passed. Key generation throttled, warning logged in router fw4.',
      action: async () => {
        await fetch('/api/router/set_qber', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ qber: 6.8 }) });
      }
    },
    {
      title: 'STAGE 3 / 5 · QUANTUM ATTACK & FORGERY',
      text: 'Adversary (Eve) attacks the link & forges signature! QBER spikes to 16.5% >= 11% cutoff. Router guard turns RED, dropping port 8765.',
      action: async () => {
        playAlertSiren();
        await fetch('/soc/attack/forgery', { method: 'POST' });
        await fetch('/api/router/set_state', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ state: 'RED' }) });
      }
    },
    {
      title: 'STAGE 4 / 5 · HARDWARE PROBE ATTEMPT',
      text: 'Simulating transfer attempt under attack: Router kernel netfilter drops relay packet! Transaction instantly blocked.',
      action: async () => {
        if (fireSimBtn) fireSimBtn.click();
      }
    },
    {
      title: 'STAGE 5 / 5 · SELF-HEALING RESTORATION',
      text: 'Triggering Q-STDF self-healing protocol: Fresh quantum keys negotiated. Netfilter drop rules flushed. Baseline GREEN restored!',
      action: async () => {
        playShieldChime();
        await fetch('/soc/reset', { method: 'POST' });
        await fetch('/api/router/set_state', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ state: 'GREEN' }) });
      }
    }
  ];

  function runTourStep() {
    if (tourCurrentStep >= tourStages.length) {
      endTour();
      return;
    }
    const st = tourStages[tourCurrentStep];
    tourStepCounter.textContent = st.title;
    tourText.textContent = st.text;
    st.action();
    tourCurrentStep++;
    tourTimer = setTimeout(runTourStep, 7000);
  }

  function startTour() {
    initAudio();
    tourCurrentStep = 0;
    tourBanner.classList.remove('hidden');
    guidedTourBtn.style.boxShadow = '0 0 20px #00f2fe';
    runTourStep();
  }

  function endTour() {
    if (tourTimer) clearTimeout(tourTimer);
    tourBanner.classList.add('hidden');
    guidedTourBtn.style.boxShadow = '';
    showToast('Guided Demo Tour Completed');
  }

  if (guidedTourBtn) guidedTourBtn.addEventListener('click', startTour);
  if (tourSkipBtn) tourSkipBtn.addEventListener('click', endTour);

  // -------------------------------------------------------------------------
  // Main Polling Loop (1 sec tick)
  // -------------------------------------------------------------------------
  function tick() {
    fetchSocFeed();
    fetchRouterTelemetry();
  }

  tick();
  setInterval(tick, 1000);
});
