'use strict';

let currentMode = 'deterministic';
let _wordCount  = 4;
let _separator  = '-';

// ── Popup / integration mode ─────────────────────────────────────
const _urlParams   = new URLSearchParams(window.location.search);
const _popupDomain = _urlParams.get('domain') || '';
const _popupSource = _urlParams.get('source') || '';
const _isPopup     = !!_popupSource && !!window.opener;

// Validate opener origin — prevents any site from intercepting the password via postMessage
const _popupOrigin = (() => {
  const raw = _urlParams.get('origin') || '';
  try {
    const u = new URL(raw);
    if (['https:', 'http:', 'chrome-extension:', 'moz-extension:'].includes(u.protocol))
      return u.origin;
  } catch (_) {}
  return '';
})();

if (_popupDomain) {
  document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('domain').value = _popupDomain;
  });
}

// ── Mode toggle ─────────────────────────────────────────────────

function setMode(mode) {
  currentMode = mode;

  const masterField = document.getElementById('master-field');
  const domainField = document.getElementById('domain-field');
  const sliderWrap  = document.querySelector('.slider-wrap');
  const warning     = document.getElementById('argon-warning');
  const phraseField = document.getElementById('phrase-field');
  const detBtn      = document.getElementById('mode-det');
  const rndBtn      = document.getElementById('mode-rnd');
  const phraseBtn   = document.getElementById('mode-phrase');

  const isDet    = mode === 'deterministic';
  const isRnd    = mode === 'random';
  const isPhrase = mode === 'passphrase';

  masterField.classList.toggle('hidden', !isDet);
  domainField.classList.toggle('hidden', !isDet);
  warning.classList.toggle('hidden', !isDet);
  sliderWrap.classList.toggle('hidden', isPhrase);
  phraseField.classList.toggle('hidden', !isPhrase);

  detBtn.classList.toggle('active', isDet);
  rndBtn.classList.toggle('active', isRnd);
  phraseBtn.classList.toggle('active', isPhrase);

  document.getElementById('btn-text').textContent = isPhrase ? 'Сгенерировать фразу' : 'Сгенерировать пароль';
  document.getElementById('result').classList.remove('visible');
  document.getElementById('error-msg').classList.remove('visible');
}

function setWordCount(n) {
  _wordCount = n;
  document.querySelectorAll('#word-count-btns .sep-btn').forEach(b => {
    b.classList.toggle('active', parseInt(b.textContent) === n);
  });
}

function setSep(sep) {
  _separator = sep;
  const labels = { '-': 'дефис  —', ' ': 'пробел', '.': 'точка  .', '_': 'подчёркивание _' };
  document.querySelectorAll('#sep-btns .sep-btn').forEach(b => {
    b.classList.toggle('active', b.textContent.trim() === (labels[sep] || '').trim());
  });
}

// ── Slider ──────────────────────────────────────────────────────

function updateLen(v) {
  document.getElementById('len-val').textContent = `${v} символов`;
}

// ── Eye toggle ──────────────────────────────────────────────────

function toggleEye() {
  const inp  = document.getElementById('master');
  const ico  = document.getElementById('eye-icon');
  const show = inp.type === 'password';
  inp.type = show ? 'text' : 'password';
  ico.innerHTML = show
    ? `<line x1="1" y1="1" x2="23" y2="23"/>
       <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8
                a18.45 18.45 0 0 1 5.06-5.94"/>
       <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8
                a18.5 18.5 0 0 1-2.16 3.19"/>
       <path d="M14.12 14.12A3 3 0 1 1 9.88 9.88"/>`
    : `<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
       <circle cx="12" cy="12" r="3"/>`;
}

// ── Generate ────────────────────────────────────────────────────

async function generate() {
  const master  = document.getElementById('master').value;
  const domain  = document.getElementById('domain').value.trim();
  const length  = parseInt(document.getElementById('pwd-length').value);

  const errEl   = document.getElementById('error-msg');
  const btn     = document.getElementById('btn-gen');
  const spinner = document.getElementById('spinner');
  const btnIcon = document.getElementById('btn-icon');
  const btnText = document.getElementById('btn-text');

  errEl.classList.remove('visible');
  document.getElementById('result').classList.remove('visible');

  if (currentMode === 'deterministic') {
    if (!master) return showError('Введите главный пароль.');
    if (!domain) return showError('Введите домен или сервис.');
  }

  btn.disabled          = true;
  spinner.style.display = 'block';
  btnIcon.style.display = 'none';
  btnText.textContent   = currentMode === 'passphrase' ? 'Генерация…'
                        : currentMode === 'random'     ? 'Генерация…'
                        : 'Вычисление Argon2id…';

  try {
    let res;
    const controller = new AbortController();
    const timeoutId  = setTimeout(() => controller.abort(), 30000);

    try {
      if (currentMode === 'passphrase') {
        res = await fetch('/generate/passphrase', {
          method:  'POST',
          headers: { 'Content-Type': 'application/json' },
          body:    JSON.stringify({ words: _wordCount, separator: _separator }),
          signal:  controller.signal,
        });
      } else if (currentMode === 'random') {
        res = await fetch('/generate/random', {
          method:  'POST',
          headers: { 'Content-Type': 'application/json' },
          body:    JSON.stringify({ length }),
          signal:  controller.signal,
        });
      } else {
        res = await fetch('/generate', {
          method:  'POST',
          headers: { 'Content-Type': 'application/json' },
          body:    JSON.stringify({ master_password: master, domain, length }),
          signal:  controller.signal,
        });
      }
    } finally {
      clearTimeout(timeoutId);
    }

    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || `Ошибка сервера: ${res.status}`);

    showResult(data, domain);

  } catch (e) {
    showError(e.name === 'AbortError' ? 'Превышено время ожидания (30 с).' : e.message);
  } finally {
    btn.disabled          = false;
    spinner.style.display = 'none';
    btnIcon.style.display = 'block';
    btnText.textContent   = currentMode === 'passphrase' ? 'Сгенерировать фразу' : 'Сгенерировать пароль';
  }
}

// ── Helpers ─────────────────────────────────────────────────────

function showResult(data, domain) {
  if (currentMode === 'passphrase') {
    document.getElementById('result-label').textContent    = 'Кодовая фраза';
    document.getElementById('result-password').textContent = data.passphrase;
    document.getElementById('meta-length').textContent     = data.word_count + ' сл.';
    document.getElementById('meta-charset').textContent    = '—';
    document.getElementById('meta-entropy').textContent    = data.entropy_bits;
  } else {
    document.getElementById('result-label').textContent =
      currentMode === 'random' ? 'Случайный пароль' : `Пароль для ${domain}`;
    document.getElementById('result-password').textContent = data.password;
    document.getElementById('meta-length').textContent     = data.length;
    document.getElementById('meta-charset').textContent    = data.charset_size;
    document.getElementById('meta-entropy').textContent    = data.entropy_bits;
  }

  document.getElementById('result').classList.add('visible');

  if (_isPopup) {
    const btn = document.getElementById('btn-copy');
    btn.classList.remove('copied');
    btn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 11 12 14 22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg>Вставить в ${_popupSource}`;
    btn.onclick = sendToOpener;
  } else {
    resetCopyBtn();
  }
}

function sendToOpener() {
  const pwd = document.getElementById('result-password').textContent;
  window.opener.postMessage({ type: 'upass_password', password: pwd }, _popupOrigin || window.location.origin);
  const btn = document.getElementById('btn-copy');
  btn.classList.add('copied');
  btn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>Вставлено!`;
  setTimeout(() => window.close(), 800);
}

function showError(msg) {
  const el = document.getElementById('error-msg');
  el.textContent = msg;
  el.classList.add('visible');
}

function resetCopyBtn() {
  const btn = document.getElementById('btn-copy');
  btn.classList.remove('copied');
  btn.innerHTML = `
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none"
         stroke="currentColor" stroke-width="2">
      <rect x="9" y="9" width="13" height="13" rx="2"/>
      <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
    </svg>Копировать`;
}

async function copyPassword() {
  const pwd = document.getElementById('result-password').textContent;
  const btn = document.getElementById('btn-copy');
  try {
    await navigator.clipboard.writeText(pwd);
  } catch {
    // Fallback for browsers without Clipboard API
    const ta = document.createElement('textarea');
    ta.value = pwd;
    ta.style.cssText = 'position:fixed;opacity:0';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
  }
  btn.classList.add('copied');
  btn.innerHTML = `
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none"
         stroke="currentColor" stroke-width="2">
      <polyline points="20 6 9 17 4 12"/>
    </svg>Скопировано!`;
  setTimeout(resetCopyBtn, 2000);
}

// Enter → generate
document.addEventListener('keydown', e => {
  if (e.key === 'Enter') generate();
});

// ── Strength Meter ───────────────────────────────────────────────
const _SM_LABELS = ['', 'Очень слабый', 'Слабый', 'Средний', 'Сильный', 'Очень сильный'];
const _SM_COLORS = ['', '#ef4444', '#f97316', '#eab308', '#22c55e', '#6366f1'];

function _smEntropy(pwd) {
  let pool = 0;
  if (/[a-z]/.test(pwd)) pool += 26;
  if (/[A-Z]/.test(pwd)) pool += 26;
  if (/[0-9]/.test(pwd))  pool += 10;
  if (/[^a-zA-Z0-9]/.test(pwd)) pool += 32;
  return pool > 0 ? Math.round(pwd.length * Math.log2(pool)) : 0;
}

function _smScore(pwd) {
  if (!pwd) return 0;
  let s = 0;
  if (pwd.length >= 8)          s++;
  if (/[A-Z]/.test(pwd))        s++;
  if (/[a-z]/.test(pwd))        s++;
  if (/[0-9]/.test(pwd))        s++;
  if (/[^a-zA-Z0-9]/.test(pwd)) s++;
  if (pwd.length >= 16) s = Math.min(5, s + 1);
  if (pwd.length < 6)   s = Math.min(1, s);
  return Math.min(5, s);
}

function _smCheck(id, ok) {
  document.getElementById('smc-' + id).classList.toggle('ok', ok);
  const dot = document.getElementById('smd-' + id);
  dot.textContent = ok ? '✓' : '';
}

function smAnalyze(pwd) {
  const sc   = _smScore(pwd);
  const bits = _smEntropy(pwd);

  for (let i = 1; i <= 5; i++) {
    const bar = document.getElementById('sm-b' + i);
    bar.className = 'sm-bar' + (i <= sc ? ` s${sc}` : '');
  }

  const lbl = document.getElementById('sm-label');
  lbl.textContent = pwd ? _SM_LABELS[sc] : '—';
  lbl.style.color = pwd ? _SM_COLORS[sc] : '#4b5563';

  document.getElementById('sm-entropy').textContent = pwd ? `~${bits} бит энтропии` : '';

  _smCheck('len',     pwd.length >= 8);
  _smCheck('upper',   /[A-Z]/.test(pwd));
  _smCheck('lower',   /[a-z]/.test(pwd));
  _smCheck('digit',   /[0-9]/.test(pwd));
  _smCheck('special', /[^a-zA-Z0-9]/.test(pwd));
  _smCheck('long',    pwd.length >= 16);
}
