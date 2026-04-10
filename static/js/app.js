'use strict';

let currentMode = 'deterministic';

// ── Mode toggle ─────────────────────────────────────────────────

function setMode(mode) {
  currentMode = mode;

  const masterField = document.getElementById('master-field');
  const domainField = document.getElementById('domain-field');
  const warning     = document.getElementById('argon-warning');
  const detBtn      = document.getElementById('mode-det');
  const rndBtn      = document.getElementById('mode-rnd');

  const isRandom = mode === 'random';

  masterField.classList.toggle('hidden', isRandom);
  domainField.classList.toggle('hidden', isRandom);
  warning.classList.toggle('hidden', isRandom);   // предупреждение только для Argon2

  detBtn.classList.toggle('active', !isRandom);
  rndBtn.classList.toggle('active',  isRandom);

  document.getElementById('result').classList.remove('visible');
  document.getElementById('error-msg').classList.remove('visible');
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

  btn.disabled             = true;
  spinner.style.display    = 'block';
  btnIcon.style.display    = 'none';
  btnText.textContent      = currentMode === 'random' ? 'Генерация…' : 'Вычисление Argon2id…';

  try {
    let res;
    const controller = new AbortController();
    const timeoutId  = setTimeout(() => controller.abort(), 30000);

    try {
      if (currentMode === 'random') {
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
    btnText.textContent   = 'Сгенерировать пароль';
  }
}

// ── Helpers ─────────────────────────────────────────────────────

function showResult(data, domain) {
  document.getElementById('result-label').textContent =
    currentMode === 'random' ? 'Случайный пароль' : `Пароль для ${domain}`;

  document.getElementById('result-password').textContent = data.password;
  document.getElementById('meta-length').textContent     = data.length;
  document.getElementById('meta-charset').textContent    = data.charset_size;
  document.getElementById('meta-entropy').textContent    = data.entropy_bits;

  document.getElementById('result').classList.add('visible');
  resetCopyBtn();
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
