(() => {
  'use strict';
  const form = document.getElementById('unlock-form');
  const password = document.getElementById('password');
  const button = document.getElementById('unlock');
  const status = document.getElementById('status');
  const text = new TextEncoder();
  const fragment = new URLSearchParams(location.hash.slice(1)).get('k');

  function readKey(value) {
    if (!/^[A-Za-z0-9_-]{43}$/.test(value || '')) return null;
    const raw = atob(value.replace(/-/g, '+').replace(/_/g, '/') + '=');
    return Uint8Array.from(raw, ch => ch.charCodeAt(0));
  }
  const shareKey = readKey(fragment);
  if (!shareKey || !window.crypto?.subtle) {
    password.disabled = true;
    button.disabled = true;
    status.textContent = shareKey ? '请在支持 HTTPS 的现代浏览器中打开。' : '请使用完整的分享链接打开画板。';
    return;
  }
  let payloadPromise;
  async function loadPayload() {
    const response = await fetch('./board.bin', { credentials: 'omit', referrerPolicy: 'no-referrer' });
    if (!response.ok) throw new Error('load');
    const data = new Uint8Array(await response.arrayBuffer());
    if (data.length < 52 || new TextDecoder().decode(data.subarray(0,8)) !== 'BOARD001') throw new Error('load');
    return data;
  }
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (!password.value || button.disabled) return;
    button.disabled = true;
    status.textContent = '正在打开…';
    const passBytes = text.encode(password.value);
    const prefix = text.encode('board-key-v1:');
    const material = new Uint8Array(prefix.length + shareKey.length + 1 + passBytes.length);
    material.set(prefix);
    material.set(shareKey, prefix.length);
    material.set(passBytes, prefix.length + shareKey.length + 1);
    passBytes.fill(0);
    let data;
    try {
      payloadPromise ||= loadPayload();
      data = await payloadPromise;
    } catch {
      payloadPromise = null;
      material.fill(0);
      status.textContent = '画板加载失败，请重试。';
      button.disabled = false;
      return;
    }
    try {
      const secret = await crypto.subtle.importKey('raw', material, 'PBKDF2', false, ['deriveKey']);
      const aes = await crypto.subtle.deriveKey(
        { name: 'PBKDF2', hash: 'SHA-256', iterations: 600000, salt: data.subarray(8,24) },
        secret, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
      );
      const clear = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: data.subarray(24,36) }, aes, data.subarray(36));
      const anchorSupport = `<script>
        document.addEventListener('click', e => {
          const link = e.target.closest('a[href^="#"]');
          if (!link) return;
          const target = document.getElementById(link.getAttribute('href').slice(1));
          if (target) { e.preventDefault(); target.scrollIntoView({ block: 'start' }); }
        });</script>`;
      const html = new TextDecoder().decode(clear).replace('</body>', anchorSupport + '</body>');
      const src = URL.createObjectURL(new Blob([html], { type: 'text/html;charset=utf-8' }));
      const frame = document.createElement('iframe');
      frame.id = 'preview';
      frame.title = '移动端频道设计画板';
      frame.setAttribute('sandbox', 'allow-scripts allow-forms');
      frame.referrerPolicy = 'no-referrer';
      frame.src = src;
      document.title = '移动端频道设计画板';
      password.value = '';
      document.body.replaceChildren(frame);
      addEventListener('unload', () => URL.revokeObjectURL(src), { once: true });
    } catch {
      status.textContent = '密码不正确或分享链接已变更。';
      button.disabled = false;
      password.select();
    } finally {
      material.fill(0);
    }
  });
})();
