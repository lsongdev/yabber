const examples = {
  proxy: {
    code: '# Your domain. Your local app.\ntls:\n  acme:\n    email: hello@example.com\n\nsites:\n  - hosts: [app.example.com]\n    proxy: http://127.0.0.1:3000',
    description: 'Automatic HTTPS → your app on port 3000',
  },
  files: {
    code: '# A home for your static site.\ntls:\n  acme:\n    email: hello@example.com\n\nsites:\n  - hosts: [www.example.com]\n    files: /srv/www',
    description: 'Automatic HTTPS → static files in /srv/www',
  },
  redirect: {
    code: '# Point visitors in the right direction.\ntls:\n  acme:\n    email: hello@example.com\n\nsites:\n  - hosts: [old.example.com]\n    redirect:\n      to: https://www.example.com\n      preserve_path: true',
    description: 'Automatic HTTPS → a permanent redirect, path included',
  },
};

const tabs = [...document.querySelectorAll('[data-example]')];
const configCode = document.getElementById('config-code');
const configPanel = document.getElementById('config-panel');

// Create text nodes rather than interpreting configuration as HTML.
function renderCode(source) {
  const lines = source.split('\n');
  configCode.replaceChildren();
  lines.forEach((line, index) => {
    if (index) configCode.append('\n');
    const match = line.match(/^(\s*(?:- )?)([a-z_]+:)(.*)$/);
    if (line.startsWith('#')) {
      const comment = document.createElement('span');
      comment.className = 'syntax-comment';
      comment.textContent = line;
      configCode.append(comment);
    } else if (match) {
      const key = document.createElement('span');
      key.className = 'syntax-key';
      key.textContent = match[2];
      configCode.append(match[1], key, match[3]);
    } else {
      configCode.append(line);
    }
  });
}

function selectExample(tab) {
  const example = examples[tab.dataset.example];
  tabs.forEach((item) => {
    const selected = item === tab;
    item.setAttribute('aria-selected', String(selected));
    item.tabIndex = selected ? 0 : -1;
  });
  configPanel.setAttribute('aria-labelledby', tab.id);
  renderCode(example.code);
  document.getElementById('config-description').textContent = example.description;
}

tabs.forEach((tab, index) => {
  tab.addEventListener('click', () => selectExample(tab));
  tab.addEventListener('keydown', (event) => {
    let next;
    if (event.key === 'ArrowRight') next = (index + 1) % tabs.length;
    if (event.key === 'ArrowLeft') next = (index - 1 + tabs.length) % tabs.length;
    if (event.key === 'Home') next = 0;
    if (event.key === 'End') next = tabs.length - 1;
    if (next === undefined) return;
    event.preventDefault();
    selectExample(tabs[next]);
    tabs[next].focus();
  });
});

document.querySelectorAll('[data-copy]').forEach((button) => {
  let resetTimer;
  button.addEventListener('click', async () => {
    const source = document.getElementById(button.dataset.copy);
    const status = document.getElementById('copy-status');
    const original = button.textContent;
    try {
      await navigator.clipboard.writeText(source.textContent);
      clearTimeout(resetTimer);
      button.textContent = 'Copied ✓';
      status.textContent = 'Copied to clipboard.';
      resetTimer = setTimeout(() => { button.textContent = 'Copy ⧉'; }, 2200);
    } catch {
      const selection = window.getSelection();
      const range = document.createRange();
      range.selectNodeContents(source);
      selection.removeAllRanges();
      selection.addRange(range);
      status.textContent = 'Clipboard unavailable. Text selected; use your device’s copy command.';
      button.textContent = original;
    }
  });
});
