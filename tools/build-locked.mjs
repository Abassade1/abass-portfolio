// Encrypts the private case-study pages and their images (AES-256-GCM, key from
// PBKDF2-SHA256) so they can be hosted on a static site and only read in the
// browser by someone who has the passcode.
//
// Usage:  node tools/build-locked.mjs            (passcode from private-src/passcode.txt)
//         PASSCODE="new passcode" node tools/build-locked.mjs
//
// Inputs (git-ignored):  private-src/pages/*.html   plaintext case-study pages
//                        private-src/img/**         plaintext private images
// Outputs (public):      <name>.html (locked shell), locked/*.enc (encrypted images)
import { readFileSync, writeFileSync, readdirSync, mkdirSync, rmSync, existsSync } from 'node:fs';
import { createHash, createCipheriv, pbkdf2Sync, randomBytes } from 'node:crypto';
import { join, extname, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const ITER = 600000;
const passFile = join(root, 'private-src/passcode.txt');
const passcode = (process.env.PASSCODE ?? (existsSync(passFile) ? readFileSync(passFile, 'utf8') : '')).trim();
if (passcode.length < 12) {
  console.error('Passcode missing or shorter than 12 characters.');
  process.exit(1);
}
if (process.env.PASSCODE) writeFileSync(passFile, passcode + '\n', { mode: 0o600 });

const salt = existsSync(join(root, 'locked/salt.txt'))
  ? Buffer.from(readFileSync(join(root, 'locked/salt.txt'), 'utf8').trim(), 'base64')
  : randomBytes(16);
const key = pbkdf2Sync(passcode, salt, ITER, 32, 'sha256');

function encrypt(plain) {
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(plain), c.final(), c.getAuthTag()]); // WebCrypto layout: data || tag
  return { iv, ct };
}

const MIME = { '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.svg': 'image/svg+xml', '.webp': 'image/webp', '.gif': 'image/gif' };
const PLACEHOLDER = 'data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7';

rmSync(join(root, 'locked'), { recursive: true, force: true });
mkdirSync(join(root, 'locked'));
writeFileSync(join(root, 'locked/salt.txt'), salt.toString('base64') + '\n');

const imageCache = new Map();
function lockImage(rel) {
  if (imageCache.has(rel)) return imageCache.get(rel);
  const priv = join(root, 'private-src/img', rel);
  const pub = join(root, 'assets/img', rel);
  const file = existsSync(priv) ? priv : pub;
  if (!existsSync(file)) throw new Error('Missing image: ' + rel);
  const name = createHash('sha256').update(rel).digest('hex').slice(0, 20) + '.enc';
  const { iv, ct } = encrypt(readFileSync(file));
  writeFileSync(join(root, 'locked', name), Buffer.concat([iv, ct]));
  const out = { name, mime: MIME[extname(rel).toLowerCase()] ?? 'application/octet-stream' };
  imageCache.set(rel, out);
  return out;
}

const pagesDir = join(root, 'private-src/pages');
for (const file of readdirSync(pagesDir).filter((f) => f.endsWith('.html'))) {
  const src = readFileSync(join(pagesDir, file), 'utf8');
  const m = src.match(/^([\s\S]*?)<main id="main">([\s\S]*?)<\/main>([\s\S]*)$/);
  if (!m) throw new Error('No <main id="main"> in ' + file);
  let [, head, main, tail] = m;
  const title = (head.match(/<title>([^<]*)<\/title>/) ?? [])[1] ?? 'Case study';

  // swap every private image for a placeholder plus a pointer to its encrypted file
  main = main.replace(/<img\b[^>]*>/g, (tag) =>
    tag.replace(/\ssrc="assets\/img\/([^"]+)"/, (_, rel) => {
      const { name, mime } = lockImage(rel);
      return ` src="${PLACEHOLDER}" data-locked="locked/${name}" data-mime="${mime}"`;
    })
  );

  const { iv, ct } = encrypt(Buffer.from(JSON.stringify({ title, html: main }), 'utf8'));
  const payload = JSON.stringify({ salt: salt.toString('base64'), iter: ITER, iv: iv.toString('base64'), ct: ct.toString('base64') });

  // public shell: generic metadata only, no case-study text
  head = head
    .replace(/<title>[^<]*<\/title>/, '<title>Private case study | Mustapha Adebayo</title>')
    .replace(/<meta name="description"[^>]*>/, '<meta name="description" content="Private case study. A passcode is required.">')
    .replace(/\s*<meta (?:property="og:|name="twitter:)[^>]*>/g, '')
    .replace('<meta name="viewport"', '<meta name="robots" content="noindex, nofollow">\n    <meta name="viewport"')
    .replace("img-src 'self' data:;", "img-src 'self' data: blob:;");
  head = head.replace(/(<ul class="navbar-nav[^>]*>[\s\S]*?)(<\/ul>)/, '$1<li class="nav-item"><a class="nav-link" href="#" id="lock-link" hidden>Lock</a></li>\n            $2');
  tail = tail.replace('<script src="assets/js/nav-bar.js"></script>', '<script src="assets/js/nav-bar.js"></script>\n    <script src="assets/js/unlock.js"></script>');

  const gate = `<main id="main">
      <section class="container lock-gate" id="lock-gate" aria-labelledby="lock-title">
        <p class="kicker">Private case study</p>
        <h1 id="lock-title" class="h2">Enter the passcode to continue</h1>
        <p>Detailed case studies are shared with people I've given access to. You only need to enter the passcode once to read all of them.</p>
        <form id="lock-form" autocomplete="off">
          <label for="lock-input" class="visually-hidden">Passcode</label>
          <input id="lock-input" type="password" class="lock-input" placeholder="Passcode" autocomplete="off" required>
          <button type="submit" class="btn-accent" id="lock-button">Unlock</button>
          <p id="lock-error" class="lock-error" role="alert" hidden></p>
        </form>
        <p class="lock-help">Need access? <a href="mailto:abassade@gmail.com">Email me</a>.</p>
      </section>
      <div id="locked-content" hidden></div>
      <script id="locked-payload" type="application/json">${payload}</script>
    </main>`;
  writeFileSync(join(root, file), head + gate + tail);
  console.log('locked', file);
}
console.log('encrypted images:', imageCache.size);
