// Phase 2: Initialize Target Metadata
// Fetch homepage, extract forms/links/scripts/tech stack.

const cheerio = require('cheerio');
const { loadConfig, writeArtifact, fetchWithTimeout, log, isSameOrigin } = require('./lib');

function detectTechStack(html, headers) {
  const frameworks = [];
  const server = headers.get('server') || null;
  const poweredBy = headers.get('x-powered-by') || null;

  const lc = html.toLowerCase();
  if (/\bng-version|ng-controller|data-ng-|angular\b/.test(lc)) frameworks.push('Angular');
  if (/\b__next|_next\/static\b/.test(lc)) frameworks.push('Next.js');
  if (/<div[^>]+id="root"[^>]*>\s*<\/div>/.test(html) || /react-dom|data-reactroot/.test(lc)) frameworks.push('React');
  if (/\bvue\b|v-app|data-v-/.test(lc)) frameworks.push('Vue');
  if (/\bsvelte\b/.test(lc)) frameworks.push('Svelte');
  if (/csrf-token|_csrf/.test(lc)) frameworks.push('server-rendered-form');

  return { frameworks: Array.from(new Set(frameworks)), server, poweredBy };
}

(async () => {
  const cfg = loadConfig();
  const target = cfg.target;
  log(2, `extracting metadata`);

  const res = await fetchWithTimeout(target, { method: 'GET' }, 30000);
  const html = await res.text();
  const $ = cheerio.load(html);

  const links = new Set();
  $('a[href]').each((_, el) => {
    const href = $(el).attr('href');
    if (!href || href.startsWith('#') || href.startsWith('javascript:') || href.startsWith('mailto:')) return;
    if (isSameOrigin(target, href)) {
      try { links.add(new URL(href, target).pathname); } catch {}
    }
  });

  const forms = [];
  $('form').each((_, el) => {
    const $f = $(el);
    forms.push({
      action: $f.attr('action') || '/',
      method: ($f.attr('method') || 'GET').toUpperCase(),
      fields: $f.find('input[name], select[name], textarea[name]').map((_, inp) => $(inp).attr('name')).get(),
    });
  });

  const scripts = [];
  $('script[src]').each((_, el) => {
    const src = $(el).attr('src');
    if (src) scripts.push(src);
  });

  const metadata = {
    phase: 2,
    target,
    timestamp: new Date().toISOString(),
    title: $('title').first().text().trim() || null,
    description: $('meta[name="description"]').attr('content') || null,
    techStack: detectTechStack(html, res.headers),
    initialEndpoints: Array.from(links).sort(),
    initialForms: forms,
    scripts: Array.from(new Set(scripts)),
    htmlBodyEmpty: !$('body').text().trim(),
  };

  writeArtifact('phase2_metadata.json', metadata);
  log(2, `OK: ${metadata.initialEndpoints.length} links, ${metadata.initialForms.length} forms, ${metadata.scripts.length} scripts, frameworks=${JSON.stringify(metadata.techStack.frameworks)}`);
})();
