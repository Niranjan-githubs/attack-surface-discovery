// Phase 17: Bulk Write to Storage. SINGLE TRANSLATION POINT — only this file knows the schema.

const path = require('path');
const Database = require('better-sqlite3');
const { readArtifact, writeArtifact, log, STORAGE_DIR } = require('./lib');

const DB_PATH = path.join(STORAGE_DIR, 'reconnaissance.db');

(async () => {
  // Fresh DB each run
  const fs = require('fs');
  if (fs.existsSync(DB_PATH)) fs.unlinkSync(DB_PATH);
  const db = new Database(DB_PATH);

  db.exec(`
    CREATE TABLE endpoints (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      canonical TEXT NOT NULL UNIQUE,
      methods TEXT NOT NULL,
      sources TEXT NOT NULL,
      statuses TEXT,
      confidence TEXT
    );
    CREATE TABLE role_access (
      endpoint_id INTEGER REFERENCES endpoints(id),
      role TEXT NOT NULL,
      status INTEGER,
      PRIMARY KEY (endpoint_id, role)
    );
    CREATE TABLE parameters (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      endpoint_canonical TEXT,
      name TEXT,
      where_ TEXT,
      classification TEXT,
      semantic_type TEXT,
      occurrences INTEGER
    );
    CREATE TABLE workflows (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      purpose TEXT,
      step_count INTEGER
    );
    CREATE TABLE workflow_steps (
      workflow_id INTEGER REFERENCES workflows(id),
      step_order INTEGER,
      endpoint_canonical TEXT,
      method TEXT,
      role TEXT
    );
    CREATE TABLE artifacts_meta (
      name TEXT PRIMARY KEY,
      path TEXT,
      timestamp TEXT
    );
    CREATE TABLE secrets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      type TEXT,
      severity TEXT,
      source_file TEXT,
      snippet TEXT
    );
    CREATE INDEX idx_ep_conf ON endpoints(confidence);
    CREATE INDEX idx_ra_role ON role_access(role);
  `);

  const endpoints = readArtifact('phase15_endpoints.json');
  const params = readArtifact('phase14_params.json');
  const flows = readArtifact('phase16_flows.json');
  const js = readArtifact('phase11_js.json');

  const insEp = db.prepare('INSERT OR IGNORE INTO endpoints (canonical, methods, sources, statuses, confidence) VALUES (?, ?, ?, ?, ?)');
  const insRA = db.prepare('INSERT OR REPLACE INTO role_access (endpoint_id, role, status) VALUES (?, ?, ?)');
  const getEpId = db.prepare('SELECT id FROM endpoints WHERE canonical = ?');
  const insParam = db.prepare('INSERT INTO parameters (endpoint_canonical, name, where_, classification, semantic_type, occurrences) VALUES (?, ?, ?, ?, ?, ?)');
  const insFlow = db.prepare('INSERT INTO workflows (name, purpose, step_count) VALUES (?, ?, ?)');
  const insStep = db.prepare('INSERT INTO workflow_steps (workflow_id, step_order, endpoint_canonical, method, role) VALUES (?, ?, ?, ?, ?)');
  const insSecret = db.prepare('INSERT INTO secrets (type, severity, source_file, snippet) VALUES (?, ?, ?, ?)');

  let epCount = 0, raCount = 0, paramCount = 0, flowCount = 0, stepCount = 0, secretCount = 0;

  const tx = db.transaction(() => {
    for (const e of (endpoints?.endpoints || [])) {
      insEp.run(e.canonical, e.methods.join(','), e.sources.join(','), e.statuses.join(','), e.confidence);
      epCount++;
      const row = getEpId.get(e.canonical);
      if (row) {
        for (const [role, status] of Object.entries(e.roleAccess || {})) {
          insRA.run(row.id, role, typeof status === 'number' ? status : (status?.status || null));
          raCount++;
        }
      }
    }
    for (const p of (params?.params || [])) {
      insParam.run(p.path, p.name, p.where, p.classification, p.semanticType, p.occurrences);
      paramCount++;
    }
    for (const f of (flows?.workflows || [])) {
      const r = insFlow.run(f.name, f.purpose || null, (f.steps || []).length);
      flowCount++;
      let order = 0;
      for (const s of (f.steps || [])) {
        insStep.run(r.lastInsertRowid, order++, s.endpoint, s.method || 'GET', s.role || null);
        stepCount++;
      }
    }
    for (const s of (js?.secrets || [])) {
      insSecret.run(s.type, s.severity, s.sourceFile, s.snippet);
      secretCount++;
    }
  });
  tx();

  db.close();

  writeArtifact('phase17_storage.json', {
    phase: 17,
    timestamp: new Date().toISOString(),
    dbPath: DB_PATH,
    rowCounts: { endpoints: epCount, role_access: raCount, parameters: paramCount, workflows: flowCount, workflow_steps: stepCount, secrets: secretCount },
  });
  log(17, `OK: wrote ${epCount} endpoints, ${raCount} role_access, ${paramCount} params, ${flowCount} workflows, ${secretCount} secrets to ${DB_PATH}`);
})();
