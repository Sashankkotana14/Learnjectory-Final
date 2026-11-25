// Settings module backend (additive): full profile editing, profile photo, theme/notification preferences, security, data export, account deletion.
// The original GET/PUT /api/settings and PUT /api/auth/password keep working exactly as before; everything here lives under /api/settings/*.
// Everything is scoped to req.user.id. Nothing in other modules' tables is written except on explicit account deletion (that user's own rows only).
const bcrypt = require('bcryptjs'), db = require('../database/db'), V = require('../lib/vaultStore');
const one = (s, ...a) => db.prepare(s).get(...a), all = (s, ...a) => db.prepare(s).all(...a), run = (s, ...a) => db.prepare(s).run(...a);
const bad = (res, error, status = 400) => res.status(status).json({ error });
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/, THEMES = ['light', 'dark', 'system'];
const AVATAR_MAX = 2 * 1024 * 1024;

// Own table (created on start, never touches existing tables): one profile photo per user, stored in the database.
db.exec(`CREATE TABLE IF NOT EXISTS user_avatars(user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,mime TEXT NOT NULL,data BLOB NOT NULL,size INTEGER NOT NULL,updated_at TEXT DEFAULT CURRENT_TIMESTAMP)`);

// Additive migration: academic profile columns + username on users (existing rows keep NULL; nothing is rewritten).
for (const [c, d] of [['username', 'TEXT'], ['college', "TEXT DEFAULT ''"], ['course', "TEXT DEFAULT ''"], ['branch', "TEXT DEFAULT ''"], ['year_of_study', "TEXT DEFAULT ''"]])
  if (!all('PRAGMA table_info(users)').some(x => x.name === c)) db.exec(`ALTER TABLE users ADD COLUMN ${c} ${d}`);
db.exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(LOWER(username)) WHERE username IS NOT NULL AND username<>\'\'');
const USERNAME = /^[A-Za-z0-9_.]{3,30}$/, YEARS = ['', '1', '2', '3', '4', '5', '6', 'Other'];
const TEXT_FIELDS = { college: 120, course: 120, branch: 120 };

// Real content check (magic bytes) - the file name / declared type is never trusted. SVG is deliberately not allowed (script risk).
function sniff(b) {
  if (!Buffer.isBuffer(b) || b.length < 12) return null;
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return 'image/jpeg';
  if (b.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return 'image/png';
  if (b.subarray(0, 4).toString('latin1') === 'RIFF' && b.subarray(8, 12).toString('latin1') === 'WEBP') return 'image/webp';
  if (['GIF87a', 'GIF89a'].includes(b.subarray(0, 6).toString('latin1'))) return 'image/gif';
  return null;
}
const settingsRow = uid => {
  let r = one('SELECT notifications,theme FROM user_settings WHERE user_id=?', uid);
  if (!r) { run('INSERT INTO user_settings(user_id) VALUES(?)', uid); r = one('SELECT notifications,theme FROM user_settings WHERE user_id=?', uid); }
  return r;
};
function profile(uid) {
  const u = one('SELECT id,name,username,email,bio,college,course,branch,year_of_study,created_at FROM users WHERE id=?', uid), s = settingsRow(uid), a = one('SELECT size,updated_at FROM user_avatars WHERE user_id=?', uid);
  return { ...u, username: u.username || '', college: u.college || '', course: u.course || '', branch: u.branch || '', year_of_study: u.year_of_study || '', notifications: s.notifications ? 1 : 0, theme: THEMES.includes(s.theme) ? s.theme : 'dark', has_avatar: !!a, avatar_updated_at: a ? a.updated_at : null, avatar_size: a ? a.size : 0 };
}
exports.getProfile = (req, res) => res.json(profile(req.user.id));

exports.updateProfile = (req, res) => {
  const uid = req.user.id, b = req.body || {}, u = one('SELECT * FROM users WHERE id=?', uid), out = {};
  if (b.name !== undefined) {
    const n = String(b.name).trim().replace(/\s+/g, ' ');
    if (!n) return bad(res, 'Name is required'); if (n.length > 80) return bad(res, 'Name must be 80 characters or less');
    out.name = n;
  }
  if (b.bio !== undefined) {
    const t = String(b.bio).trim();
    if (t.length > 500) return bad(res, 'Bio must be 500 characters or less');
    out.bio = t;
  }
  if (b.username !== undefined) {
    const n = String(b.username).trim();
    if (n && !USERNAME.test(n)) return bad(res, 'Username must be 3-30 characters: letters, numbers, dot or underscore');
    if (n && one('SELECT id FROM users WHERE LOWER(username)=LOWER(?) AND id<>?', n, uid)) return bad(res, 'That username is already taken', 409);
    out.username = n || null;
  }
  for (const [k, max] of Object.entries(TEXT_FIELDS)) if (b[k] !== undefined) {
    const t = String(b[k]).trim().replace(/\s+/g, ' ');
    if (t.length > max) return bad(res, `${k[0].toUpperCase() + k.slice(1)} must be ${max} characters or less`);
    out[k] = t;
  }
  if (b.year_of_study !== undefined) {
    const y = String(b.year_of_study).trim();
    if (!YEARS.includes(y)) return bad(res, 'Choose a valid year of study');
    out.year_of_study = y;
  }
  if (b.email !== undefined) {
    const e = String(b.email).trim().toLowerCase();
    if (e !== u.email) {
      if (!EMAIL.test(e) || e.length > 254) return bad(res, 'Enter a valid email address');
      if (!bcrypt.compareSync(String(b.currentPassword || ''), u.password)) return bad(res, 'Enter your current password to change your email', 401);
      if (one('SELECT id FROM users WHERE email=? AND id<>?', e, uid)) return bad(res, 'That email is already used by another account', 409);
      out.email = e;
    }
  }
  const keys = Object.keys(out);
  if (keys.length) run(`UPDATE users SET ${keys.map(k => k + '=?').join(',')} WHERE id=?`, ...keys.map(k => out[k]), uid);
  res.json(profile(uid));
};

exports.updatePreferences = (req, res) => {
  const uid = req.user.id, b = req.body || {}; settingsRow(uid);
  if (b.theme !== undefined && !THEMES.includes(b.theme)) return bad(res, 'Theme must be light, dark or system');
  if (b.notifications !== undefined && ![0, 1, true, false].includes(b.notifications)) return bad(res, 'notifications must be on or off');
  run('UPDATE user_settings SET theme=COALESCE(?,theme),notifications=COALESCE(?,notifications) WHERE user_id=?', b.theme ?? null, b.notifications === undefined ? null : (b.notifications ? 1 : 0), uid);
  res.json(profile(uid));
};

// ---- profile photo (raw request body, same transport as the rest of the app's uploads) ----
exports.uploadAvatar = (req, res) => {
  const buf = req.body;
  if (!Buffer.isBuffer(buf) || !buf.length) return bad(res, 'No image received');
  if (buf.length > AVATAR_MAX) return bad(res, 'Image is too large (max 2 MB)', 413);
  const mime = sniff(buf);
  if (!mime) return bad(res, 'Please choose a JPG, PNG, WebP or GIF image', 415);
  run(`INSERT INTO user_avatars(user_id,mime,data,size,updated_at) VALUES(?,?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(user_id) DO UPDATE SET mime=excluded.mime,data=excluded.data,size=excluded.size,updated_at=CURRENT_TIMESTAMP`, req.user.id, mime, buf, buf.length);
  res.json(profile(req.user.id));
};
exports.getAvatar = (req, res) => {
  const a = one('SELECT mime,data FROM user_avatars WHERE user_id=?', req.user.id);
  if (!a) return bad(res, 'No profile photo', 404);
  res.set({ 'Content-Type': a.mime, 'Content-Length': Buffer.byteLength(a.data), 'Cache-Control': 'private, no-cache', 'X-Content-Type-Options': 'nosniff', 'Content-Disposition': 'inline' });
  res.end(Buffer.from(a.data));
};
exports.removeAvatar = (req, res) => { run('DELETE FROM user_avatars WHERE user_id=?', req.user.id); res.json(profile(req.user.id)); };

// ---- security ----
// Sign out everywhere: bumping token_version invalidates every token issued so far (this device included), same mechanism as logout.
exports.signOutEverywhere = (req, res) => { run('UPDATE users SET token_version=COALESCE(token_version,0)+1 WHERE id=?', req.user.id); res.json({ ok: true }); };

// ---- data export: every row this user owns, as one readable text file (password hash, photo bytes and vault file storage names are never included) ----
const userTables = () => all("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").map(t => t.name)
  .filter(t => t !== 'users' && t !== 'user_avatars' && all(`PRAGMA table_info(${t})`).some(c => c.name === 'user_id'));
// Readable text layout for the download (plain, document-style: one detail per line, sections per topic). No JSON/raw keys are shown.
const TABLE_TITLES = { academics: 'Academics - Subjects', assignments: 'Assignments', study_sessions: 'Study Sessions', goals: 'Goals', habits: 'Habits', habit_logs: 'Habit History', projects: 'Projects', skills: 'Skills', achievements: 'Achievements', achievement_unlocks: 'Achievements Unlocked', opportunities: 'Opportunities', community_posts: 'Community Posts', community_comments: 'Community Comments', community_likes: 'Community Likes', community_collab: 'Collaboration Requests', vault: 'Vault - Notes', vault_files: 'Vault - Files', vault_links: 'Vault - Links', vault_folders: 'Vault - Folders', study_plans: 'Study Plans', study_plan_items: 'Study Plan Items', career_paths: 'Career Paths', career_lessons: 'Career Lessons', career_study_logs: 'Career Study Log', resumes: 'Resumes', saved_jobs: 'Saved Jobs', notifications: 'Notifications', activity_logs: 'Recent Activity', dashboard_boards: 'Dashboard Layout' };
const LABELS = { org: 'Organization', repo_url: 'Repository Link', link: 'Link', url: 'Link', target_grade: 'Target Grade', classes_attended: 'Classes Attended', classes_total: 'Total Classes', done_today: 'Done Today', daily_target: 'Daily Target', target_type: 'Target Type', target_unit: 'Target Unit', target_label: 'Target Label', est_minutes: 'Estimated Minutes', youtube_query: 'YouTube Search', notif_at: 'Time', is_read: 'Read', is_cleared: 'Cleared', mime: 'File Type', ext: 'Extension', size: 'Size', created_at: 'Created On', updated_at: 'Updated On', completed_at: 'Completed On', earned_at: 'Earned On', unlocked_at: 'Unlocked On', uploaded_at: 'Uploaded On', saved_at: 'Saved On', decided_at: 'Decided On', started_at: 'Started At', posted_at: 'Posted On', unlocked_date: 'Unlocked On', value_at_unlock: 'Value When Unlocked', log_date: 'Date', plan_date: 'Plan Date', session_date: 'Session Date', due_date: 'Due Date', target_date: 'Target Date' };
const YESNO = new Set(['completed', 'done_today', 'remote', 'is_read', 'is_cleared', 'visible']);
const prettyKey = k => LABELS[k] || k.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
const prettyTable = t => TABLE_TITLES[t] || prettyKey(t);
const nice = (k, v) => {
  if (YESNO.has(k)) return v ? 'Yes' : 'No';
  if (k === 'progress' && Number.isFinite(+v)) return v + '%';
  if (k === 'size' && Number.isFinite(+v)) { const n = +v; return n >= 1048576 ? (n / 1048576).toFixed(1) + ' MB' : n >= 1024 ? (n / 1024).toFixed(1) + ' KB' : n + ' bytes'; }
  if (k === 'notif_at' && Number.isFinite(+v) && +v > 0) return new Date(+v).toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
  if (typeof v === 'string') { const m = v.match(/^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2})(?::\d{2}(?:\.\d+)?)?Z?$/); if (m) return `${m[1]} ${m[2]}${/Z$/.test(v) || v.includes('T') ? ' UTC' : ''}`; return v.replace(/\r?\n/g, ' ').trim(); }
  return String(v);
};
function exportText(p, data, when) {
  const L = [], line = '='.repeat(60), thin = '-'.repeat(60), put = (k, v) => { if (v !== null && v !== undefined && String(v).trim() !== '') L.push(`${k}: ${v}`); };
  L.push(line, 'LEARNJECTORY - MY DATA', line, '', `Downloaded On: ${nice('x', when)}`, '', line, 'MY PROFILE', line);
  put('My Name', p.name); put('Username', p.username); put('Email', p.email); put('About Me', p.bio); put('College', p.college); put('Course', p.course); put('Branch', p.branch);
  put('Year of Study', p.year_of_study ? `Year ${p.year_of_study}` : ''); put('Member Since', p.created_at ? nice('x', p.created_at) : '');
  put('Theme', p.theme ? p.theme.charAt(0).toUpperCase() + p.theme.slice(1) : ''); put('Notifications', p.notifications ? 'On' : 'Off'); put('Profile Photo', p.has_avatar ? 'Yes' : 'No');
  for (const [t, rows] of Object.entries(data)) {
    if (!rows.length) continue;
    L.push('', '', line, `${prettyTable(t).toUpperCase()} (${rows.length})`, line);
    rows.forEach((r, i) => {
      L.push('', `${i + 1}.`);
      for (const [k, v] of Object.entries(r)) if (k !== 'id' && k !== 'user_id' && !/_id$/.test(k)) put('   ' + prettyKey(k), v === null || v === undefined || v === '' ? '' : nice(k, v));
    });
  }
  L.push('', '', thin, 'End of your Learnjectory data. Your password is never included.', thin, '');
  return L.join('\r\n');
}
exports.exportData = (req, res) => {
  const uid = req.user.id, data = {};
  for (const t of userTables()) data[t] = all(`SELECT * FROM ${t} WHERE user_id=?`, uid).map(r => { if ('stored_name' in r) { const { stored_name, ...rest } = r; return rest; } return r; });
  const body = exportText(profile(uid), data, new Date().toISOString());
  res.set({ 'Content-Type': 'text/plain; charset=utf-8', 'Content-Disposition': 'attachment; filename="learnjectory-my-data.txt"', 'Cache-Control': 'no-store' });
  res.send(body);
};

// ---- delete account: needs the password + the typed word DELETE; removes only this user's rows (and the rows other people attached to this user's posts/comments) ----
exports.deleteAccount = (req, res) => {
  const uid = req.user.id, b = req.body || {}, u = one('SELECT * FROM users WHERE id=?', uid);
  if (!u) return bad(res, 'Account not found', 404);
  if (String(b.confirm || '').trim() !== 'DELETE') return bad(res, 'Type DELETE to confirm');
  if (!bcrypt.compareSync(String(b.password || ''), u.password)) return bad(res, 'Password is incorrect', 401);
  const files = all('SELECT stored_name FROM vault_files WHERE user_id=?', uid).map(f => f.stored_name), tables = userTables();
  db.transaction(() => {
    run("DELETE FROM community_likes WHERE (target_type='post' AND target_id IN (SELECT id FROM community_posts WHERE user_id=?)) OR (target_type='comment' AND target_id IN (SELECT id FROM community_comments WHERE user_id=? OR post_id IN (SELECT id FROM community_posts WHERE user_id=?)))", uid, uid, uid);
    run('DELETE FROM community_comments WHERE post_id IN (SELECT id FROM community_posts WHERE user_id=?)', uid);
    run('DELETE FROM community_collab WHERE post_id IN (SELECT id FROM community_posts WHERE user_id=?)', uid);
    for (const t of tables) run(`DELETE FROM ${t} WHERE user_id=?`, uid);
    run('DELETE FROM user_avatars WHERE user_id=?', uid);
    run('DELETE FROM users WHERE id=?', uid);
  })();
  for (const f of files) V.remove(uid, f);
  res.json({ ok: true });
};
