<?php
/**
 * Hitek Multi-API Admin — Panel Gate Edition
 * Single-file PHP app with:
 * - ADMIN PANEL GATE password (before any admin page)
 * - Create/manage APIs with: unique Data URL, API key (optional), match mode, CORS
 * - Extra features (10+): theme toggle, NotFound message, field targeting, IP allow/deny,
 *   webhook callbacks, CSV export, analytics, health check, pretty JSON, rate window override.
 *
 * Public endpoint: ?route=api&slug=SLUG&number=VALUE[&key=API_KEY][&pretty=1]
 */

declare(strict_types=1);
session_start();

/* =========================
   CONFIG
========================= */
const PANEL_PASS            = 'Fantom=Gandu'; // <<< Admin panel password gate
const GLOBAL_DEFAULT_DATA_URL = 'https://hitek.ffloveryt.workers.dev/';
const GLOBAL_CACHE_TTL_SEC  = 300;   // default cache ttl
const CACHE_DIR             = __DIR__ . '/cache';
const DB_FILE               = __DIR__ . '/app.db';
const APP_BASE_URL          = '';    // leave blank to auto-guess
const DEFAULT_ADMIN_USER    = 'admin';
const DEFAULT_ADMIN_PASS    = 'admin123';

// Default global RL fallback (overridden per API by sidecar)
const RL_WINDOW_SECONDS_DEF = 60;    // seconds
const RL_MAX_HITS_DEF       = 60;    // requests per window

/* =========================
   BOOTSTRAP
========================= */
if (!is_dir(CACHE_DIR)) @mkdir(CACHE_DIR, 0775, true);
$db = new PDO('sqlite:' . DB_FILE);
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
init_db($db);
ensure_default_admin($db);

// Routing
$route = $_GET['route'] ?? 'gate';

// Gate: force password before any admin route (API bypasses gate)
$admin_routes = ['login','dashboard','create_api','toggle_api','delete_api','regen_key','update_api','logs','export_csv','health'];
if (in_array($route, $admin_routes, true) && !panel_gate_ok()) {
    $route = 'gate';
}

switch ($route) {
    // Gate + Auth
    case 'gate':         render_gate(); break;
    case 'gate_submit':  handle_gate_submit(); break;

    case 'login':        handle_login($db); break;
    case 'logout':       handle_logout(); break;

    // Admin features
    case 'dashboard':    require_auth(); render_dashboard($db); break;
    case 'create_api':   require_auth(); handle_create_api($db); break;
    case 'toggle_api':   require_auth(); handle_toggle_api($db); break;
    case 'delete_api':   require_auth(); handle_delete_api($db); break;
    case 'regen_key':    require_auth(); handle_regen_key($db); break;
    case 'update_api':   require_auth(); handle_update_api($db); break;
    case 'logs':         require_auth(); render_logs($db); break;
    case 'export_csv':   require_auth(); export_logs_csv($db); break;
    case 'health':       require_auth(); render_health($db); break;

    // Public API
    case 'api':          handle_public_api($db); break;

    default: http_response_code(404); echo "Not Found"; break;
}

/* =========================
   DB SCHEMA
========================= */
function init_db(PDO $db): void {
    $db->exec("
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
    ");
    $db->exec("
        CREATE TABLE IF NOT EXISTS apis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            slug TEXT UNIQUE NOT NULL,
            label TEXT,
            data_url TEXT, -- unique per API if provided
            require_key INTEGER NOT NULL DEFAULT 0,
            api_key TEXT,
            match_mode TEXT NOT NULL DEFAULT 'exact', -- 'exact' | 'contains'
            cors_enabled INTEGER NOT NULL DEFAULT 0,
            notfound_text TEXT, -- custom Not Found message
            search_fields TEXT, -- CSV of fields/columns to target (JSON or CSV)
            allow_ips TEXT,     -- CSV allowlist
            deny_ips TEXT,      -- CSV denylist
            webhook_url TEXT,   -- callback on hit/miss
            enabled INTEGER NOT NULL DEFAULT 1,
            created_by INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT,
            UNIQUE(data_url),
            FOREIGN KEY(created_by) REFERENCES admins(id)
        );
    ");
    $db->exec("
        CREATE TABLE IF NOT EXISTS hits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            api_id INTEGER NOT NULL,
            ip TEXT NOT NULL,
            number TEXT,
            ok INTEGER NOT NULL,
            ts INTEGER NOT NULL,
            ua TEXT,
            FOREIGN KEY(api_id) REFERENCES apis(id)
        );
    ");
}

function ensure_default_admin(PDO $db): void {
    $c = (int)$db->query("SELECT COUNT(*) FROM admins")->fetchColumn();
    if ($c === 0) {
        $hash = password_hash(DEFAULT_ADMIN_PASS, PASSWORD_DEFAULT);
        $st = $db->prepare("INSERT INTO admins (username, password_hash, created_at) VALUES (?,?,?)");
        $st->execute([DEFAULT_ADMIN_USER, $hash, date('c')]);
    }
}

/* =========================
   PANEL GATE
========================= */
function panel_gate_ok(): bool {
    return isset($_SESSION['panel_ok']) && $_SESSION['panel_ok'] === true;
}
function render_gate(string $err=''): void {
    $theme = theme_css();
    $mode = theme_mode();
    echo <<<HTML
<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin Panel Gate</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<style>{$theme}</style></head>
<body class="bg-gradient {$mode}">
<div class="container py-5">
  <div class="row justify-content-center">
    <div class="col-md-5">
      <div class="card shadow-lg border-0 rounded-4 glass">
        <div class="card-body p-4">
          <div class="d-flex justify-content-between align-items-center">
            <h1 class="h4 fw-bold mb-3">Admin Panel Gate</h1>
            <form method="post" action="?route=gate_submit" class="d-flex align-items-center">
              <input type="hidden" name="toggle_theme" value="1">
              <button class="btn btn-sm btn-outline-light" title="Toggle theme">🌓</button>
            </form>
          </div>
          <p class="text-secondary">Enter panel password to continue.</p>
HTML;
    if ($err) echo '<div class="alert alert-danger">'.$err.'</div>';
    echo <<<HTML
          <form method="post" action="?route=gate_submit">
            <div class="mb-3">
              <label class="form-label">Password</label>
              <input name="panel_pass" type="password" class="form-control form-control-lg" placeholder="Enter gate password" required>
            </div>
            <button class="btn btn-primary btn-lg w-100">Enter</button>
          </form>
          <p class="small text-muted mt-3 mb-0">Hint: Provided by owner.</p>
        </div>
      </div>
    </div>
  </div>
</div>
</body></html>
HTML;
}
function handle_gate_submit(): void {
    if (isset($_POST['toggle_theme'])) {
        toggle_theme();
        render_gate();
        return;
    }
    $p = $_POST['panel_pass'] ?? '';
    if ($p === PANEL_PASS) {
        $_SESSION['panel_ok'] = true;
        header('Location: ?route=login');
        exit;
    }
    render_gate("Wrong password.");
}

/* =========================
   AUTH
========================= */
function require_auth(): void { if (!isset($_SESSION['admin_id'])) { header("Location:?route=login"); exit; } }
function current_admin(PDO $db): ?array {
    if (!isset($_SESSION['admin_id'])) return null;
    $st=$db->prepare("SELECT id, username FROM admins WHERE id=?");
    $st->execute([$_SESSION['admin_id']]);
    $r=$st->fetch(PDO::FETCH_ASSOC);
    return $r ?: null;
}

function handle_login(PDO $db): void {
    if ($_SERVER['REQUEST_METHOD']==='POST') {
        $u=trim($_POST['username'] ?? ''); $p=trim($_POST['password'] ?? '');
        $st=$db->prepare("SELECT id,password_hash FROM admins WHERE username=?");
        $st->execute([$u]); $row=$st->fetch(PDO::FETCH_ASSOC);
        if ($row && password_verify($p,$row['password_hash'])) {
            $_SESSION['admin_id']=(int)$row['id']; header("Location:?route=dashboard"); exit;
        }
        render_login("Invalid credentials.");
        return;
    }
    render_login();
}
function handle_logout(): void { session_destroy(); header("Location:?route=gate"); exit; }

function render_login(string $err=''): void {
    $theme=theme_css(); $mode=theme_mode();
    echo <<<HTML
<!doctype html><html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Login • Hitek Admin</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<style>{$theme}</style></head>
<body class="bg-gradient {$mode}">
<div class="container py-5"><div class="row justify-content-center"><div class="col-md-5">
<div class="card shadow-lg border-0 rounded-4 glass"><div class="card-body p-4">
<div class="d-flex justify-content-between align-items-center">
  <h1 class="h4 fw-bold mb-3">Hitek API Admin</h1>
  <form method="post" action="?route=gate_submit" class="d-flex align-items-center">
    <input type="hidden" name="toggle_theme" value="1"><button class="btn btn-sm btn-outline-light">🌓</button>
  </form>
</div>
<p class="text-secondary">Sign in to manage your APIs.</p>
HTML;
    if ($err) echo '<div class="alert alert-danger">'.$err.'</div>';
    echo <<<HTML
<form method="post">
  <div class="mb-3"><label class="form-label">Username</label>
  <input name="username" class="form-control form-control-lg" required></div>
  <div class="mb-3"><label class="form-label">Password</label>
  <input name="password" type="password" class="form-control form-control-lg" required></div>
  <button class="btn btn-primary btn-lg w-100">Login</button>
</form>
<p class="small text-muted mt-3 mb-0">Default: <code>admin / admin123</code></p>
</div></div></div></div></div>
</body></html>
HTML;
}

/* =========================
   THEME
========================= */
function theme_mode(): string { return $_SESSION['theme'] ?? 'dark'; }
function toggle_theme(): void { $_SESSION['theme'] = (theme_mode()==='dark') ? 'light' : 'dark'; }
function theme_css(): string {
return <<<CSS
:root{--g1:#1f2235;--g2:#3b1d60;--glass:rgba(255,255,255,.08)}
.light:root, .light {--g1:#e9eef7;--g2:#bfd1ff;--glass:rgba(0,0,0,.06)}
.bg-gradient{min-height:100vh;background:
radial-gradient(1000px 600px at -10% -20%, #8247ff33, transparent 60%),
radial-gradient(800px 500px at 120% 120%, #00e1ff22, transparent 60%),
linear-gradient(135deg, var(--g1), var(--g2));}
.glass{background:var(--glass);backdrop-filter: blur(10px)}
.glass-strong{background:rgba(255,255,255,.12);backdrop-filter: blur(16px)}
.table td,.table th{vertical-align:middle}
.badge-mono{background:#222;color:#ddd;border:1px solid #444}
.light .badge-mono{background:#fff;color:#333;border:1px solid #ddd}
CSS;
}

/* =========================
   DASHBOARD + CREATE/UPDATE
========================= */
function render_dashboard(PDO $db): void {
    $admin=current_admin($db);
    $apis=$db->query("SELECT * FROM apis ORDER BY id DESC")->fetchAll(PDO::FETCH_ASSOC) ?: [];
    $base=guess_base_url(); $theme=theme_css(); $mode=theme_mode();
    // analytics
    $stats = [
        'hits'  => (int)$db->query("SELECT COUNT(*) FROM hits WHERE ok=1")->fetchColumn(),
        'miss'  => (int)$db->query("SELECT COUNT(*) FROM hits WHERE ok=0")->fetchColumn(),
        'total' => (int)$db->query("SELECT COUNT(*) FROM hits")->fetchColumn()
    ];
    $top = $db->query("SELECT number, COUNT(*) c FROM hits WHERE number IS NOT NULL AND number<>'' GROUP BY number ORDER BY c DESC LIMIT 5")->fetchAll(PDO::FETCH_ASSOC);

    echo <<<HTML
<!doctype html><html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Dashboard • Hitek</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<style>{$theme}</style></head>
<body class="bg-gradient {$mode}">
<nav class="navbar navbar-expand-lg navbar-dark glass px-3">
  <a class="navbar-brand fw-bold" href="?route=dashboard">Hitek API Admin</a>
  <div class="ms-auto d-flex align-items-center gap-2">
    <a class="btn btn-outline-light btn-sm" href="?route=logs">Logs</a>
    <a class="btn btn-outline-light btn-sm" href="?route=export_csv">Export CSV</a>
    <a class="btn btn-outline-light btn-sm" href="?route=health">Health</a>
    <form method="post" action="?route=gate_submit"><input type="hidden" name="toggle_theme" value="1"><button class="btn btn-outline-light btn-sm">🌓</button></form>
    <span class="badge bg-light text-dark">Signed in as {$admin['username']}</span>
    <a class="btn btn-outline-light" href="?route=logout">Logout</a>
  </div>
</nav>

<div class="container py-4">
  <div class="row g-4">
    <div class="col-lg-5">
      <div class="card shadow-sm border-0 rounded-4 glass-strong">
        <div class="card-body">
          <h2 class="h5 fw-bold mb-3">Create a new API</h2>
          <form method="post" action="?route=create_api">
            <div class="mb-3"><label class="form-label">Label</label>
              <input name="label" class="form-control" placeholder="e.g., Customer Lookup API"></div>
            <div class="mb-3"><label class="form-label">Slug (optional)</label>
              <input name="slug" class="form-control" placeholder="letters-numbers-dashes">
              <div class="form-text">Leave blank to auto-generate (3–40 chars).</div>
            </div>

            <h6 class="mt-2">1) Data Source URL</h6>
            <div class="form-text mb-2">Must be unique if provided (or leave blank to use global default).</div>
            <input name="data_url" class="form-control" placeholder="https://example.com/data.json">

            <div class="row mt-3">
              <div class="col-6"><label class="form-label">Match Mode</label>
                <select class="form-select" name="match_mode">
                  <option value="exact" selected>Exact</option>
                  <option value="contains">Contains</option>
                </select></div>
              <div class="col-6"><label class="form-label">CORS</label>
                <select class="form-select" name="cors_enabled">
                  <option value="0" selected>Disabled</option>
                  <option value="1">Enabled</option>
                </select></div>
            </div>

            <div class="mt-3"><label class="form-label">Search fields (optional)</label>
              <input name="search_fields" class="form-control" placeholder="JSON keys or CSV columns, comma-separated">
            </div>

            <div class="mt-3"><label class="form-label">Custom Not Found message</label>
              <input name="notfound_text" class="form-control" placeholder="e.g., Not Found">
            </div>

            <div class="row mt-3">
              <div class="col-6"><label class="form-label">Rate limit (req/min)</label>
                <input name="rl" type="number" min="1" max="1000" value="60" class="form-control">
              </div>
              <div class="col-6"><label class="form-label">Rate window (seconds)</label>
                <input name="rlw" type="number" min="10" max="3600" value="60" class="form-control">
              </div>
            </div>

            <div class="row mt-3">
              <div class="col-6"><label class="form-label">Cache TTL (seconds)</label>
                <input name="ttl" type="number" min="30" max="3600" value="300" class="form-control">
              </div>
              <div class="col-6"><label class="form-label">Webhook URL (optional)</label>
                <input name="webhook_url" class="form-control" placeholder="https://example.com/hook">
              </div>
            </div>

            <div class="mt-3"><label class="form-label">Allow IPs (CSV)</label>
              <input name="allow_ips" class="form-control" placeholder="1.2.3.4,5.6.7.8">
            </div>
            <div class="mt-3"><label class="form-label">Deny IPs (CSV)</label>
              <input name="deny_ips" class="form-control" placeholder="9.9.9.9,10.0.0.1">
            </div>

            <h6 class="mt-3">2) API Key (optional)</h6>
            <div class="form-check form-switch mb-2">
              <input class="form-check-input" type="checkbox" role="switch" id="rqk" name="require_key" value="1">
              <label class="form-check-label" for="rqk">Require API Key</label>
            </div>
            <input name="api_key" class="form-control" placeholder="Enter key (or leave blank to auto-generate)">

            <button class="btn btn-primary mt-3">Create API</button>
          </form>
          <hr class="my-4">
          <p class="small text-muted mb-0">
            Public endpoint: <code>{$base}?route=api&amp;slug=&lt;SLUG&gt;&amp;number=&lt;NUMBER&gt;&amp;key=&lt;API_KEY?&gt;</code><br>
            Add <code>&pretty=1</code> for pretty JSON.
          </p>
        </div>
      </div>
    </div>

    <div class="col-lg-7">
      <div class="card shadow-sm border-0 rounded-4 glass-strong">
        <div class="card-body">
          <h2 class="h5 fw-bold mb-3">Your APIs</h2>
          <div class="row g-3 mb-3">
            <div class="col">
              <div class="p-3 rounded glass text-center">
                <div class="h5 mb-0">{$stats['total']}</div>
                <div class="small text-muted">Total requests</div>
              </div>
            </div>
            <div class="col">
              <div class="p-3 rounded glass text-center">
                <div class="h5 mb-0">{$stats['hits']}</div>
                <div class="small text-muted">Hits</div>
              </div>
            </div>
            <div class="col">
              <div class="p-3 rounded glass text-center">
                <div class="h5 mb-0">{$stats['miss']}</div>
                <div class="small text-muted">Misses</div>
              </div>
            </div>
            <div class="col-12">
              <div class="p-3 rounded glass">
                <div class="small text-muted mb-1">Top numbers</div>
                <div class="d-flex flex-wrap gap-2">
HTML;
    foreach ($top as $t) {
        $n = htmlspecialchars((string)$t['number']); $c=(int)$t['c'];
        echo "<span class='badge badge-mono'>{$n}: {$c}</span>";
    }
    echo <<<HTML
                </div>
              </div>
            </div>
          </div>
HTML;

    if (!$apis) {
        echo '<div class="alert alert-info">No APIs yet. Create one on the left.</div>';
    } else {
        echo '<div class="table-responsive"><table class="table table-sm align-middle"><thead>
              <tr><th>#</th><th>Label</th><th>Slug</th><th>Data URL</th><th>Key?</th><th>Mode</th><th>Status</th><th>Actions</th></tr>
              </thead><tbody>';
        $i=1; $base=guess_base_url();
        foreach ($apis as $api) {
            $status = $api['enabled'] ? '<span class="badge bg-success">Enabled</span>' : '<span class="badge bg-secondary">Disabled</span>';
            $keyb   = $api['require_key'] ? '<span class="badge bg-warning text-dark">Required</span>' : '<span class="badge bg-light text-dark">No</span>';
            $url    = htmlspecialchars($api['data_url'] ?: GLOBAL_DEFAULT_DATA_URL);
            $slug   = htmlspecialchars($api['slug']);
            $example = $base.'?route=api&slug='.urlencode($api['slug']).'&number=987654'.($api['require_key']?'&key='.urlencode((string)$api['api_key']):'');
            $mode = htmlspecialchars($api['match_mode']);
            echo "<tr>
              <td>{$i}</td>
              <td>".htmlspecialchars($api['label'] ?? '')."</td>
              <td><code>{$slug}</code></td>
              <td><div class='text-truncate' style='max-width:220px'><code>{$url}</code></div></td>
              <td>{$keyb}</td>
              <td><span class='badge badge-mono'>{$mode}</span></td>
              <td>{$status}</td>
              <td>
                <div class='d-flex flex-wrap gap-1'>
                  <a class='btn btn-sm btn-outline-primary' target='_blank' href='".htmlspecialchars($example)."'>Test</a>
                  <a class='btn btn-sm btn-outline-info' href='?route=logs&api_id={$api['id']}'>Logs</a>
                  <a class='btn btn-sm btn-outline-secondary' href='?route=health&api_id={$api['id']}'>Health</a>
                  <a class='btn btn-sm btn-outline-warning' href='?route=toggle_api&id={$api['id']}'>".($api['enabled']?'Disable':'Enable')."</a>
                  <a class='btn btn-sm btn-outline-danger' href='?route=delete_api&id={$api['id']}' onclick='return confirm(\"Delete this API?\")'>Delete</a>
                  <button class='btn btn-sm btn-outline-light' data-bs-toggle='collapse' data-bs-target='#e{$api['id']}'>Edit</button>
                </div>
              </td>
            </tr>
            <tr class='collapse' id='e{$api['id']}'><td colspan='8'>
              <form class='border rounded p-3' method='post' action='?route=update_api'>
                <input type='hidden' name='id' value='{$api['id']}'>
                <div class='row g-2'>
                  <div class='col-md-3'><label class='form-label'>Label</label>
                    <input class='form-control' name='label' value='".htmlspecialchars($api['label'] ?? '')."'></div>
                  <div class='col-md-3'><label class='form-label'>Slug</label>
                    <input class='form-control' name='slug' value='{$slug}'></div>
                  <div class='col-md-6'><label class='form-label'>Data URL (unique)</label>
                    <input class='form-control' name='data_url' value='{$url}'></div>
                  <div class='col-md-3'><label class='form-label'>Match</label>
                    <select class='form-select' name='match_mode'>
                      <option ".($api['match_mode']=='exact'?'selected':'')." value='exact'>Exact</option>
                      <option ".($api['match_mode']=='contains'?'selected':'')." value='contains'>Contains</option>
                    </select></div>
                  <div class='col-md-3'><label class='form-label'>CORS</label>
                    <select class='form-select' name='cors_enabled'>
                      <option ".(!$api['cors_enabled']?'selected':'')." value='0'>Disabled</option>
                      <option ".($api['cors_enabled']?'selected':'')." value='1'>Enabled</option>
                    </select></div>
                  <div class='col-md-3'><label class='form-label'>API Key</label>
                    <input class='form-control' name='api_key' value='".htmlspecialchars((string)$api['api_key'])."'></div>
                  <div class='col-md-3'><label class='form-label'>Require Key</label>
                    <select class='form-select' name='require_key'>
                      <option ".(!$api['require_key']?'selected':'')." value='0'>No</option>
                      <option ".($api['require_key']?'selected':'')." value='1'>Yes</option>
                    </select></div>
                  <div class='col-md-6'><label class='form-label'>Search fields</label>
                    <input class='form-control' name='search_fields' value='".htmlspecialchars((string)$api['search_fields'])."'></div>
                  <div class='col-md-6'><label class='form-label'>Not Found text</label>
                    <input class='form-control' name='notfound_text' value='".htmlspecialchars((string)$api['notfound_text'])."'></div>
                  <div class='col-md-6'><label class='form-label'>Allow IPs</label>
                    <input class='form-control' name='allow_ips' value='".htmlspecialchars((string)$api['allow_ips'])."'></div>
                  <div class='col-md-6'><label class='form-label'>Deny IPs</label>
                    <input class='form-control' name='deny_ips' value='".htmlspecialchars((string)$api['deny_ips'])."'></div>
                  <div class='col-md-8'><label class='form-label'>Webhook URL</label>
                    <input class='form-control' name='webhook_url' value='".htmlspecialchars((string)$api['webhook_url'])."'></div>
                </div>
                <div class='mt-2 d-flex gap-2'>
                  <button class='btn btn-sm btn-primary'>Save</button>
                  <a class='btn btn-sm btn-outline-warning' href='?route=regen_key&id={$api['id']}'>Regenerate Key</a>
                </div>
              </form>
            </td></tr>";
            $i++;
        }
        echo '</tbody></table></div>';
    }

    echo <<<HTML
        </div>
      </div>
    </div>
  </div>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body></html>
HTML;
}

/* CREATE / UPDATE / DELETE / KEY  */
function rand_key(int $len=32): string { $a='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'; $o=''; for($i=0;$i<$len;$i++) $o.=$a[random_int(0,strlen($a)-1)]; return $o; }
function gen_slug(): string { $a='abcdefghijklmnopqrstuvwxyz0123456789'; $o=''; for($i=0;$i<10;$i++) $o.=$a[random_int(0,strlen($a)-1)]; return $o; }
function save_sidecar(string $slug, array $data): void { file_put_contents(__DIR__."/{$slug}.cfg.json", json_encode($data)); }
function load_sidecar(string $slug): array {
    $p=__DIR__."/{$slug}.cfg.json"; if(!file_exists($p)) return ['rl'=>RL_MAX_HITS_DEF,'ttl'=>GLOBAL_CACHE_TTL_SEC,'rlw'=>RL_WINDOW_SECONDS_DEF];
    $j=json_decode(file_get_contents($p),true); if(!is_array($j)) $j=[];
    $j+=['rl'=>RL_MAX_HITS_DEF,'ttl'=>GLOBAL_CACHE_TTL_SEC,'rlw'=>RL_WINDOW_SECONDS_DEF];
    return $j;
}

function handle_create_api(PDO $db): void {
    $label=trim($_POST['label'] ?? ''); $slug=trim($_POST['slug'] ?? '');
    $data_url=trim($_POST['data_url'] ?? ''); $match_mode=(($_POST['match_mode'] ?? 'exact')==='contains')?'contains':'exact';
    $cors_enabled=(int)($_POST['cors_enabled'] ?? 0) ? 1 : 0;
    $search_fields=trim($_POST['search_fields'] ?? ''); $notfound=trim($_POST['notfound_text'] ?? 'Not Found');
    $allow_ips=trim($_POST['allow_ips'] ?? ''); $deny_ips=trim($_POST['deny_ips'] ?? '');
    $webhook_url=trim($_POST['webhook_url'] ?? '');
    $require_key=(int)($_POST['require_key'] ?? 0) ? 1 : 0; $api_key_in=trim($_POST['api_key'] ?? ''); $api_key=$require_key ? ($api_key_in ?: rand_key()) : null;
    $rl=(int)($_POST['rl'] ?? RL_MAX_HITS_DEF); $ttl=(int)($_POST['ttl'] ?? GLOBAL_CACHE_TTL_SEC); $rlw=(int)($_POST['rlw'] ?? RL_WINDOW_SECONDS_DEF);

    if ($slug==='') $slug=gen_slug();
    if (!preg_match('~^[a-zA-Z0-9-]{3,40}$~',$slug)) toast_and_redirect("Invalid slug.","dashboard");
    if ($data_url!=='' && !filter_var($data_url,FILTER_VALIDATE_URL)) toast_and_redirect("Invalid Data URL.","dashboard");
    if ($data_url!==''){ $st=$db->prepare("SELECT COUNT(*) FROM apis WHERE data_url=?"); $st->execute([$data_url]); if((int)$st->fetchColumn()>0) toast_and_redirect("Data URL already used.","dashboard"); }

    $admin=current_admin($db);
    $st=$db->prepare("INSERT INTO apis (slug,label,data_url,require_key,api_key,match_mode,cors_enabled,notfound_text,search_fields,allow_ips,deny_ips,webhook_url,enabled,created_by,created_at,updated_at)
                      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,1,?,?,?)");
    $st->execute([$slug,$label?:null,$data_url?:null,$require_key,$api_key,$match_mode,$cors_enabled,$notfound?:'Not Found',$search_fields?:null,$allow_ips?:null,$deny_ips?:null,$webhook_url?:null,$admin['id'],date('c'),date('c')]);
    save_sidecar($slug,['rl'=>$rl,'ttl'=>$ttl,'rlw'=>$rlw]);
    toast_and_redirect("API created: {$slug}","dashboard");
}
function handle_update_api(PDO $db): void {
    $id=(int)($_POST['id'] ?? 0); if($id<=0) toast_and_redirect("Invalid ID","dashboard");
    $st=$db->prepare("SELECT * FROM apis WHERE id=?"); $st->execute([$id]); $api=$st->fetch(PDO::FETCH_ASSOC); if(!$api) toast_and_redirect("API not found","dashboard");

    $label=trim($_POST['label'] ?? ''); $slug=trim($_POST['slug'] ?? '');
    $data_url=trim($_POST['data_url'] ?? ''); $match_mode=(($_POST['match_mode'] ?? 'exact')==='contains')?'contains':'exact';
    $cors_enabled=(int)($_POST['cors_enabled'] ?? 0) ? 1 : 0;
    $api_key=trim($_POST['api_key'] ?? ''); $require_key=(int)($_POST['require_key'] ?? 0) ? 1 : 0;
    $search_fields=trim($_POST['search_fields'] ?? ''); $notfound=trim($_POST['notfound_text'] ?? 'Not Found');
    $allow_ips=trim($_POST['allow_ips'] ?? ''); $deny_ips=trim($_POST['deny_ips'] ?? ''); $webhook_url=trim($_POST['webhook_url'] ?? '');

    if (!preg_match('~^[a-zA-Z0-9-]{3,40}$~',$slug)) toast_and_redirect("Invalid slug.","dashboard");
    if ($data_url!=='' && !filter_var($data_url,FILTER_VALIDATE_URL)) toast_and_redirect("Invalid Data URL.","dashboard");
    if ($data_url!=='' && $data_url!== (string)$api['data_url']) {
        $st=$db->prepare("SELECT COUNT(*) FROM apis WHERE data_url=?"); $st->execute([$data_url]);
        if((int)$st->fetchColumn()>0) toast_and_redirect("Data URL already used.","dashboard");
    }
    if ($slug !== (string)$api['slug']) {
        $st=$db->prepare("SELECT COUNT(*) FROM apis WHERE slug=?"); $st->execute([$slug]); if((int)$st->fetchColumn()>0) toast_and_redirect("Slug exists.","dashboard");
    }
    if ($require_key && $api_key==='') $api_key=rand_key();
    if (!$require_key) $api_key=null;

    $st=$db->prepare("UPDATE apis SET slug=?,label=?,data_url=?,require_key=?,api_key=?,match_mode=?,cors_enabled=?,notfound_text=?,search_fields=?,allow_ips=?,deny_ips=?,webhook_url=?,updated_at=? WHERE id=?");
    $st->execute([$slug,$label?:null,$data_url?:null,$require_key,$api_key,$match_mode,$cors_enabled,$notfound?:'Not Found',$search_fields?:null,$allow_ips?:null,$deny_ips?:null,$webhook_url?:null,date('c'),$id]);

    // cache invalidate if slug or url changed
    if ($slug !== (string)$api['slug']) { $old=cache_file_for_slug($api['slug']); if(file_exists($old)) @unlink($old); }
    if (($data_url?:null) !== ($api['data_url']?:null)) { $cf=cache_file_for_slug($slug); if(file_exists($cf)) @unlink($cf); }

    toast_and_redirect("API updated.","dashboard");
}
function handle_toggle_api(PDO $db): void {
    $id=(int)($_GET['id'] ?? 0); if($id<=0) toast_and_redirect("Invalid ID","dashboard");
    $db->prepare("UPDATE apis SET enabled=CASE WHEN enabled=1 THEN 0 ELSE 1 END, updated_at=? WHERE id=?")->execute([date('c'),$id]);
    toast_and_redirect("Toggled.","dashboard");
}
function handle_delete_api(PDO $db): void {
    $id=(int)($_GET['id'] ?? 0); if($id<=0) toast_and_redirect("Invalid ID","dashboard");
    $st=$db->prepare("SELECT slug FROM apis WHERE id=?"); $st->execute([$id]); $slug=$st->fetchColumn();
    if($slug){ $cf=cache_file_for_slug($slug); if(file_exists($cf)) @unlink($cf); $db->prepare("DELETE FROM hits WHERE api_id=?")->execute([$id]); $db->prepare("DELETE FROM apis WHERE id=?")->execute([$id]); }
    toast_and_redirect("API deleted.","dashboard");
}
function handle_regen_key(PDO $db): void {
    $id=(int)($_GET['id'] ?? 0); if($id<=0) toast_and_redirect("Invalid ID","dashboard");
    $key=rand_key(); $db->prepare("UPDATE apis SET api_key=?, require_key=1, updated_at=? WHERE id=?")->execute([$key,date('c'),$id]);
    toast_and_redirect("Key regenerated.","dashboard");
}

/* =========================
   LOGS + CSV EXPORT + HEALTH
========================= */
function render_logs(PDO $db): void {
    $api_id = isset($_GET['api_id']) ? (int)$_GET['api_id'] : null;
    $theme=theme_css(); $mode=theme_mode();
    $api = null;
    if ($api_id) { $st=$db->prepare("SELECT label,slug FROM apis WHERE id=?"); $st->execute([$api_id]); $api=$st->fetch(PDO::FETCH_ASSOC); }
    if ($api_id) { $st=$db->prepare("SELECT * FROM hits WHERE api_id=? ORDER BY id DESC LIMIT 200"); $st->execute([$api_id]); $rows=$st->fetchAll(PDO::FETCH_ASSOC); }
    else { $rows=$db->query("SELECT h.*, a.slug FROM hits h JOIN apis a ON a.id=h.api_id ORDER BY h.id DESC LIMIT 200")->fetchAll(PDO::FETCH_ASSOC); }

    echo <<<HTML
<!doctype html><html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Logs • Hitek</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<style>{$theme}</style></head>
<body class="bg-gradient {$mode}">
<nav class="navbar navbar-dark glass px-3">
  <a class="navbar-brand fw-bold" href="?route=dashboard">Hitek Admin</a>
  <div class="ms-auto">
    <a class="btn btn-outline-light btn-sm" href="?route=export_csv">Export CSV (All)</a>
HTML;
    if ($api_id) echo " <a class='btn btn-outline-light btn-sm' href='?route=export_csv&api_id={$api_id}'>Export CSV (This API)</a>";
    echo <<<HTML
    <a class="btn btn-outline-light btn-sm" href="?route=dashboard">Back</a>
  </div>
</nav>
<div class="container py-4">
  <div class="card glass-strong border-0 rounded-4"><div class="card-body">
    <h2 class="h5 fw-bold mb-3">Logs {$api_id ? '• '.htmlspecialchars($api['label'] ?: $api['slug']) : ''}</h2>
    <div class="table-responsive"><table class="table table-sm align-middle">
      <thead><tr><th>#</th><th>API</th><th>IP</th><th>Number</th><th>OK</th><th>Time</th><th>UA</th></tr></thead><tbody>
HTML;
    $i=1;
    foreach ($rows as $r) {
        $ok = $r['ok'] ? '<span class="badge bg-success">Hit</span>' : '<span class="badge bg-danger">Miss</span>';
        $slug = isset($r['slug']) ? htmlspecialchars($r['slug']) : '';
        echo "<tr><td>{$i}</td><td>".($slug ?: $r['api_id'])."</td><td>".htmlspecialchars($r['ip'])."</td><td>".htmlspecialchars((string)$r['number'])."</td><td>{$ok}</td><td>".date('Y-m-d H:i:s',(int)$r['ts'])."</td><td><div class='text-truncate' style='max-width:420px'>".htmlspecialchars((string)$r['ua'])."</div></td></tr>";
        $i++;
    }
    echo <<<HTML
      </tbody></table></div>
  </div></div>
</div>
</body></html>
HTML;
}
function export_logs_csv(PDO $db): void {
    $api_id = isset($_GET['api_id']) ? (int)$_GET['api_id'] : null;
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="hitek_logs'.($api_id?('_api'.$api_id):'').'.csv"');
    $out = fopen('php://output','w');
    fputcsv($out, ['id','api_id','ip','number','ok','ts','ua']);
    if ($api_id) { $st=$db->prepare("SELECT id,api_id,ip,number,ok,ts,ua FROM hits WHERE api_id=? ORDER BY id DESC"); $st->execute([$api_id]); }
    else { $st=$db->query("SELECT id,api_id,ip,number,ok,ts,ua FROM hits ORDER BY id DESC"); }
    while($r=$st->fetch(PDO::FETCH_NUM)){ fputcsv($out,$r); }
    fclose($out); exit;
}
function render_health(PDO $db): void {
    $theme=theme_css(); $mode=theme_mode();
    $apis=$db->query("SELECT id,slug,data_url,label FROM apis ORDER BY id DESC")->fetchAll(PDO::FETCH_ASSOC) ?: [];
    echo <<<HTML
<!doctype html><html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Health • Hitek</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<style>{$theme}</style></head>
<body class="bg-gradient {$mode}">
<nav class="navbar navbar-dark glass px-3">
  <a class="navbar-brand fw-bold" href="?route=dashboard">Hitek Admin</a>
</nav>
<div class="container py-4">
  <div class="card glass-strong border-0 rounded-4"><div class="card-body">
    <h2 class="h5 fw-bold mb-3">Health Check</h2>
    <div class="table-responsive"><table class="table table-sm">
      <thead><tr><th>#</th><th>API</th><th>Slug</th><th>URL</th><th>Status</th><th>Size</th></tr></thead><tbody>
HTML;
    $i=1;
    foreach ($apis as $a) {
        $url = $a['data_url'] ?: GLOBAL_DEFAULT_DATA_URL;
        $status = '—'; $size='—';
        try {
            $payload = curl_get($url);
            if ($payload !== false && $payload!=='') { $status = '<span class="badge bg-success">OK</span>'; $size = number_format(strlen($payload)).' bytes'; }
            else { $status = '<span class="badge bg-danger">FAIL</span>'; }
        } catch(Throwable $e){ $status = '<span class="badge bg-danger">FAIL</span>'; }
        echo "<tr><td>{$i}</td><td>".htmlspecialchars($a['label'] ?: '')."</td><td><code>".htmlspecialchars($a['slug'])."</code></td><td class='text-truncate' style='max-width:260px'><code>".htmlspecialchars($url)."</code></td><td>{$status}</td><td>{$size}</td></tr>";
        $i++;
    }
    echo <<<HTML
      </tbody></table></div>
  </div></div>
</div>
</body></html>
HTML;
}

/* =========================
   PUBLIC API
========================= */
function handle_public_api(PDO $db): void {
    // CORS preflight quick exit
    if ($_SERVER['REQUEST_METHOD']==='OPTIONS') {
        header('Access-Control-Allow-Origin:*');
        header('Access-Control-Allow-Headers: Content-Type, X-API-Key');
        header('Access-Control-Allow-Methods: GET, OPTIONS');
        exit;
    }
    $slug=trim($_GET['slug'] ?? ''); $number=trim($_GET['number'] ?? ''); $key=trim($_GET['key'] ?? '');
    $pretty = isset($_GET['pretty']) ? true : false;
    $ip=$_SERVER['REMOTE_ADDR'] ?? '0.0.0.0'; $ua=$_SERVER['HTTP_USER_AGENT'] ?? '';
    $st=$db->prepare("SELECT * FROM apis WHERE slug=? AND enabled=1"); $st->execute([$slug]); $api=$st->fetch(PDO::FETCH_ASSOC);
    if (!$api || $slug==='' || $number==='') { http_response_code(404); return_json(['status'=>'Not Found'],$pretty); return; }

    // CORS
    if ((int)$api['cors_enabled']) {
        header('Access-Control-Allow-Origin:*');
        header('Access-Control-Allow-Headers: Content-Type, X-API-Key');
        header('Access-Control-Allow-Methods: GET, OPTIONS');
    }

    // IP allow/deny
    if ($api['deny_ips'] && ip_in_list($ip, $api['deny_ips'])) { http_response_code(403); return_json(['status'=>'error','message'=>'IP denied'],$pretty); return; }
    if ($api['allow_ips'] && !ip_in_list($ip, $api['allow_ips'])) { http_response_code(403); return_json(['status'=>'error','message'=>'IP not allowed'],$pretty); return; }

    // API key
    $hdr_key = $_SERVER['HTTP_X_API_KEY'] ?? '';
    $present_key = $key !== '' ? $key : $hdr_key;
    if ((int)$api['require_key']) {
        if ($present_key==='' || $present_key !== (string)$api['api_key']) { http_response_code(401); return_json(['status'=>'error','message'=>'Invalid or missing API key'],$pretty); return; }
    }

    // Rate limit
    $cfg = load_sidecar($api['slug']); $rl=(int)$cfg['rl']; $rlw=(int)$cfg['rlw']; if($rl<=0) $rl=RL_MAX_HITS_DEF; if($rlw<=0) $rlw=RL_WINDOW_SECONDS_DEF;
    if (!rate_limit_ok($db,(int)$api['id'],$ip,$rl,$rlw)) { http_response_code(429); return_json(['status'=>'error','message'=>'Too Many Requests'],$pretty); return; }

    // Fetch data
    $data_url = $api['data_url'] ?: GLOBAL_DEFAULT_DATA_URL; $cache_file=cache_file_for_slug($api['slug']); $ttl = max(30,(int)$cfg['ttl']);
    try { $payload = fetch_remote_with_cache($data_url,$cache_file,$ttl); }
    catch(Throwable $e){ log_hit($db,(int)$api['id'],$ip,$number,0,$ua); webhook_post($api,false,$number,$ip); http_response_code(502); return_json(['status'=>'error','message'=>'Upstream fetch failed'],$pretty); return; }

    // Search
    $match = scan_payload_for_number($payload,$number,(string)$api['match_mode'], (string)$api['search_fields']);
    if ($match === null) {
        log_hit($db,(int)$api['id'],$ip,$number,0,$ua); webhook_post($api,false,$number,$ip);
        http_response_code(404);
        return_json(['status'=> ($api['notfound_text'] ?: 'Not Found') ],$pretty); return;
    }

    log_hit($db,(int)$api['id'],$ip,$number,1,$ua); webhook_post($api,true,$number,$ip);
    http_response_code(200);
    return_json([
        'status'=>'ok',
        'match'=>$match,
        'source'=>$data_url,
        'cached'=> file_exists($cache_file) ? (time()-filemtime($cache_file) < $ttl) : false,
        'fetched'=> file_exists($cache_file) ? date('c', filemtime($cache_file)) : null,
    ],$pretty);
}
function return_json(array $obj, bool $pretty=false): void {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($obj, $pretty ? (JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT) : JSON_UNESCAPED_UNICODE);
}

/* rate limit + logs + webhook */
function rate_limit_ok(PDO $db, int $api_id, string $ip, int $limit, int $window): bool {
    $now=time();
    $st=$db->prepare("SELECT COUNT(*) FROM hits WHERE api_id=? AND ip=? AND ts>=?");
    $st->execute([$api_id,$ip,$now-$window]);
    return ((int)$st->fetchColumn() < $limit);
}
function log_hit(PDO $db, int $api_id, string $ip, string $number, int $ok, string $ua): void {
    $db->prepare("INSERT INTO hits (api_id, ip, number, ok, ts, ua) VALUES (?,?,?,?,?,?)")->execute([$api_id,$ip,$number,$ok,time(),substr($ua,0,500)]);
}
function webhook_post(array $api, bool $ok, string $number, string $ip): void {
    if (empty($api['webhook_url'])) return;
    $url=(string)$api['webhook_url'];
    $ch=curl_init($url);
    $payload=json_encode([
        'slug'=>$api['slug'],'ok'=>$ok,'number'=>$number,'ip'=>$ip,'ts'=>time()
    ]);
    curl_setopt_array($ch,[
        CURLOPT_POST=>true, CURLOPT_POSTFIELDS=>$payload,
        CURLOPT_HTTPHEADER=>['Content-Type: application/json'],
        CURLOPT_RETURNTRANSFER=>true, CURLOPT_TIMEOUT_MS=>700
    ]);
    curl_exec($ch); curl_close($ch);
}

/* =========================
   FETCH + CACHE
========================= */
function cache_file_for_slug(string $slug): string { return CACHE_DIR . "/{$slug}.bin"; }
function fetch_remote_with_cache(string $url,string $path,int $ttl): string {
    $use_cache = file_exists($path) && (time()-filemtime($path))<$ttl;
    if ($use_cache) return file_get_contents($path);
    $data=curl_get($url); if($data===false || $data==='') throw new RuntimeException("Empty upstream");
    file_put_contents($path,$data); return $data;
}
function curl_get(string $url): string|false {
    $ch=curl_init($url);
    curl_setopt_array($ch,[
        CURLOPT_RETURNTRANSFER=>true, CURLOPT_FOLLOWLOCATION=>true,
        CURLOPT_TIMEOUT=>25, CURLOPT_SSL_VERIFYHOST=>2, CURLOPT_SSL_VERIFYPEER=>true,
        CURLOPT_USERAGENT=>'Hitek-API/3.0'
    ]);
    $res=curl_exec($ch); curl_close($ch); return $res;
}

/* =========================
   SCANNER (with field targeting)
========================= */
function scan_payload_for_number(string $payload,string $number,string $mode='exact', string $fields_csv='') {
    $fields = parse_csv_list($fields_csv); // [] means search all fields
    $trim=ltrim($payload);

    // JSON?
    if ($trim!=='' && ($trim[0]==='{' || $trim[0]==='[')) {
        $json=json_decode($payload,true);
        if (json_last_error()===JSON_ERROR_NONE) {
            $found=json_search($json,$number,$mode,$fields);
            if ($found!==null) return $found;
        }
    }
    // CSV/TSV?
    $firstLine=strtok($payload,"\r\n");
    $delimiter=(substr_count((string)$firstLine,"\t")>substr_count((string)$firstLine,",")) ? "\t" : ",";
    if (substr_count((string)$firstLine,$delimiter)>=1) {
        $rows=csv_parse($payload,$delimiter);
        if ($rows) {
            foreach($rows as $row){
                if (row_matches($row,$number,$mode,$fields)) return $row;
            }
        }
    }
    // Plain text lines
    $lines=preg_split('~\R~',$payload);
    foreach($lines as $line){ if($line==='') continue; if(match_val($line,$number,$mode)) return ['line'=>trim($line)]; }
    return null;
}
function row_matches($row,string $needle,string $mode,array $fields): bool {
    if (!empty($fields) && is_array($row)) {
        foreach($fields as $f){ if(array_key_exists($f,$row) && match_val((string)$row[$f],$needle,$mode)) return true; }
        return false;
    }
    foreach($row as $v){ if(match_val((string)$v,$needle,$mode)) return true; }
    return false;
}
function parse_csv_list(string $s): array {
    if (trim($s)==='') return [];
    $out=array_filter(array_map('trim', explode(',',$s)), fn($x)=>$x!=='');
    return array_values(array_unique($out));
}
function match_val(string $val,string $needle,string $mode): bool {
    return ($mode==='contains') ? (stripos($val,$needle)!==false) : ((string)$val===(string)$needle);
}
function json_search($node,string $needle,string $mode,array $fields) {
    if (is_array($node)) {
        $isAssoc = array_keys($node)!==range(0,count($node)-1);
        if ($isAssoc) {
            if (!empty($fields)) {
                foreach($fields as $f){ if(array_key_exists($f,$node) && is_scalar($node[$f]) && match_val((string)$node[$f],$needle,$mode)) return $node; }
            } else {
                foreach($node as $k=>$v){ if(is_scalar($v) && match_val((string)$v,$needle,$mode)) return $node; }
            }
            foreach($node as $v){ $res=json_search($v,$needle,$mode,$fields); if($res!==null) return $res; }
        } else {
            foreach($node as $item){ $res=json_search($item,$needle,$mode,$fields); if($res!==null) return $res; }
        }
    } elseif (is_scalar($node)) {
        if (match_val((string)$node,$needle,$mode)) return $node;
    }
    return null;
}
function csv_parse(string $text,string $delimiter=','): array {
    $f=fopen('php://memory','r+'); fwrite($f,$text); rewind($f);
    $rows=[]; $headers=null;
    while(($cols=fgetcsv($f,0,$delimiter))!==false){
        if ($headers===null){
            $looksHeader=true; foreach($cols as $c){ if($c===''||is_numeric($c)){$looksHeader=false;break;} }
            if ($looksHeader){ $headers=$cols; continue; }
        }
        if($headers){ $row=[]; foreach($headers as $i=>$h){ $row[$h]=$cols[$i]??null; } $rows[]=$row; }
        else { $rows[]=$cols; }
    }
    fclose($f); return $rows;
}

/* =========================
   HELPERS
========================= */
function ip_in_list(string $ip, string $csv): bool {
    $list=parse_csv_list($csv); return in_array($ip,$list,true);
}
function toast_and_redirect(string $msg,string $route): void { $_SESSION['toast']=$msg; header("Location:?route={$route}"); exit; }
function guess_base_url(): string {
    if (APP_BASE_URL!=='') return APP_BASE_URL;
    $proto = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS']!=='off') ? 'https' : 'http';
    $host  = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $self  = $_SERVER['PHP_SELF'] ?? '/index.php';
    return "{$proto}://{$host}{$self}";
}