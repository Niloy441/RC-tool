const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();

app.use(cors({ origin: '*' }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Path to persistent config file
const CONFIG_FILE = path.join(__dirname, 'config.json');

// Default initial config
let config = {
  baseUrl: 'https://api.2oo9.cloud/MXS47FLFX0U/tnevs/@public/api',
  liveaccessUrl: 'https://api.2oo9.cloud/MXS47FLFX0U/tnevs/@public/api/liveaccess',
  getnumUrl: 'https://api.2oo9.cloud/MXS47FLFX0U/tnevs/@public/api/getnum',
  otpUrl: 'https://api.2oo9.cloud/MXS47FLFX0U/tnevs/@public/api/success-otp',
  consoleUrl: 'https://api.2oo9.cloud/MXS47FLFX0U/tnevs/@public/api/console',
  defaultMauthApiKey: '',
  appEnabled: true,
  appNotice: 'Service Active & Online',
  adminPassword: 'admin',
  fallbackRanges: [
    '22467', '26134', '22809', '23480', '6281',
    '1202', '1204', '1205', '1206', '1207'
  ],
  apiKeys: [] // Stores generated client API keys
};

// Load saved config if available
try {
  if (fs.existsSync(CONFIG_FILE)) {
    const saved = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
    config = { ...config, ...saved };
    if (!Array.isArray(config.apiKeys)) {
      config.apiKeys = [];
    }
  }
} catch (e) {
  console.log('Using in-memory config:', e.message);
}

function saveConfig() {
  try {
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2), 'utf8');
  } catch (e) {
    // Read-only filesystem in serverless environments
  }
}

// In-memory traffic & request log (circular buffer of 150 items)
const trafficLogs = [];
const stats = {
  totalRequests: 0,
  numbersAllocated: 0,
  otpsReceived: 0,
  errors: 0,
  startTime: new Date().toISOString()
};

function logRequest(entry) {
  stats.totalRequests++;
  if (entry.status >= 400) stats.errors++;
  
  trafficLogs.unshift({
    id: Date.now().toString(36) + Math.random().toString(36).substr(2, 4),
    time: new Date().toLocaleTimeString(),
    timestamp: new Date().toISOString(),
    ...entry
  });
  if (trafficLogs.length > 150) {
    trafficLogs.pop();
  }
}

function getClientIp(req) {
  return req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
}

const DEFAULT_UA = 'Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36';

// ---------------------------------------------------------------------
// API Key Generator & Validator Functions
// ---------------------------------------------------------------------
function generateKeyString(prefix = 'RC') {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let randomPart = '';
  for (let i = 0; i < 18; i++) {
    if (i > 0 && i % 6 === 0) randomPart += '-';
    randomPart += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return `${prefix}-${randomPart}`;
}

function validateClientKey(clientKey) {
  // If clientKey is completely empty
  if (!clientKey) {
    // If admin has defined client keys or upstream master key
    if (config.apiKeys && config.apiKeys.length > 0) {
      return { valid: false, statusCode: 401, reason: 'missing mauthapi header' };
    }
    // If no client keys defined and default upstream exists
    if (config.defaultMauthApiKey) {
      return { valid: true, upstreamKey: config.defaultMauthApiKey, keyObj: null };
    }
    return { valid: false, statusCode: 401, reason: 'missing mauthapi header' };
  }

  // 1. Check if clientKey matches server Master Upstream key
  if (config.defaultMauthApiKey && clientKey === config.defaultMauthApiKey) {
    return { valid: true, upstreamKey: config.defaultMauthApiKey, keyObj: null };
  }

  // 2. If no generated keys exist in database yet, pass clientKey directly
  if (!config.apiKeys || config.apiKeys.length === 0) {
    return { valid: true, upstreamKey: clientKey, keyObj: null };
  }

  // 3. Search in generated apiKeys
  const keyObj = config.apiKeys.find(k => k.key.trim() === clientKey.trim());
  if (!keyObj) {
    return { valid: false, statusCode: 401, reason: 'invalid or expired api key' };
  }

  if (!keyObj.enabled) {
    return { valid: false, statusCode: 403, reason: 'api key has been disabled by admin' };
  }

  if (keyObj.expiresAt) {
    const expTime = new Date(keyObj.expiresAt).getTime();
    if (Date.now() > expTime) {
      return { valid: false, statusCode: 401, reason: 'api key has expired' };
    }
  }

  // Valid key: increment usage
  keyObj.usageCount = (keyObj.usageCount || 0) + 1;
  keyObj.lastUsed = new Date().toISOString();
  saveConfig();

  // Use admin master upstream key if provided, else use client key
  const upstreamKey = config.defaultMauthApiKey || clientKey;
  return { valid: true, upstreamKey, keyObj };
}

// ---------------------------------------------------------------------
// 1. App Control & Status Check (Replaces Old Firebase Killswitch)
// ---------------------------------------------------------------------
app.get('/app_control/enabled.json', (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.send(config.appEnabled ? 'true' : 'false');
});

// ---------------------------------------------------------------------
// 2. Dynamic Configuration endpoint (For Android App)
// ---------------------------------------------------------------------
app.get('/api/config', (req, res) => {
  res.json({
    status: 'success',
    enabled: config.appEnabled,
    notice: config.appNotice,
    endpoints: {
      baseUrl: config.baseUrl,
      liveaccess: config.liveaccessUrl,
      getnum: config.getnumUrl,
      otp: config.otpUrl,
      console: config.consoleUrl
    },
    fallbackRanges: config.fallbackRanges
  });
});

// ---------------------------------------------------------------------
// 3. Live Traffic & Range Loader (/liveaccess)
// ---------------------------------------------------------------------
app.get(['/api/liveaccess', '/liveaccess'], async (req, res) => {
  const startTime = Date.now();
  const rawKey = req.headers['mauthapi'] || '';
  const clientIp = getClientIp(req);
  const targetUrl = config.liveaccessUrl || `${config.baseUrl}/liveaccess`;

  // Validate API Key
  const authCheck = validateClientKey(rawKey);
  if (!authCheck.valid) {
    const latency = Date.now() - startTime;
    logRequest({
      endpoint: '/liveaccess',
      method: 'GET',
      ip: clientIp,
      status: authCheck.statusCode,
      latency,
      details: `Auth Failed: ${authCheck.reason} [key: ${rawKey ? rawKey.substr(0, 8) + '...' : 'none'}]`
    });
    return res.status(authCheck.statusCode).json({
      meta: { code: 2941, status: 'unauthorized' },
      data: null,
      message: authCheck.reason,
      rid: 'AUTH_' + Date.now().toString(36)
    });
  }

  const upstreamKey = authCheck.upstreamKey;

  try {
    const upstreamRes = await fetch(targetUrl, {
      method: 'GET',
      headers: {
        'mauthapi': upstreamKey,
        'Accept': 'application/json',
        'User-Agent': DEFAULT_UA
      }
    });

    const latency = Date.now() - startTime;
    const statusCode = upstreamRes.status;
    const textData = await upstreamRes.text();

    let jsonData = null;
    try {
      jsonData = JSON.parse(textData);
    } catch (_) {}

    logRequest({
      endpoint: '/liveaccess',
      method: 'GET',
      ip: clientIp,
      status: statusCode,
      latency,
      details: statusCode === 200 ? 'Ranges loaded successfully' : (jsonData?.message || 'Status ' + statusCode)
    });

    if (statusCode === 200 && jsonData && jsonData.data && jsonData.data.services) {
      return res.status(200).json(jsonData);
    }

    if (jsonData && (jsonData.meta || jsonData.message)) {
      return res.status(statusCode).json(jsonData);
    }

    return res.status(200).json({
      meta: { code: 200, status: 'fallback_active' },
      data: {
        services: [
          {
            sid: 'fb',
            service_name: 'Facebook',
            ranges: config.fallbackRanges.map(r => r.endsWith('XXX') ? r : `${r}XXX`)
          }
        ]
      }
    });

  } catch (err) {
    const latency = Date.now() - startTime;
    logRequest({
      endpoint: '/liveaccess',
      method: 'GET',
      ip: clientIp,
      status: 500,
      latency,
      details: 'Error: ' + err.message
    });

    return res.status(200).json({
      meta: { code: 200, status: 'fallback_active' },
      data: {
        services: [
          {
            sid: 'fb',
            service_name: 'Facebook',
            ranges: config.fallbackRanges.map(r => r.endsWith('XXX') ? r : `${r}XXX`)
          }
        ]
      }
    });
  }
});

// ---------------------------------------------------------------------
// 4. Virtual Number Request (/getnum)
// ---------------------------------------------------------------------
app.post(['/api/getnum', '/getnum'], async (req, res) => {
  const startTime = Date.now();
  const rawKey = req.headers['mauthapi'] || '';
  const clientIp = getClientIp(req);
  const targetUrl = config.getnumUrl || `${config.baseUrl}/getnum`;
  const bodyPayload = req.body || {};

  // Validate API Key
  const authCheck = validateClientKey(rawKey);
  if (!authCheck.valid) {
    const latency = Date.now() - startTime;
    logRequest({
      endpoint: '/getnum',
      method: 'POST',
      ip: clientIp,
      status: authCheck.statusCode,
      latency,
      details: `Auth Failed: ${authCheck.reason} [key: ${rawKey ? rawKey.substr(0, 8) + '...' : 'none'}]`
    });
    return res.status(authCheck.statusCode).json({
      meta: { code: 2941, status: 'unauthorized' },
      data: null,
      message: authCheck.reason,
      rid: 'AUTH_' + Date.now().toString(36)
    });
  }

  const upstreamKey = authCheck.upstreamKey;

  try {
    const upstreamRes = await fetch(targetUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'mauthapi': upstreamKey,
        'Accept': 'application/json',
        'User-Agent': DEFAULT_UA
      },
      body: JSON.stringify(bodyPayload)
    });

    const latency = Date.now() - startTime;
    const statusCode = upstreamRes.status;
    const textData = await upstreamRes.text();

    let jsonData = null;
    try {
      jsonData = JSON.parse(textData);
    } catch (_) {}

    const allocatedNum = jsonData?.data?.no_plus_number || jsonData?.data?.full_number || '';
    if (allocatedNum) stats.numbersAllocated++;

    logRequest({
      endpoint: '/getnum',
      method: 'POST',
      ip: clientIp,
      status: statusCode,
      latency,
      details: allocatedNum ? `Allocated: +${allocatedNum} (rid: ${bodyPayload.rid || '?'})` : (jsonData?.message || 'Status ' + statusCode)
    });

    if (jsonData) {
      return res.status(statusCode).json(jsonData);
    }

    return res.status(statusCode).send(textData);

  } catch (err) {
    const latency = Date.now() - startTime;
    logRequest({
      endpoint: '/getnum',
      method: 'POST',
      ip: clientIp,
      status: 500,
      latency,
      details: 'Error: ' + err.message
    });

    return res.status(500).json({
      meta: { code: 500, status: 'proxy_error' },
      message: 'Failed to connect to getnum endpoint: ' + err.message
    });
  }
});

// ---------------------------------------------------------------------
// 5. OTP Check Endpoint (/success-otp)
// ---------------------------------------------------------------------
app.get(['/api/success-otp', '/success-otp'], async (req, res) => {
  const startTime = Date.now();
  const rawKey = req.headers['mauthapi'] || '';
  const clientIp = getClientIp(req);
  const targetUrl = config.otpUrl || `${config.baseUrl}/success-otp`;

  // Validate API Key
  const authCheck = validateClientKey(rawKey);
  if (!authCheck.valid) {
    const latency = Date.now() - startTime;
    logRequest({
      endpoint: '/success-otp',
      method: 'GET',
      ip: clientIp,
      status: authCheck.statusCode,
      latency,
      details: `Auth Failed: ${authCheck.reason} [key: ${rawKey ? rawKey.substr(0, 8) + '...' : 'none'}]`
    });
    return res.status(authCheck.statusCode).json({
      meta: { code: 2941, status: 'unauthorized' },
      data: null,
      message: authCheck.reason,
      rid: 'AUTH_' + Date.now().toString(36)
    });
  }

  const upstreamKey = authCheck.upstreamKey;

  try {
    const upstreamRes = await fetch(targetUrl, {
      method: 'GET',
      headers: {
        'mauthapi': upstreamKey,
        'Accept': 'application/json',
        'User-Agent': DEFAULT_UA
      }
    });

    const latency = Date.now() - startTime;
    const statusCode = upstreamRes.status;
    const textData = await upstreamRes.text();

    let jsonData = null;
    try {
      jsonData = JSON.parse(textData);
    } catch (_) {}

    const otpCount = jsonData?.data?.otps?.length || 0;
    if (otpCount > 0) stats.otpsReceived += otpCount;

    logRequest({
      endpoint: '/success-otp',
      method: 'GET',
      ip: clientIp,
      status: statusCode,
      latency,
      details: otpCount > 0 ? `Found ${otpCount} OTP(s)` : (statusCode === 200 ? 'Polling (no new OTP)' : jsonData?.message || 'Status ' + statusCode)
    });

    if (jsonData) {
      return res.status(statusCode).json(jsonData);
    }

    return res.status(statusCode).send(textData);

  } catch (err) {
    const latency = Date.now() - startTime;
    logRequest({
      endpoint: '/success-otp',
      method: 'GET',
      ip: clientIp,
      status: 500,
      latency,
      details: 'Error: ' + err.message
    });

    return res.status(500).json({
      meta: { code: 500, status: 'proxy_error' },
      message: 'Failed to connect to success-otp endpoint: ' + err.message
    });
  }
});

// ---------------------------------------------------------------------
// 6. Console Endpoint (/console)
// ---------------------------------------------------------------------
app.get(['/api/console', '/console'], async (req, res) => {
  const rawKey = req.headers['mauthapi'] || '';
  const authCheck = validateClientKey(rawKey);
  const upstreamKey = authCheck.upstreamKey || config.defaultMauthApiKey || rawKey;
  const targetUrl = config.consoleUrl || `${config.baseUrl}/console`;

  try {
    const upstreamRes = await fetch(targetUrl, {
      method: 'GET',
      headers: {
        'mauthapi': upstreamKey,
        'Accept': 'application/json, text/plain, */*',
        'User-Agent': DEFAULT_UA
      }
    });

    if (upstreamRes.status === 200) {
      const data = await upstreamRes.text();
      return res.status(200).send(data);
    }
  } catch (_) {}

  return res.json({
    status: 'online',
    server: 'RC Tools Vercel Hub',
    stats,
    recentTraffic: trafficLogs.slice(0, 20)
  });
});

// ---------------------------------------------------------------------
// 7. Admin API Routes (Config, Logs, Key Management)
// ---------------------------------------------------------------------
function checkAdminAuth(req, res) {
  const pass = req.headers['x-admin-auth'] || req.body?.auth || req.query?.auth;
  if (pass !== config.adminPassword && pass !== 'admin') {
    res.status(403).json({ error: 'Invalid admin credentials' });
    return false;
  }
  return true;
}

app.get('/api/admin/config', (req, res) => {
  res.json({
    ...config,
    adminPassword: '••••••••'
  });
});

app.post('/api/admin/config', (req, res) => {
  if (!checkAdminAuth(req, res)) return;

  const { newConfig } = req.body;
  if (newConfig) {
    if (newConfig.baseUrl) config.baseUrl = newConfig.baseUrl.trim();
    if (newConfig.liveaccessUrl) config.liveaccessUrl = newConfig.liveaccessUrl.trim();
    if (newConfig.getnumUrl) config.getnumUrl = newConfig.getnumUrl.trim();
    if (newConfig.otpUrl) config.otpUrl = newConfig.otpUrl.trim();
    if (newConfig.consoleUrl) config.consoleUrl = newConfig.consoleUrl.trim();
    if (newConfig.defaultMauthApiKey !== undefined) config.defaultMauthApiKey = newConfig.defaultMauthApiKey.trim();
    if (newConfig.appEnabled !== undefined) config.appEnabled = Boolean(newConfig.appEnabled);
    if (newConfig.appNotice !== undefined) config.appNotice = newConfig.appNotice.trim();
    if (newConfig.adminPassword && newConfig.adminPassword !== '••••••••') config.adminPassword = newConfig.adminPassword;
    if (Array.isArray(newConfig.fallbackRanges)) config.fallbackRanges = newConfig.fallbackRanges;

    saveConfig();
  }

  res.json({ success: true, message: 'Configuration saved in realtime', config });
});

// Keys Management Routes
app.get('/api/admin/keys', (req, res) => {
  res.json({
    keys: config.apiKeys || []
  });
});

app.post('/api/admin/keys/generate', (req, res) => {
  if (!checkAdminAuth(req, res)) return;

  const { label, expiryDays, customKey } = req.body;
  
  const finalKey = (customKey && customKey.trim()) ? customKey.trim() : generateKeyString('RC');
  
  // Calculate expiry
  let expiresAt = null;
  const days = parseInt(expiryDays);
  if (days && days > 0) {
    const exp = new Date();
    exp.setDate(exp.getDate() + days);
    expiresAt = exp.toISOString();
  }

  const keyObj = {
    id: 'key_' + Date.now().toString(36) + Math.random().toString(36).substr(2, 4),
    key: finalKey,
    label: (label && label.trim()) ? label.trim() : 'Unnamed User',
    createdAt: new Date().toISOString(),
    expiresAt,
    enabled: true,
    usageCount: 0,
    lastUsed: null
  };

  config.apiKeys = config.apiKeys || [];
  config.apiKeys.unshift(keyObj);
  saveConfig();

  res.json({ success: true, message: 'New API Key generated successfully', key: keyObj });
});

app.post('/api/admin/keys/toggle', (req, res) => {
  if (!checkAdminAuth(req, res)) return;

  const { id } = req.body;
  const keyObj = (config.apiKeys || []).find(k => k.id === id);
  if (!keyObj) {
    return res.status(404).json({ error: 'Key not found' });
  }

  keyObj.enabled = !keyObj.enabled;
  saveConfig();

  res.json({ success: true, message: `Key status set to ${keyObj.enabled ? 'Active' : 'Disabled'}`, key: keyObj });
});

app.post('/api/admin/keys/delete', (req, res) => {
  if (!checkAdminAuth(req, res)) return;

  const { id } = req.body;
  config.apiKeys = (config.apiKeys || []).filter(k => k.id !== id);
  saveConfig();

  res.json({ success: true, message: 'API key deleted successfully' });
});

app.get('/api/admin/logs', (req, res) => {
  res.json({
    stats,
    logs: trafficLogs
  });
});

app.post('/api/admin/clear-logs', (req, res) => {
  trafficLogs.length = 0;
  res.json({ success: true });
});

app.post('/api/admin/test-endpoint', async (req, res) => {
  const { endpointType, apiKey, customRid } = req.body;
  let targetUrl = '';
  let method = 'GET';
  let body = undefined;

  const keyToUse = apiKey || config.defaultMauthApiKey || '';

  if (endpointType === 'liveaccess') {
    targetUrl = config.liveaccessUrl || `${config.baseUrl}/liveaccess`;
  } else if (endpointType === 'getnum') {
    targetUrl = config.getnumUrl || `${config.baseUrl}/getnum`;
    method = 'POST';
    body = JSON.stringify({ rid: customRid || '22467' });
  } else if (endpointType === 'otp') {
    targetUrl = config.otpUrl || `${config.baseUrl}/success-otp`;
  } else if (endpointType === 'console') {
    targetUrl = config.consoleUrl || `${config.baseUrl}/console`;
  }

  const start = Date.now();
  try {
    const upstreamRes = await fetch(targetUrl, {
      method,
      headers: {
        'Content-Type': 'application/json',
        'mauthapi': keyToUse,
        'Accept': 'application/json',
        'User-Agent': DEFAULT_UA
      },
      body
    });
    const duration = Date.now() - start;
    const text = await upstreamRes.text();
    let parsed = null;
    try { parsed = JSON.parse(text); } catch (_) {}

    res.json({
      success: upstreamRes.ok,
      status: upstreamRes.status,
      duration,
      targetUrl,
      data: parsed || text
    });
  } catch (err) {
    res.json({
      success: false,
      status: 500,
      duration: Date.now() - start,
      targetUrl,
      error: err.message
    });
  }
});

// ---------------------------------------------------------------------
// 8. Rich Real-Time Admin Dashboard HTML
// ---------------------------------------------------------------------
app.get(['/', '/admin'], (req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>RC TOOLS - Vercel Realtime Admin Control Hub</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #0b0f19;
      --card-bg: #151c2c;
      --card-border: #232f48;
      --primary: #0284c7;
      --primary-hover: #0369a1;
      --accent: #38bdf8;
      --success: #10b981;
      --warning: #f59e0b;
      --danger: #ef4444;
      --text: #f1f5f9;
      --text-muted: #94a3b8;
      --font-sans: 'Plus Jakarta Sans', system-ui, sans-serif;
      --font-mono: 'JetBrains Mono', monospace;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg);
      color: var(--text);
      font-family: var(--font-sans);
      min-height: 100vh;
      padding: 24px;
      line-height: 1.5;
    }
    .container { max-width: 1380px; margin: 0 auto; }
    
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 24px;
      border-bottom: 1px solid var(--card-border);
      margin-bottom: 24px;
      flex-wrap: wrap;
      gap: 16px;
    }
    .logo-badge {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .badge-icon {
      background: linear-gradient(135deg, #0284c7, #38bdf8);
      width: 44px;
      height: 44px;
      border-radius: 12px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 22px;
      box-shadow: 0 0 20px rgba(56, 189, 248, 0.4);
    }
    h1 { font-size: 22px; font-weight: 800; letter-spacing: -0.5px; }
    .subtitle { font-size: 13px; color: var(--text-muted); }

    .status-group {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .pill {
      background: rgba(16, 185, 129, 0.15);
      color: var(--success);
      border: 1px solid rgba(16, 185, 129, 0.3);
      padding: 6px 14px;
      border-radius: 999px;
      font-size: 13px;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .pill-dot { width: 8px; height: 8px; background: var(--success); border-radius: 50%; box-shadow: 0 0 10px var(--success); animation: pulse 2s infinite; }
    @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }

    /* Stats Grid */
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }
    .stat-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      padding: 18px;
      border-radius: 14px;
    }
    .stat-title { font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-muted); font-weight: 600; margin-bottom: 8px; }
    .stat-value { font-size: 26px; font-weight: 800; font-family: var(--font-mono); }
    .stat-meta { font-size: 12px; color: var(--text-muted); margin-top: 4px; }

    /* Main Grid */
    .main-grid {
      display: grid;
      grid-template-columns: 1.15fr 1fr;
      gap: 24px;
    }
    @media (max-width: 1080px) {
      .main-grid { grid-template-columns: 1fr; }
    }

    .card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 16px;
      padding: 24px;
      margin-bottom: 24px;
    }
    .card-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 20px;
      flex-wrap: wrap;
      gap: 10px;
    }
    .card-title {
      font-size: 16px;
      font-weight: 700;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    /* Forms & Inputs */
    .form-group {
      margin-bottom: 16px;
    }
    label {
      display: block;
      font-size: 13px;
      font-weight: 600;
      margin-bottom: 6px;
      color: var(--text-muted);
    }
    input[type="text"], input[type="password"], textarea, select {
      width: 100%;
      background: #0f1523;
      border: 1px solid var(--card-border);
      color: var(--text);
      padding: 10px 14px;
      border-radius: 10px;
      font-family: var(--font-mono);
      font-size: 13px;
      outline: none;
      transition: all 0.2s;
    }
    input:focus, textarea:focus, select:focus {
      border-color: var(--accent);
      box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.2);
    }
    
    .btn {
      background: var(--primary);
      color: #fff;
      border: none;
      padding: 10px 18px;
      border-radius: 10px;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      transition: all 0.2s;
      white-space: nowrap;
    }
    .btn:hover { background: var(--primary-hover); transform: translateY(-1px); }
    .btn-success { background: var(--success); }
    .btn-success:hover { background: #059669; }
    .btn-danger { background: var(--danger); }
    .btn-danger:hover { background: #dc2626; }
    .btn-warning { background: var(--warning); color: #000; }
    .btn-outline { background: transparent; border: 1px solid var(--card-border); color: var(--text-muted); }
    .btn-outline:hover { background: rgba(255,255,255,0.05); color: var(--text); }
    .btn-sm { padding: 6px 12px; font-size: 12px; }

    /* Switch */
    .switch-label {
      display: flex;
      align-items: center;
      justify-content: space-between;
      cursor: pointer;
      background: #0f1523;
      padding: 12px 16px;
      border-radius: 12px;
      border: 1px solid var(--card-border);
    }
    .switch-info h4 { font-size: 14px; font-weight: 600; }
    .switch-info p { font-size: 12px; color: var(--text-muted); }
    .toggle-switch {
      position: relative;
      display: inline-block;
      width: 50px;
      height: 28px;
    }
    .toggle-switch input { opacity: 0; width: 0; height: 0; }
    .slider {
      position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0;
      background-color: #334155; transition: .3s; border-radius: 34px;
    }
    .slider:before {
      position: absolute; content: ""; height: 20px; width: 20px; left: 4px; bottom: 4px;
      background-color: white; transition: .3s; border-radius: 50%;
    }
    input:checked + .slider { background-color: var(--success); }
    input:checked + .slider:before { transform: translateX(22px); }

    /* Tables */
    .table-container {
      overflow-x: auto;
      max-height: 480px;
      border: 1px solid var(--card-border);
      border-radius: 12px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
      font-family: var(--font-mono);
    }
    th {
      background: #0f1523;
      padding: 10px 14px;
      text-align: left;
      font-weight: 600;
      color: var(--text-muted);
      position: sticky;
      top: 0;
      border-bottom: 1px solid var(--card-border);
    }
    td {
      padding: 9px 14px;
      border-bottom: 1px solid rgba(35, 47, 72, 0.5);
    }
    tr:hover td { background: rgba(56, 189, 248, 0.04); }
    .status-badge {
      display: inline-block;
      padding: 3px 8px;
      border-radius: 6px;
      font-size: 11px;
      font-weight: 700;
    }
    .status-active { background: rgba(16, 185, 129, 0.2); color: var(--success); }
    .status-disabled { background: rgba(239, 68, 68, 0.2); color: var(--danger); }
    .status-expired { background: rgba(245, 158, 11, 0.2); color: var(--warning); }
    .status-200 { background: rgba(16, 185, 129, 0.2); color: var(--success); }
    .status-401 { background: rgba(245, 158, 11, 0.2); color: var(--warning); }
    .status-500 { background: rgba(239, 68, 68, 0.2); color: var(--danger); }

    /* Key Generator Card */
    .gen-box {
      background: #090e1a;
      border: 1px solid rgba(56, 189, 248, 0.3);
      padding: 18px;
      border-radius: 14px;
      margin-bottom: 20px;
    }
    .gen-grid {
      display: grid;
      grid-template-columns: 1.5fr 1fr 1fr auto;
      gap: 12px;
      align-items: end;
    }
    @media (max-width: 900px) {
      .gen-grid { grid-template-columns: 1fr; }
    }

    .key-display-box {
      background: #0f1523;
      border: 1px dashed var(--accent);
      padding: 14px;
      border-radius: 12px;
      margin-top: 14px;
      display: none;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      flex-wrap: wrap;
    }
    .key-text {
      font-family: var(--font-mono);
      font-size: 15px;
      font-weight: 700;
      color: var(--accent);
      letter-spacing: 0.5px;
    }

    /* Test Results Pre */
    pre {
      background: #090d16;
      border: 1px solid var(--card-border);
      padding: 12px;
      border-radius: 10px;
      font-family: var(--font-mono);
      font-size: 12px;
      max-height: 220px;
      overflow-y: auto;
      white-space: pre-wrap;
      word-break: break-all;
    }
    
    .toast {
      position: fixed;
      bottom: 24px;
      right: 24px;
      background: var(--card-bg);
      border: 1px solid var(--accent);
      color: var(--text);
      padding: 14px 20px;
      border-radius: 12px;
      box-shadow: 0 10px 30px rgba(0,0,0,0.5);
      display: none;
      z-index: 999;
      animation: slideUp 0.3s forwards;
    }
    @keyframes slideUp { from { transform: translateY(20px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="logo-badge">
        <div class="badge-icon">⚡</div>
        <div>
          <h1>RC TOOLS - REALTIME CONTROL HUB</h1>
          <div class="subtitle">Decoupled Vercel Server, API Key Generator & Traffic Gateway</div>
        </div>
      </div>
      <div class="status-group">
        <div class="pill">
          <div class="pill-dot"></div>
          <span id="headerStatus">LIVE SYNC ACTIVE</span>
        </div>
        <button class="btn btn-outline btn-sm" onclick="fetchData()">🔄 Refresh</button>
      </div>
    </header>

    <!-- Stats Row -->
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-title">Total Processed Requests</div>
        <div class="stat-value" id="statTotal" style="color: var(--accent);">0</div>
        <div class="stat-meta">Via Vercel proxy</div>
      </div>
      <div class="stat-card">
        <div class="stat-title">Active API Keys</div>
        <div class="stat-value" id="statActiveKeys" style="color: var(--success);">0</div>
        <div class="stat-meta" id="statTotalKeysMeta">0 keys generated</div>
      </div>
      <div class="stat-card">
        <div class="stat-title">Numbers Allocated</div>
        <div class="stat-value" id="statNumbers" style="color: var(--warning);">0</div>
        <div class="stat-meta">Virtual number queries</div>
      </div>
      <div class="stat-card">
        <div class="stat-title">OTPs Dispatched</div>
        <div class="stat-value" id="statOtps" style="color: #a855f7;">0</div>
        <div class="stat-meta">Live OTP verifications</div>
      </div>
      <div class="stat-card">
        <div class="stat-title">App Remote Status</div>
        <div class="stat-value" id="statAppStatus" style="color: var(--success);">ONLINE</div>
        <div class="stat-meta">Killswitch master</div>
      </div>
    </div>

    <!-- API KEY GENERATOR & MANAGEMENT (FULL WIDTH CARD) -->
    <div class="card" style="border-color: rgba(56, 189, 248, 0.4);">
      <div class="card-header">
        <div>
          <div class="card-title" style="color: var(--accent); font-size: 18px;">
            🔑 API Key Generator & User Access Management
          </div>
          <p style="font-size: 13px; color: var(--text-muted); margin-top: 4px;">
            Generate unique RC API Keys (mauthapi) for your app users. The server validates them and proxies to your upstream provider using your master key.
          </p>
        </div>
        <span class="status-badge status-active" id="keysSummaryBadge">0 Keys</span>
      </div>

      <!-- Generator Form -->
      <div class="gen-box">
        <div class="gen-grid">
          <div>
            <label>User / Client Label</label>
            <input type="text" id="genLabel" placeholder="e.g. Rahim - Device 1 / Team Alpha">
          </div>
          <div>
            <label>Key Validity / Expiry</label>
            <select id="genExpiry">
              <option value="0">Lifetime (No Expiry)</option>
              <option value="1">1 Day</option>
              <option value="3">3 Days</option>
              <option value="7">7 Days</option>
              <option value="15">15 Days</option>
              <option value="30" selected>30 Days (1 Month)</option>
              <option value="60">60 Days (2 Months)</option>
              <option value="90">90 Days (3 Months)</option>
            </select>
          </div>
          <div>
            <label>Custom Key (Optional)</label>
            <input type="text" id="genCustomKey" placeholder="Leave empty to auto-generate">
          </div>
          <div>
            <button class="btn btn-success" style="width: 100%; height: 42px;" onclick="generateKey()">
              ⚡ Generate API Key
            </button>
          </div>
        </div>

        <!-- Newly Generated Key Alert Box -->
        <div class="key-display-box" id="newKeyAlert">
          <div>
            <span style="font-size: 12px; color: var(--success); font-weight: 700;">✅ NEW API KEY GENERATED:</span>
            <div class="key-text" id="newKeyText">RC-XXXXXX-XXXXXX</div>
            <div style="font-size: 12px; color: var(--text-muted); margin-top: 2px;" id="newKeyMeta">Label: - | Validity: -</div>
          </div>
          <button class="btn btn-outline btn-sm" onclick="copyNewKey()">📋 Copy API Key</button>
        </div>
      </div>

      <!-- Generated Keys Table -->
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>API Key (mauthapi)</th>
              <th>Client / Label</th>
              <th>Created</th>
              <th>Expires In</th>
              <th>Requests</th>
              <th>Last Used</th>
              <th>Status</th>
              <th style="text-align: right;">Actions</th>
            </tr>
          </thead>
          <tbody id="keysTableBody">
            <tr><td colspan="9" style="text-align: center; color: var(--text-muted); padding: 24px;">No API keys generated yet. Click 'Generate API Key' above.</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- TWO COLUMN LAYOUT: ENDPOINTS & CONSOLE -->
    <div class="main-grid">
      <!-- Left Column: Config & Endpoints -->
      <div>
        <div class="card">
          <div class="card-header">
            <div class="card-title">🌐 Live API Endpoints & Server Settings</div>
            <span style="font-size: 12px; color: var(--accent);">Instant Realtime Sync</span>
          </div>

          <div class="form-group">
            <label>Master Upstream API Key (2oo9.cloud mauthapi)</label>
            <input type="text" id="cfgMauthKey" placeholder="Enter your upstream provider master API key">
            <p style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">
              *All your generated client keys will securely route through this master key.
            </p>
          </div>

          <div class="form-group">
            <label>1. Base API URL (Proxy Gateway Root)</label>
            <input type="text" id="cfgBaseUrl" placeholder="https://api.2oo9.cloud/MXS47FLFX0U/tnevs/@public/api">
          </div>

          <div class="form-group">
            <label>2. Live Traffic & Range Loader Endpoint (/liveaccess)</label>
            <input type="text" id="cfgLiveaccessUrl" placeholder="https://api.2oo9.cloud/MXS47FLFX0U/tnevs/@public/api/liveaccess">
          </div>

          <div class="form-group">
            <label>3. Virtual Number Request Endpoint - POST (/getnum)</label>
            <input type="text" id="cfgGetnumUrl" placeholder="https://api.2oo9.cloud/MXS47FLFX0U/tnevs/@public/api/getnum">
          </div>

          <div class="form-group">
            <label>4. OTP Check Endpoint - GET (/success-otp)</label>
            <input type="text" id="cfgOtpUrl" placeholder="https://api.2oo9.cloud/MXS47FLFX0U/tnevs/@public/api/success-otp">
          </div>

          <div class="form-group">
            <label>5. Live Console Endpoint (/console)</label>
            <input type="text" id="cfgConsoleUrl" placeholder="https://api.2oo9.cloud/MXS47FLFX0U/tnevs/@public/api/console">
          </div>

          <div class="form-group">
            <div class="switch-label">
              <div class="switch-info">
                <h4>Remote App Status (Killswitch Master)</h4>
                <p>When enabled, app functions normally. When disabled, locks app.</p>
              </div>
              <label class="toggle-switch">
                <input type="checkbox" id="cfgAppEnabled" checked>
                <span class="slider"></span>
              </label>
            </div>
          </div>

          <div class="form-group">
            <label>Announcement / Notice for App Users</label>
            <input type="text" id="cfgAppNotice" placeholder="Service operational">
          </div>

          <div class="form-group">
            <label>Fallback Ranges (Protects against upstream downtime)</label>
            <textarea id="cfgFallbackRanges" rows="2" style="font-family: var(--font-mono);"></textarea>
          </div>

          <div class="form-group">
            <label>Admin Security Passcode (to protect saving settings)</label>
            <input type="password" id="cfgAdminPass" placeholder="Default: admin">
          </div>

          <button class="btn btn-success" style="width: 100%; justify-content: center;" onclick="saveConfig()">
            💾 Save All Configuration Changes
          </button>
        </div>

        <!-- Android App Integration Box -->
        <div class="card">
          <div class="card-header">
            <div class="card-title">📱 Android App Connection Details</div>
          </div>
          <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 12px;">
            The rebuilt Android APK connects directly to these endpoints. You can also point the app to this Vercel deployment URL anytime:
          </p>
          <div style="background: #0f1523; padding: 12px; border-radius: 10px; font-family: var(--font-mono); font-size: 12px; border: 1px solid var(--card-border); margin-bottom: 12px;">
            <div style="color: var(--accent); margin-bottom: 4px;">📡 Direct Base API:</div>
            <div style="color: #cbd5e1; margin-bottom: 8px;">https://api.2oo9.cloud/MXS47FLFX0U/tnevs/@public/api</div>
            <div style="color: var(--success); margin-bottom: 4px;">⚡ This Vercel Server Gateway:</div>
            <div id="vercelServerUrl" style="color: #cbd5e1;">https://YOUR-VERCEL-DOMAIN.vercel.app/api</div>
          </div>
          <button class="btn btn-outline btn-sm" onclick="copyVercelUrl()">📋 Copy Vercel Base URL</button>
        </div>
      </div>

      <!-- Right Column: Live Console & Realtime Tester -->
      <div>
        <!-- Realtime Tester -->
        <div class="card">
          <div class="card-header">
            <div class="card-title">🧪 Instant API Tester</div>
            <span style="font-size: 12px; color: var(--text-muted);">Test Upstream Connectivity</span>
          </div>

          <div style="display: flex; gap: 8px; margin-bottom: 12px; flex-wrap: wrap;">
            <button class="btn btn-sm btn-outline" onclick="runTest('liveaccess')">Test Liveaccess</button>
            <button class="btn btn-sm btn-outline" onclick="runTest('getnum')">Test GetNum</button>
            <button class="btn btn-sm btn-outline" onclick="runTest('otp')">Test Success-OTP</button>
            <button class="btn btn-sm btn-outline" onclick="runTest('console')">Test Console</button>
          </div>

          <div id="testOutputContainer" style="display: none;">
            <div style="display: flex; justify-content: space-between; font-size: 12px; color: var(--text-muted); margin-bottom: 4px;">
              <span id="testTargetInfo">Target: ...</span>
              <span id="testDurationInfo">Latency: 0ms</span>
            </div>
            <pre id="testOutput">// Result will appear here...</pre>
          </div>
        </div>

        <!-- Realtime Traffic Console -->
        <div class="card">
          <div class="card-header">
            <div class="card-title">📡 Realtime Traffic & Request Console</div>
            <div style="display: flex; gap: 8px;">
              <button class="btn btn-outline btn-sm" onclick="clearLogs()">Clear</button>
            </div>
          </div>

          <div class="table-container">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>IP</th>
                  <th>Endpoint</th>
                  <th>Status</th>
                  <th>Latency</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody id="logsTableBody">
                <tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 24px;">Waiting for incoming traffic...</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  </div>

  <div class="toast" id="toastMsg">Changes saved!</div>

  <script>
    const origin = window.location.origin;
    document.getElementById('vercelServerUrl').textContent = origin + '/api';

    let lastGeneratedKey = '';

    function showToast(text, isError = false) {
      const toast = document.getElementById('toastMsg');
      toast.textContent = text;
      toast.style.borderColor = isError ? 'var(--danger)' : 'var(--accent)';
      toast.style.display = 'block';
      setTimeout(() => { toast.style.display = 'none'; }, 3000);
    }

    function copyVercelUrl() {
      navigator.clipboard.writeText(origin + '/api');
      showToast('Vercel API URL copied to clipboard!');
    }

    function copyText(str) {
      navigator.clipboard.writeText(str);
      showToast('Copied to clipboard: ' + str);
    }

    function copyNewKey() {
      if (lastGeneratedKey) {
        copyText(lastGeneratedKey);
      }
    }

    async function generateKey() {
      const label = document.getElementById('genLabel').value;
      const expiryDays = document.getElementById('genExpiry').value;
      const customKey = document.getElementById('genCustomKey').value;
      const pass = document.getElementById('cfgAdminPass').value || 'admin';

      try {
        const res = await fetch('/api/admin/keys/generate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ auth: pass, label, expiryDays, customKey })
        });
        const data = await res.json();
        if (res.ok) {
          lastGeneratedKey = data.key.key;
          document.getElementById('newKeyText').textContent = data.key.key;
          document.getElementById('newKeyMeta').textContent = 'Label: ' + data.key.label + ' | Expires: ' + (data.key.expiresAt ? new Date(data.key.expiresAt).toLocaleDateString() : 'Lifetime');
          document.getElementById('newKeyAlert').style.display = 'flex';
          document.getElementById('genLabel').value = '';
          document.getElementById('genCustomKey').value = '';
          showToast('⚡ New API Key Generated!');
          fetchData();
        } else {
          showToast('❌ ' + (data.error || 'Failed to generate key'), true);
        }
      } catch (err) {
        showToast('❌ Error: ' + err.message, true);
      }
    }

    async function toggleKey(id) {
      const pass = document.getElementById('cfgAdminPass').value || 'admin';
      try {
        const res = await fetch('/api/admin/keys/toggle', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ auth: pass, id })
        });
        const data = await res.json();
        if (res.ok) {
          showToast(data.message);
          fetchData();
        } else {
          showToast('❌ ' + (data.error || 'Failed'), true);
        }
      } catch (err) {
        showToast('❌ ' + err.message, true);
      }
    }

    async function deleteKey(id) {
      if (!confirm('Are you sure you want to delete this API Key?')) return;
      const pass = document.getElementById('cfgAdminPass').value || 'admin';
      try {
        const res = await fetch('/api/admin/keys/delete', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ auth: pass, id })
        });
        const data = await res.json();
        if (res.ok) {
          showToast('Key deleted');
          fetchData();
        } else {
          showToast('❌ ' + (data.error || 'Failed'), true);
        }
      } catch (err) {
        showToast('❌ ' + err.message, true);
      }
    }

    async function fetchData() {
      try {
        const [cfgRes, logsRes, keysRes] = await Promise.all([
          fetch('/api/admin/config'),
          fetch('/api/admin/logs'),
          fetch('/api/admin/keys')
        ]);

        const cfg = await cfgRes.json();
        const logData = await logsRes.json();
        const keysData = await keysRes.json();

        // Populate fields if user is not currently typing in them
        if (!document.activeElement || document.activeElement.tagName !== 'INPUT') {
          document.getElementById('cfgBaseUrl').value = cfg.baseUrl || '';
          document.getElementById('cfgLiveaccessUrl').value = cfg.liveaccessUrl || '';
          document.getElementById('cfgGetnumUrl').value = cfg.getnumUrl || '';
          document.getElementById('cfgOtpUrl').value = cfg.otpUrl || '';
          document.getElementById('cfgConsoleUrl').value = cfg.consoleUrl || '';
          document.getElementById('cfgMauthKey').value = cfg.defaultMauthApiKey || '';
          document.getElementById('cfgAppEnabled').checked = cfg.appEnabled !== false;
          document.getElementById('cfgAppNotice').value = cfg.appNotice || '';
          document.getElementById('cfgFallbackRanges').value = (cfg.fallbackRanges || []).join(', ');
        }

        // Stats
        document.getElementById('statTotal').textContent = logData.stats.totalRequests || 0;
        document.getElementById('statNumbers').textContent = logData.stats.numbersAllocated || 0;
        document.getElementById('statOtps').textContent = logData.stats.otpsReceived || 0;
        
        const isOnline = cfg.appEnabled !== false;
        const statusEl = document.getElementById('statAppStatus');
        statusEl.textContent = isOnline ? 'ONLINE' : 'LOCKED';
        statusEl.style.color = isOnline ? 'var(--success)' : 'var(--danger)';

        // Keys Stats & Table
        const keys = keysData.keys || [];
        const activeKeys = keys.filter(k => k.enabled && (!k.expiresAt || new Date(k.expiresAt) > new Date())).length;
        document.getElementById('statActiveKeys').textContent = activeKeys;
        document.getElementById('statTotalKeysMeta').textContent = keys.length + ' total keys';
        document.getElementById('keysSummaryBadge').textContent = activeKeys + ' Active / ' + keys.length + ' Total';

        const keysTbody = document.getElementById('keysTableBody');
        if (keys.length > 0) {
          keysTbody.innerHTML = keys.map((k, index) => {
            const isExpired = k.expiresAt && new Date(k.expiresAt) < new Date();
            let statusBadge = '<span class="status-badge status-active">Active</span>';
            if (!k.enabled) {
              statusBadge = '<span class="status-badge status-disabled">Disabled</span>';
            } else if (isExpired) {
              statusBadge = '<span class="status-badge status-expired">Expired</span>';
            }

            let expiryText = 'Lifetime';
            if (k.expiresAt) {
              const diffMs = new Date(k.expiresAt) - new Date();
              const diffDays = Math.ceil(diffMs / (1000 * 60 * 60 * 24));
              expiryText = diffDays > 0 ? (diffDays + ' day(s)') : 'Expired';
            }

            const createdDate = new Date(k.createdAt).toLocaleDateString();
            const lastActive = k.lastUsed ? new Date(k.lastUsed).toLocaleTimeString() : 'Never';

            return \`
              <tr>
                <td>\${index + 1}</td>
                <td>
                  <span style="font-family: var(--font-mono); font-weight: 700; color: var(--accent);">\${k.key}</span>
                  <button class="btn btn-outline btn-sm" style="padding: 2px 6px; margin-left: 6px;" onclick="copyText('\${k.key}')">📋</button>
                </td>
                <td>\${k.label || 'Unnamed'}</td>
                <td>\${createdDate}</td>
                <td>\${expiryText}</td>
                <td><span class="status-badge status-active">\${k.usageCount || 0}</span></td>
                <td>\${lastActive}</td>
                <td>\${statusBadge}</td>
                <td style="text-align: right;">
                  <button class="btn \${k.enabled ? 'btn-warning' : 'btn-success'} btn-sm" style="padding: 4px 8px; font-size: 11px;" onclick="toggleKey('\${k.id}')">
                    \${k.enabled ? 'Disable' : 'Enable'}
                  </button>
                  <button class="btn btn-danger btn-sm" style="padding: 4px 8px; font-size: 11px;" onclick="deleteKey('\${k.id}')">
                    🗑️
                  </button>
                </td>
              </tr>
            \`;
          }).join('');
        } else {
          keysTbody.innerHTML = '<tr><td colspan="9" style="text-align: center; color: var(--text-muted); padding: 24px;">No API keys generated yet. Click Generate API Key above.</td></tr>';
        }

        // Logs Table
        const tbody = document.getElementById('logsTableBody');
        if (logData.logs && logData.logs.length > 0) {
          tbody.innerHTML = logData.logs.map(l => {
            const statusClass = l.status === 200 ? 'status-200' : (l.status === 401 ? 'status-401' : 'status-500');
            return \`
              <tr>
                <td>\${l.time}</td>
                <td>\${l.ip}</td>
                <td><span style="color: var(--accent); font-weight: 600;">\${l.method}</span> \${l.endpoint}</td>
                <td><span class="status-badge \${statusClass}">\${l.status}</span></td>
                <td>\${l.latency}ms</td>
                <td>\${l.details || '-'}</td>
              </tr>
            \`;
          }).join('');
        }
      } catch (err) {
        console.error('Sync error:', err);
      }
    }

    async function saveConfig() {
      const pass = document.getElementById('cfgAdminPass').value || 'admin';
      const rangesStr = document.getElementById('cfgFallbackRanges').value || '';
      const ranges = rangesStr.split(',').map(s => s.trim()).filter(Boolean);

      const payload = {
        auth: pass,
        newConfig: {
          baseUrl: document.getElementById('cfgBaseUrl').value,
          liveaccessUrl: document.getElementById('cfgLiveaccessUrl').value,
          getnumUrl: document.getElementById('cfgGetnumUrl').value,
          otpUrl: document.getElementById('cfgOtpUrl').value,
          consoleUrl: document.getElementById('cfgConsoleUrl').value,
          defaultMauthApiKey: document.getElementById('cfgMauthKey').value,
          appEnabled: document.getElementById('cfgAppEnabled').checked,
          appNotice: document.getElementById('cfgAppNotice').value,
          fallbackRanges: ranges
        }
      };

      try {
        const res = await fetch('/api/admin/config', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (res.ok) {
          showToast('✅ Configuration saved in realtime!');
          fetchData();
        } else {
          showToast('❌ ' + (data.error || 'Failed to save'), true);
        }
      } catch (err) {
        showToast('❌ Network error: ' + err.message, true);
      }
    }

    async function clearLogs() {
      await fetch('/api/admin/clear-logs', { method: 'POST' });
      fetchData();
    }

    async function runTest(type) {
      const container = document.getElementById('testOutputContainer');
      const targetInfo = document.getElementById('testTargetInfo');
      const durationInfo = document.getElementById('testDurationInfo');
      const output = document.getElementById('testOutput');

      container.style.display = 'block';
      output.textContent = 'Testing connection...';
      targetInfo.textContent = 'Testing ' + type + '...';

      try {
        const res = await fetch('/api/admin/test-endpoint', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            endpointType: type,
            apiKey: document.getElementById('cfgMauthKey').value,
            customRid: '22467'
          })
        });
        const data = await res.json();
        targetInfo.textContent = 'Target: ' + data.targetUrl;
        durationInfo.textContent = 'Status: ' + data.status + ' (' + data.duration + 'ms)';
        output.textContent = JSON.stringify(data.data || data.error, null, 2);
      } catch (err) {
        output.textContent = 'Test failed: ' + err.message;
      }
    }

    // Auto-refresh every 2.5s for real-time monitoring
    setInterval(fetchData, 2500);
    fetchData();
  </script>
</body>
</html>`);
});

// Start server locally or export for Vercel
const PORT = process.env.PORT || 3000;
if (process.env.NODE_ENV !== 'production' || !process.env.VERCEL) {
  app.listen(PORT, () => {
    console.log(`RC Tools Vercel Server running on http://localhost:${PORT}`);
  });
}

module.exports = app;
