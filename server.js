/**
 * PR Reviewer API Server
 * A simple web service that reviews GitHub PRs automatically
 * 
 * Usage:
 *   POST /review
 *   Body: { owner, repo, prNumber, githubToken }
 *   Returns: { issues: [], summary: {}, security: {}, quality: {} }
 * 
 * Run: node server.js
 */

const http = require('http');
const https = require('https');
const url = require('url');

const PORT = process.env.PORT || 3000;

// Security patterns to detect
const SECURITY_PATTERNS = [
  { regex: /eval\s*\(|new\s+Function\s*\(/g, severity: 'CRITICAL', msg: 'Dynamic code execution - potential injection' },
  { regex: /innerHTML\s*=/g, severity: 'HIGH', msg: 'Direct DOM manipulation - potential XSS' },
  { regex: /document\.write\s*\(/g, severity: 'HIGH', msg: 'Dynamic content injection - potential XSS' },
  { regex: /password\s*=\s*['"][^'"]{1,30}['"]|api[_-]?key\s*=\s*['"][^'"]{10,}['"]/g, severity: 'CRITICAL', msg: 'Hardcoded credential detected' },
  { regex: /process\.env\.\w+\s*\|\|\s*['"][^'"]+['"]/g, severity: 'LOW', msg: 'Hardcoded fallback for env variable' },
  { regex: /\.\.\/|\.\.\\\/|path\.join\([^)]+\+[^)]+\)/g, severity: 'HIGH', msg: 'Potential path traversal' },
  { regex: /WHERE\s+\w+\s*=\s*['"\.]+\s*\+|SQL\s*string.*\+/gi, severity: 'CRITICAL', msg: 'Potential SQL injection - use parameterized queries' },
  { regex: /crypto\.(createCipher|createDecipher)\(/g, severity: 'MEDIUM', msg: 'Deprecated crypto API - use crypto.createCipheriv' },
];

// Bug patterns
const BUG_PATTERNS = [
  { regex: /try\s*\{[^}]*\}\s*catch[^}]*\{\s*\}/g, severity: 'MEDIUM', msg: 'Empty catch block - errors silently ignored' },
  { regex: /===?\s*['"]undefined['"]|===?\s*['"]null['"]/g, severity: 'MEDIUM', msg: 'Use undefined/null literals not string comparisons' },
  { regex: /setTimeout\([^,]+,\s*0\)/g, severity: 'LOW', msg: 'Consider queueMicrotask or Promise.resolve().then()' },
  { regex: /for\s*\(\s*(var|let)\s+\w+\s+in\s+\w+\)/g, severity: 'MEDIUM', msg: 'Use for...of or Object.keys() for arrays' },
  { regex: /await\s+.*\n.*\.then\(/g, severity: 'LOW', msg: 'Mixed await and .then() - prefer consistent async/await' },
];

// Quality patterns
const QUALITY_PATTERNS = [
  { regex: /console\.(log|debug)\s*\(/g, severity: 'LOW', msg: 'Debug console statement left in code' },
  { regex: /\/\/\s*(TODO|FIXME|HACK|XXX):/g, severity: 'LOW', msg: 'Unresolved TODO/FIXME comment' },
  { regex: /var\s+\w+/g, severity: 'LOW', msg: 'Use of var - prefer const/let' },
  { regex: /==\s*(?!null|undefined|true|false)[^=]/g, severity: 'LOW', msg: 'Use === instead of == for strict comparison' },
];

function analyzeContent(content, filename) {
  if (!content) return [];
  const issues = [];
  const lines = content.split('\n');
  
  const allPatterns = [...SECURITY_PATTERNS, ...BUG_PATTERNS, ...QUALITY_PATTERNS];
  
  lines.forEach((line, i) => {
    allPatterns.forEach(p => {
      if (line.match(p.regex)) {
        issues.push({
          type: p.severity,
          file: filename,
          line: i + 1,
          msg: p.msg,
          code: line.trim().substring(0, 80)
        });
      }
    });
  });
  
  return issues;
}

function githubGet(path, token) {
  return new Promise((resolve, reject) => {
    const opts = {
      hostname: 'api.github.com',
      path: path,
      headers: { 'Authorization': 'token ' + token, 'User-Agent': 'PRReviewer/1.0', 'Accept': 'application/vnd.github.v3+json' }
    };
    https.get(opts, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => {
        try { resolve(JSON.parse(d)); }
        catch(e) { resolve(null); }
      });
    }).on('error', reject);
  });
}

async function reviewPR(owner, repo, prNumber, token) {
  // Get PR details
  const pr = await githubGet(`/repos/${owner}/${repo}/pulls/${prNumber}`, token);
  if (!pr || !pr.number) {
    throw new Error('PR not found or access denied');
  }
  
  // Get files changed
  const files = await githubGet(`/repos/${owner}/${repo}/pulls/${prNumber}/files?per_page=100`, token);
  
  const allIssues = [];
  
  if (Array.isArray(files)) {
    for (const file of files.slice(0, 20)) {
      if (!file.patch || file.status === 'removed') continue;
      
      // Reconstruct content from patch
      const content = file.patch.split('\n')
        .filter(l => !l.startsWith('+++') && !l.startsWith('---'))
        .map(l => l.startsWith('+') ? l.substring(1) : l.startsWith('-') ? '' : l)
        .join('\n');
      
      const issues = analyzeContent(content, file.filename);
      issues.forEach(i => allIssues.push(i));
    }
  }
  
  const critical = allIssues.filter(i => i.type === 'CRITICAL');
  const high = allIssues.filter(i => i.type === 'HIGH');
  const medium = allIssues.filter(i => i.type === 'MEDIUM');
  const low = allIssues.filter(i => i.type === 'LOW');
  
  return {
    pr: { number: pr.number, title: pr.title, url: pr.html_url, author: pr.user.login },
    stats: {
      files: files?.length || 0,
      critical: critical.length,
      high: high.length,
      medium: medium.length,
      low: low.length
    },
    issues: {
      critical, high, medium, low
    },
    summary: allIssues.length === 0 
      ? '✅ Code looks clean - no major issues detected'
      : `Found ${critical.length} critical, ${high.length} high, ${medium.length} medium, ${low.length} low severity issues`,
    recommendation: critical.length > 0 ? '🔴 REQUEST CHANGES' 
      : high.length > 0 ? '🟡 REQUEST CHANGES'
      : medium.length > 1 ? '🟡 REQUEST CHANGES'
      : '🟢 APPROVE'
  };
}

const server = http.createServer(async (req, res) => {
  const parsedUrl = url.parse(req.url, true);
  
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  
  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }
  
  if (parsedUrl.pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', service: 'PR Reviewer API' }));
    return;
  }
  
  if (parsedUrl.pathname === '/review' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
      try {
        const { owner, repo, prNumber, githubToken } = JSON.parse(body);
        
        if (!owner || !repo || !prNumber || !githubToken) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Missing required fields: owner, repo, prNumber, githubToken' }));
          return;
        }
        
        const result = await reviewPR(owner, repo, parseInt(prNumber), githubToken);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(result));
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    return;
  }
  
  if (parsedUrl.pathname === '/' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<!DOCTYPE html>
<html>
<head>
  <title>PR Reviewer API</title>
  <style>
    body { font-family: system-ui; max-width: 800px; margin: 4rem auto; padding: 2rem; background: #0a0a0f; color: #e0e0e0; }
    h1 { color: #f7931a; }
    code { background: #1a1a2e; padding: 0.2rem 0.4rem; border-radius: 4px; }
    pre { background: #1a1a2e; padding: 1rem; border-radius: 8px; overflow-x: auto; }
    .example { margin: 2rem 0; }
  </style>
</head>
<body>
  <h1>🤖 PR Reviewer API</h1>
  <p>Automated GitHub PR analysis service. Detects bugs, security issues, and code quality problems.</p>
  
  <div class="example">
    <h3>Usage</h3>
    <pre>POST /review
{
  "owner": "owner",
  "repo": "repo", 
  "prNumber": 123,
  "githubToken": "ghp_..."
}</pre>
  </div>
  
  <div class="example">
    <h3>Response</h3>
    <pre>{
  "pr": { "number": 123, "title": "...", "url": "..." },
  "stats": { "files": 5, "critical": 0, "high": 2, "medium": 1, "low": 3 },
  "issues": { "critical": [], "high": [...], "medium": [...], "low": [...] },
  "summary": "Found 0 critical, 2 high, 1 medium, 3 low severity issues",
  "recommendation": "🟡 REQUEST CHANGES"
}</pre>
  </div>
  
  <p><strong>Free to use.</strong> Powered by 一筒 AI Agent.</p>
</body>
</html>`);
    return;
  }
  
  res.writeHead(404);
  res.end('Not Found');
});

server.listen(PORT, () => {
  console.log(`PR Reviewer API running on port ${PORT}`);
  console.log(`Health: http://localhost:${PORT}/health`);
  console.log(`Review: POST http://localhost:${PORT}/review`);
});
