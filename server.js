/**
 * PR Reviewer API Server - Enhanced with more bug/security patterns
 * 
 * Run: node server.js
 */

const http = require('http');
const https = require('https');
const url = require('url');

const PORT = process.env.PORT || 3000;

// Enhanced security patterns
const SECURITY_PATTERNS = [
  { regex: /eval\s*\(|new\s+Function\s*\(/g, severity: 'CRITICAL', msg: 'Dynamic code execution - potential injection vulnerability', category: 'Security' },
  { regex: /innerHTML\s*=/g, severity: 'HIGH', msg: 'Direct DOM manipulation - potential XSS attack', category: 'Security' },
  { regex: /document\.write\s*\(/g, severity: 'HIGH', msg: 'Dynamic content injection - potential XSS', category: 'Security' },
  { regex: /password\s*=\s*['"][^'"]{1,30}['"]|api[_-]?key\s*=\s*['"][^'"]{10,}['"]|secret\s*=\s*['"][^'"]{10,}['"]/gi, severity: 'CRITICAL', msg: 'Hardcoded credential detected - remove immediately', category: 'Security' },
  { regex: /process\.env\.\w+\s*\|\|\s*['"][^'"]+['"]/g, severity: 'LOW', msg: 'Hardcoded fallback for environment variable', category: 'Security' },
  { regex: /WHERE\s+\w+\s*=\s*['"\.]+\s*\+|SQL\s*string.*\+|concat\([^)]*SELECT|concat\([^)]*INSERT/gi, severity: 'CRITICAL', msg: 'Potential SQL injection - use parameterized queries', category: 'Security' },
  { regex: /\.\.\/|\.\.\\\/|path\.join\([^)]+\+[^)]+\)/g, severity: 'HIGH', msg: 'Potential path traversal vulnerability', category: 'Security' },
  { regex: /crypto\.(createCipher|createDecipher)\(/g, severity: 'MEDIUM', msg: 'Deprecated crypto API - use crypto.createCipheriv', category: 'Security' },
  { regex: /Math\.random\(\)|\.random\(\).*password|\.random\(\).*token|\.random\(\).*id/g, severity: 'HIGH', msg: 'Math.random() is not cryptographically secure - use crypto.randomBytes()', category: 'Security' },
  { regex: /localhost.*CORS|CORS.*allow.*\*/gi, severity: 'MEDIUM', msg: 'Permissive CORS configuration may allow unauthorized access', category: 'Security' },
  { regex: /await\s+fetch\([^)]*\)\s*\.then\(/g, severity: 'LOW', msg: 'Mixed await and .then() - use consistent async/await', category: 'Style' },
];

// Bug patterns
const BUG_PATTERNS = [
  { regex: /try\s*\{[^}]*\}\s*catch[^}]*\{\s*\}/g, severity: 'MEDIUM', msg: 'Empty catch block - errors are silently ignored', category: 'Bug' },
  { regex: /===?\s*['"]undefined['"]|===?\s*['"]null['"]|===?\s*['"]true['"]|===?\s*['"]false['"]/g, severity: 'MEDIUM', msg: 'Use strict equality with literal values (use undefined/null without quotes)', category: 'Bug' },
  { regex: /for\s*\(\s*(var|let)\s+\w+\s+in\s+\w+\)/g, severity: 'MEDIUM', msg: 'for...in iterates over all enumerable properties - use for...of or Object.keys() for arrays', category: 'Bug' },
  { regex: /setTimeout\([^,]+,\s*0\)/g, severity: 'LOW', msg: 'Consider queueMicrotask() or Promise.resolve().then() instead', category: 'Style' },
  { regex: /new\s+Date\(\)\.getTime\(\)|new\s+Date\(\)\.valueOf\(\)/g, severity: 'LOW', msg: 'Use Date.now() instead of new Date().getTime()', category: 'Style' },
  { regex: /\[.*?\]\.join\([^)]*\)|Array\..*join\([^)]*\)/g, severity: 'LOW', msg: 'Array join result not used - likely forgot assignment', category: 'Bug' },
  { regex: /if\s*\([^)]+\)\s*\{[^}]*\}\s*else\s*\{[^}]*if/g, severity: 'LOW', msg: 'Deeply nested if-else chains - consider switch or early returns', category: 'Style' },
  { regex: /\+\s*''|\+\s*\"\"|\|\|\s*''|\|\|\s*\"\"/g, severity: 'LOW', msg: 'Redundant type coercion - value is already a string', category: 'Style' },
  { regex: /===.*instanceof|instanceof.*===/g, severity: 'MEDIUM', msg: 'instanceof with strict equality is unreliable - use typeof checks', category: 'Bug' },
];

// Quality patterns
const QUALITY_PATTERNS = [
  { regex: /console\.(log|debug|info)\s*\(/g, severity: 'LOW', msg: 'Debug console statement left in production code', category: 'Quality' },
  { regex: /\/\/\s*(TODO|FIXME|HACK|XXX):|\/\/\s*NOTE:|\/\/\s*BUG:/g, severity: 'LOW', msg: 'Unresolved TODO/FIXME comment - create an issue', category: 'Quality' },
  { regex: /\bvar\s+\w+/g, severity: 'LOW', msg: 'Use of var - prefer const or let for better scoping', category: 'Style' },
  { regex: /==\s*(?!null|undefined|true|false)[^=]/g, severity: 'LOW', msg: 'Use === instead of == for strict comparison', category: 'Style' },
  { regex: /void\s+0|void\s+[^s]/g, severity: 'LOW', msg: 'void expression found - clarify intent or use undefined directly', category: 'Style' },
  { regex: /;\s*$/gm, severity: 'INFO', msg: 'Trailing semicolon', category: 'Style' },
  { regex: /\/\/.*\r?\n\s*\/\//g, severity: 'INFO', msg: 'Consecutive single-line comments - consider combining', category: 'Style' },
  { regex: /try\s*\{[^}]{500,}\}/g, severity: 'MEDIUM', msg: 'Very large try block - consider extracting to a function', category: 'Quality' },
];

function analyzeContent(content, filename) {
  if (!content) return [];
  const issues = [];
  const lines = content.split('\n');
  const allPatterns = [...SECURITY_PATTERNS, ...BUG_PATTERNS, ...QUALITY_PATTERNS];
  
  lines.forEach((line, i) => {
    // Skip comments and strings in some cases
    const trimmed = line.trim();
    
    allPatterns.forEach(p => {
      // Don't flag commented-out code for most patterns
      const isCommented = trimmed.startsWith('//') || trimmed.startsWith('*');
      if (isCommented && p.category !== 'Quality') return;
      
      if (line.match(p.regex)) {
        issues.push({
          type: p.severity,
          category: p.category,
          file: filename,
          line: i + 1,
          msg: p.msg,
          code: line.trim().substring(0, 100)
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
      headers: { 
        'Authorization': 'token ' + token, 
        'User-Agent': 'PRReviewer/1.0', 
        'Accept': 'application/vnd.github.v3+json' 
      }
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
  const pr = await githubGet(`/repos/${owner}/${repo}/pulls/${prNumber}`, token);
  if (!pr || !pr.number) {
    throw new Error('PR not found or access denied. Check that the repo is public or your token is valid.');
  }
  
  // Get files changed (up to 30 files for performance)
  const files = await githubGet(`/repos/${owner}/${repo}/pulls/${prNumber}/files?per_page=30`, token);
  
  const allIssues = [];
  let totalLines = 0;
  
  if (Array.isArray(files)) {
    for (const file of files) {
      if (!file.patch || file.status === 'removed') continue;
      
      // Reconstruct content from patch
      const content = file.patch.split('\n')
        .filter(l => !l.startsWith('+++') && !l.startsWith('---'))
        .map(l => l.startsWith('+') ? l.substring(1) : l.startsWith('-') ? '' : l)
        .join('\n');
      
      totalLines += content.split('\n').length;
      const issues = analyzeContent(content, file.filename);
      issues.forEach(i => allIssues.push(i));
    }
  }
  
  const critical = allIssues.filter(i => i.type === 'CRITICAL');
  const high = allIssues.filter(i => i.type === 'HIGH');
  const medium = allIssues.filter(i => i.type === 'MEDIUM');
  const low = allIssues.filter(i => i.type === 'LOW');
  const info = allIssues.filter(i => i.type === 'INFO');
  
  const byCategory = {
    Security: allIssues.filter(i => i.category === 'Security').length,
    Bug: allIssues.filter(i => i.category === 'Bug').length,
    Quality: allIssues.filter(i => i.category === 'Quality').length,
    Style: allIssues.filter(i => i.category === 'Style').length,
  };
  
  return {
    pr: { 
      number: pr.number, 
      title: pr.title, 
      url: pr.html_url, 
      author: pr.user.login,
      state: pr.state,
      additions: pr.additions,
      deletions: pr.deletions,
      changedFiles: pr.changed_files
    },
    stats: {
      files: files?.length || 0,
      linesAnalyzed: totalLines,
      critical: critical.length,
      high: high.length,
      medium: medium.length,
      low: low.length,
      info: info.length,
      byCategory
    },
    issues: { critical, high, medium, low, info },
    summary: allIssues.length === 0 
      ? 'Code looks clean - no major issues detected.'
      : `Found ${critical.length} critical, ${high.length} high, ${medium.length} medium, ${low.length} low severity issues across ${files?.length || 0} files.`,
    recommendation: critical.length > 0 ? '🔴 REQUEST CHANGES' 
      : high.length > 0 ? '🟡 REQUEST CHANGES'
      : medium.length > 2 ? '🟡 REQUEST CHANGES'
      : '🟢 APPROVE',
    analyzedAt: new Date().toISOString()
  };
}

const server = http.createServer(async (req, res) => {
  const parsedUrl = url.parse(req.url, true);
  
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
    res.end(JSON.stringify({ status: 'ok', service: 'PR Reviewer API', version: '2.0' }));
    return;
  }
  
  if (parsedUrl.pathname === '/patterns') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ 
      patterns: {
        security: SECURITY_PATTERNS.length,
        bugs: BUG_PATTERNS.length,
        quality: QUALITY_PATTERNS.length,
        total: SECURITY_PATTERNS.length + BUG_PATTERNS.length + QUALITY_PATTERNS.length
      },
      languages: ['JavaScript', 'TypeScript', 'Python', 'Go', 'Rust', 'Java', 'C/C++', 'PHP', 'Ruby']
    }));
    return;
  }
  
  if (parsedUrl.pathname === '/review' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
      try {
        const { owner, repo, prNumber, githubToken } = JSON.parse(body);
        
        if (!owner || !repo || !prNumber) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Missing required fields: owner, repo, prNumber' }));
          return;
        }
        
        if (!githubToken) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'githubToken is required. Provide a GitHub PAT with repo scope.' }));
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
    .endpoint { margin: 1.5rem 0; }
  </style>
</head>
<body>
  <h1>PR Reviewer API v2</h1>
  <p>Automated GitHub PR analysis - Security, Bug, and Quality detection.</p>
  
  <div class="endpoint">
    <h3>POST /review</h3>
    <pre>{"owner": "owner", "repo": "repo", "prNumber": 123, "githubToken": "ghp_..."}</pre>
  </div>
  
  <div class="endpoint">
    <h3>GET /patterns</h3>
    <p>Returns detection pattern count.</p>
  </div>
  
  <div class="endpoint">
    <h3>GET /health</h3>
    <p>Service health check.</p>
  </div>
  
  <p><strong>Powered by Yitong AI Agent.</strong> contact@yitong.dev</p>
</body>
</html>`);
    return;
  }
  
  res.writeHead(404);
  res.end('Not Found');
});

server.listen(PORT, () => {
  console.log('PR Reviewer API v2 running on port', PORT);
});
