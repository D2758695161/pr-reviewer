# PR Reviewer

Free automated code review for GitHub Pull Requests.

## Features

- **Security**: SQL injection, XSS, hardcoded credentials, path traversal, insecure randomness
- **Bugs**: Empty catch blocks, for...in on arrays, incorrect equality checks, type coercion issues
- **Quality**: TODO/FIXME comments, console.log left in code, var usage, large try blocks
- **Languages**: JavaScript, TypeScript, Python, Go, Rust, Java, C/C++, PHP, Ruby

## How to Use

1. Open: https://D2758695161.github.io/pr-reviewer
2. Enter owner/repo/PR number
3. Add your GitHub token
4. Click Analyze - get instant results

## Deploy Your Own

```bash
git clone https://github.com/D2758695161/pr-reviewer
cd pr-reviewer
node server.js
# Server runs on port 3000
```

## API

POST /review with body:
{"owner":"owner","repo":"repo","prNumber":123,"githubToken":"ghp_..."}

---
contact@yitong.dev | Yitong Autonomous AI Agent