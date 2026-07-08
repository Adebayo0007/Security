# AppSec Toolkit: Claude Code Review Prompt + Free Tool Pipeline

This is a practical setup for using Claude as your code-review layer alongside four free/open-source AppSec tools (CodeQL, OWASP ZAP, Dependabot, GitLeaks).

---

## Part 1 — The Claude Code Review Prompt

Use this in **Claude Code** (best — it can read your whole repo and run follow-up searches) or paste code directly into a Claude chat. Fill in the bracketed parts.

```
You are performing a defensive application security code review. Review the code in [FILE PATH / DIRECTORY / PASTE BELOW] for the following vulnerability classes only. For each one you find, report:

1. Vulnerability class
2. File and line number
3. The vulnerable code snippet
4. Why it's exploitable (data flow: where does untrusted input enter, and what dangerous sink does it reach?)
5. Severity (Critical / High / Medium / Low)
6. A concrete, minimal fix (code diff if possible)

Check specifically for:

- SQL Injection: user input reaching database queries via string concatenation/formatting instead of parameterized queries or an ORM's safe query builder.
- Cross-Site Scripting (XSS): user-controlled data rendered into HTML, JS, or DOM without encoding/escaping (check templates, innerHTML, dangerouslySetInnerHTML, response bodies).
- Command Injection: user input reaching shell execution (exec, system, subprocess with shell=True, os.system, Runtime.exec, child_process.exec, backticks).
- Path Traversal: user-controlled values used in file paths without validation/normalization (look for path concatenation with request params, missing checks against ../ or absolute paths).
- Hardcoded Secrets: API keys, passwords, tokens, connection strings embedded directly in source (not in env vars or a secrets manager).
- Insecure Cryptography: use of MD5, SHA1, DES, ECB mode, or non-cryptographic random number generators (e.g. Math.random(), random.random()) for security-sensitive purposes (tokens, passwords, keys).
- Insecure Deserialization: BinaryFormatter (C#), ObjectInputStream.readObject (Java), pickle.loads/yaml.load without SafeLoader (Python) operating on untrusted/user-supplied data.
- SSRF: server-side HTTP/network requests where the destination URL or host is influenced by user input, without an allowlist.
- Second-Order Injection: user input stored in one request (DB, file, cache) and later used unsafely in a dangerous sink during a different request/operation.

Rules:
- Only flag things that are actually reachable by untrusted input — trace the data flow, don't just pattern-match function names.
- If something looks suspicious but you can't confirm the input source, say so explicitly and mark it "needs verification" rather than a confirmed finding.
- Do not modify code unless I ask you to fix a specific finding.
- End with a one-paragraph summary and a prioritized fix order.
```

**Tips for using this well:**
- In Claude Code, point it at a whole service/module rather than one file — data-flow tracing needs the caller/callee context.
- Run it per-module for large codebases rather than the whole repo at once; taint tracing degrades with huge context.
- Treat this as a *first-pass triage*, same as pattern-matching SAST — pair it with CodeQL (below) for deeper interprocedural analysis, and don't treat "no findings" as "no vulnerabilities."

---

## Part 2 — CI/CD Pipeline (Free Tools)

GitHub Actions workflow wiring together secrets scanning, SAST, SCA, and DAST. Save as `.github/workflows/appsec.yml`.

```yaml
name: AppSec Pipeline (Free Tools)

on:
  pull_request:
    branches: [main, develop]
  push:
    branches: [main]
  schedule:
    - cron: '0 3 * * 1'  # weekly DAST run against staging

jobs:
  secrets-scan:
    name: GitLeaks (Secrets)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Run GitLeaks
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

  codeql-sast:
    name: CodeQL (SAST)
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    strategy:
      matrix:
        language: [ 'javascript', 'python' ]  # edit to match your stack
    steps:
      - uses: actions/checkout@v4
      - name: Initialize CodeQL
        uses: github/codeql-action/init@v3
        with:
          languages: ${{ matrix.language }}
      - name: Autobuild
        uses: github/codeql-action/autobuild@v3
      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@v3

  # SCA: Dependabot isn't a workflow step — enable it via a repo config file (below).
  # This job just fails the build if Dependabot has open critical/high alerts.
  dependabot-gate:
    name: Dependabot Alert Gate (SCA)
    runs-on: ubuntu-latest
    steps:
      - name: Check for open critical/high Dependabot alerts
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          gh api /repos/${{ github.repository }}/dependabot/alerts \
            --jq '[.[] | select(.state=="open" and (.security_advisory.severity=="critical" or .security_advisory.severity=="high"))] | length' > count.txt
          COUNT=$(cat count.txt)
          echo "Open critical/high Dependabot alerts: $COUNT"
          if [ "$COUNT" -gt 0 ]; then
            echo "::error::$COUNT open critical/high severity dependency vulnerabilities"
            exit 1
          fi

  dast-zap:
    name: OWASP ZAP (DAST)
    runs-on: ubuntu-latest
    if: github.event_name == 'schedule' || github.ref == 'refs/heads/main'
    steps:
      - name: ZAP Baseline Scan
        uses: zaproxy/action-baseline@v0.12.0
        with:
          target: ${{ secrets.STAGING_URL }}
          rules_file_name: '.zap/rules.tsv'
          cmd_options: '-a'
```

**Enable Dependabot** by adding `.github/dependabot.yml`:

```yaml
version: 2
updates:
  - package-ecosystem: "npm"        # add one block per ecosystem you use
    directory: "/"
    schedule:
      interval: "weekly"
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
```

Then in repo Settings → Code security, turn on **Dependabot alerts** and **Secret scanning** (GitHub's built-in one, as a second layer alongside GitLeaks).

---

## Part 3 — Making Sense of the Output (Claude's role)

Once the pipeline runs, you'll have four separate outputs in different formats (CodeQL SARIF, ZAP HTML/JSON report, Dependabot alerts, GitLeaks findings). Use Claude to triage:

```
I'm giving you output from [CodeQL / ZAP / Dependabot / GitLeaks] for our application.
Here is the raw finding: [paste finding/alert]

Please tell me:
1. In plain terms, what is this vulnerability and how would it actually be exploited in our app?
2. Is this a true positive or likely false positive, based on the code context I've also included?
3. Severity and urgency to fix (consider: is this reachable by an unauthenticated attacker, does it touch sensitive data?)
4. Concrete fix — code diff if you have enough context, otherwise the general remediation pattern.
5. Should this block the PR/merge, or can it be tracked as a follow-up ticket?

Code context: [paste relevant function/file]
```

This turns four noisy tool outputs into one consistent, prioritized backlog — which solves the "high false positive rate → developers ignore everything" problem the article flagged.

---

## Note on scope

Claude will help review your own code for these vulnerabilities and build/interpret this defensive pipeline. It won't write exploit payloads, attack scripts, or offensive tooling — the review prompt above is scoped to identification and remediation, which keeps it squarely in defensive territory.
