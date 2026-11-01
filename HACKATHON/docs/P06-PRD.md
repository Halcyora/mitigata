# P06 PRD: SAST and DAST Correlation
## Product Requirements Document

> **Status:** Updated to match the current repo snapshot and implementation plan in `engine/README.md`.
> **Author:** Anuj · **Date:** 30 October 2026  
> **Problem:** 06 · **Flagship Challenge** — bonus points on top of normal score  
> **One-line mission:** Scan source code + running app, link the two views of every bug into one prioritised list.
>
> This PRD remains the product-level source of truth, but the implementation now reflects the checked-in Docker target setup, per-target YAML profiles, local host-mode runner, bounded verification workflow, and code-aware route correlation in the `HACKATHON` codebase. Use the code and scripts as the latest execution reference; treat the PRD as the contract for judged outcomes.

---

## Table of Contents

1. [Overview and Problem Statement](#1-overview-and-problem-statement)
2. [Goals and Non-Goals](#2-goals-and-non-goals)
3. [Functional Requirements](#3-functional-requirements)
   - 3.1 [Must Have (FR-1 – FR-10)](#31-must-have-fr-1--fr-10)
   - 3.2 [Bonus Features (B-1 – B-7)](#32-bonus-features-b-1--b-7)
4. [Test Application and Answer Key](#4-test-application-and-answer-key)
5. [Vulnerability Types](#5-vulnerability-types)
6. [Performance Targets](#6-performance-targets)
7. [Rules and Constraints](#7-rules-and-constraints)
8. [Bonus: Reachability-Aware SCA](#8-bonus-reachability-aware-sca)
9. [Suggested Tools](#9-suggested-tools)

---

## 1. Overview and Problem Statement

Build a tool that scans an application's source code and its running version, then connects the two sets of results, so **each real vulnerability appears once**, with the line of code that causes it and the proof that it can be exploited.

### The Setting

A company runs an online shop as a web application. Its security team uses two kinds of scanners:

- A **static scanner (SAST)** reads the source code without running it.
- A **dynamic scanner (DAST)** attacks the running application from the outside, the way a real attacker would.

Each produces its own report in its own format.

### The Problem — The Two Reports Never Meet

| Problem | Description |
|---|---|
| **Same bug, two tickets** | SAST says "SQL injection in orders.py, line 88". DAST says "SQL injection at /api/orders, parameter id". It is one bug, but nobody can see that — it gets fixed twice or not at all. |
| **Too much noise** | SAST reports hundreds of findings, many of them safe or in code that can never be reached. Developers stop trusting the list. |
| **No place to fix** | A DAST finding proves the app can be attacked but does not say which code to change. |
| **No clear priority** | A bug found in the code and proven exploitable matters more than a guess, but no report shows the difference. |

### Your Challenge

Build a tool that:

1. **Scans source code (SAST)**
2. **Scans a running application (DAST)**
3. **Correlates the two** — links a runtime finding to the code that causes it, merges duplicates, and produces one prioritised list

You can build one combined tool, or separate SAST and DAST scanners that feed a shared correlation engine. **Correlation is what we judge most.**

> You can choose any approach and any tech stack, and you may build on open-source scanners as long as you say so in the README.

---

## 2. Goals and Non-Goals

### Goals

| Goal | Description |
|---|---|
| **Scan code (SAST)** | Find vulnerabilities in the source code, with file and line |
| **Scan the running app (DAST)** | Find vulnerabilities by sending test requests, with URL, parameter and payload |
| **One common format** | Both scanners report findings in the same shape, using a CWE number for the vulnerability type |
| **Correlate** | Link the code finding and the runtime finding of the same bug into one issue |
| **Prioritise** | Show confirmed issues first, with a risk score |
| **Actionable** | For each issue, show where it is (URL and code line), how it was proven and what to fix |
| **Accurate** | Few wrong links and few false alarms |
| **Safe** | Scans only the test app that the organisers provide |

### Not Required

- A polished UI — a simple web page, a command-line report or a notebook is fine
- Finding every type of vulnerability — a few types done well beat many done badly
- Fixing the code automatically
- Login, user management or cloud deployment
- Support for many programming languages — the test app uses one

---

## 3. Functional Requirements

### 3.1 Must Have (FR-1 – FR-10)

Your tool must scan the test app's code and running instance, correlate the findings and show one prioritised list. Cover at least **four of the six vulnerability types** in §5, including SQL injection and cross-site scripting.

| ID | Feature | Example |
|---|---|---|
| **FR-1** | **SAST scan:** scan a source folder and report findings with file, line, vulnerability type, severity and the code snippet | SQL injection, orders.py line 88, CWE-89 |
| **FR-2** | **DAST scan:** scan a running app URL by sending test requests and report findings with URL, method, parameter, payload and evidence | `GET /api/orders?id=1'` returns a database error |
| **FR-3** | **One common finding format** for both scanners, with a CWE number for the type | Both sides report SQL injection as CWE-89 |
| **FR-4** | **Route map:** read the source code to list which URL is handled by which function and lines | `GET /api/orders → get_orders(), orders.py lines 80–95` |
| **FR-5** | **Correlate:** link a DAST finding to a SAST finding when they have the same CWE and the DAST URL is handled by the code that holds the SAST finding | DAST SQL injection on `/api/orders` + SAST SQL injection at `orders.py:88` = one confirmed issue |
| **FR-6** | **Merge duplicates:** one issue per real bug with all its evidence attached; running a scan twice does not create copies | 3 scanner findings on the same bug = 1 issue |
| **FR-7** | **Label every issue** as **Confirmed** (found by both), **Code only** (SAST, not proven) or **Runtime only** (DAST, no code location found) | Hard-coded secret = Code only |
| **FR-8** | **Issue detail for confirmed issues:** URL, parameter, payload, file, line, code snippet, CWE and severity | One page that tells a developer where to look |
| **FR-9** | **Prioritised list:** confirmed issues first, then by risk score (severity and how easy it is to exploit) | Confirmed SQL injection above a Code only weak hash |
| **FR-10** | **Simple command line, API or page** with a short README | `POST /scans`, `GET /issues`, `GET /issues/7` |

---

### 3.2 Bonus Features (B-1 – B-7)

Pick any bonus items for extra points.

| ID | Feature |
|---|---|
| **B-1** | **Auto-verify:** for a Code only finding, send a safe test request to try to prove it at runtime and upgrade it to Confirmed |
| **B-2** | **Cut SAST noise:** mark findings as safe when the code is protected (e.g. a parameterised query) or no URL can reach it |
| **B-3** | **Explain every link:** show why two findings were joined (same CWE, same route, same parameter) |
| **B-4** | **Plain-English fix suggestion** for each confirmed issue |
| **B-5** | **Compare two scans** and show new, fixed and still-open issues |
| **B-6** | **Export results as SARIF** and fail a CI build on confirmed high-severity issues |
| **B-7** | **Support a second programming language** or framework |

---

## 4. Test Application and Answer Key

> The organisers provide the test app at kickoff.

### Test Application Specification

- **One test app:** a small web shop with about **30 URLs**, its source code and a Docker Compose file to run it on your own machine.
- **Planted vulnerabilities with an answer key:** **36 in total**:
  - **20** can be found in both the code and the running app — these are the **pairs to link** (Confirmed candidates)
  - **10** only in the code (e.g. hard-coded secrets) — Code only candidates
  - **6** only at runtime (e.g. missing security headers) — Runtime only candidates
- **Safe decoys:** about **8** pieces of code that look dangerous but are safe, such as a properly parameterised database query. Reporting one is a false alarm.
- **An unseen second app:** at judging, your tool also runs on a second app with the same kinds of bugs, to check that it is not tuned only to the test app.

### Answer Key Summary

| Category | Count | Label |
|---|---|---|
| Code + Runtime pairs (linkable) | 20 | Confirmed |
| Code only (e.g. hardcoded secrets) | 10 | Code only |
| Runtime only (e.g. missing headers) | 6 | Runtime only |
| Safe decoys (false positive traps) | ~8 | Should NOT be reported |
| **Total planted** | **36** | |

---

## 5. Vulnerability Types

Cover **at least four** of the six types. **SQL injection and XSS are mandatory.**

| Type | CWE | Can Be Found By |
|---|---|---|
| **SQL injection** *(mandatory)* | CWE-89 | Code and runtime |
| **Cross-site scripting (XSS)** *(mandatory)* | CWE-79 | Code and runtime |
| Command injection | CWE-78 | Code and runtime |
| Path traversal | CWE-22 | Code and runtime |
| Open redirect | CWE-601 | Code and runtime |
| Hard-coded secrets | CWE-798 | Code only |

> **Note:** Path traversal (CWE-22) and Open redirect (CWE-601) replace Insecure Deserialisation (CWE-502) and JWT issues (CWE-347) from earlier drafts. Update all parsers and sink detectors accordingly.

---

## 6. Performance Targets

Measured against the answer key on the provided test app (and the unseen second app at judging).

| Metric | What We Measure | Good | Great |
|---|---|---|---|
| **Code detection** | Share of planted code vulnerabilities your SAST finds | > 60% | > 85% |
| **Runtime detection** | Share of planted runtime vulnerabilities your DAST finds | > 50% | > 80% |
| **Correct links** | Share of the 20 planted pairs linked into one Confirmed issue | > 50% | > 80% |
| **Wrong links** | Share of your Confirmed issues that join two different bugs | < 20% | < 5% |
| **False alarms** | Share of reported issues that are safe decoys | < 30% | < 10% |
| **Unseen app** | Share of planted pairs linked on the second app | > 40% | > 65% |
| **Run time** | Time to scan, correlate and produce the report on the test app | < 15 min | < 5 min |

### Target Summary Table

```
                      GOOD        GREAT
Code detection        > 60%       > 85%
Runtime detection     > 50%       > 80%
Correct links         > 50%       > 80%
Wrong links           < 20%       < 5%
False alarms          < 30%       < 10%
Unseen app            > 40%       > 65%
Run time              < 15 min    < 5 min
```

---

## 7. Rules and Constraints

| Rule | Detail |
|---|---|
| **Scan only the test app** | Point the DAST scanner only at the organisers' app running on your own machine. Scanning any other site or system is not allowed and leads to **disqualification**. |
| **Say what you used** | Open-source scanners and rule sets are allowed, but list them in the README. The correlation logic must be your own work. |
| **Must run easily** | Judges should be able to start it by following the README. Docker Compose is a plus. |

---

## 8. Bonus: Reachability-Aware SCA

Report whether the app can actually reach a vulnerable library function, not just that a CVE exists.

### Pipeline

| Step | Description |
|---|---|
| **1. Inventory** | Parse lockfiles into an SBOM, keeping transitive paths |
| **2. GHSA match** | Pull affected versions, fixes, CVSS, EPSS and KEV |
| **3. Function map** | Build from OSV symbols and fix-commit diffs (GHSA rarely lists functions) |
| **4. Call graph** | Link entry points, app functions and library functions (CodeQL, Joern, Semgrep) |
| **5. Supply chain** | Check for malicious packages, typosquats, dependency confusion and unpinned lockfiles |

### Reachability Statuses

| Status | Meaning |
|---|---|
| **Reachable** | App code calls the vulnerable library function via a traceable path |
| **Imported-only** | Library is imported but the vulnerable function is never called |
| **Present-only** | Library is in lockfile but never imported |
| **Unknown** | Reachability could not be determined — never downgrade Unknown |

> **Which language should this target first?** The test app's language (Python). Extend to a second language for B-7 bonus points.

---

## 9. Suggested Tools

> Not mandatory — you can use any stack. These are starting points.

| Component | Suggested Tool |
|---|---|
| SAST / code scanning | Semgrep or Bandit |
| DAST / runtime scanning | OWASP ZAP or Nuclei |
| Route map | Python's `ast` module or tree-sitter |
| Common results format | SARIF |
| Finding storage | SQLite or PostgreSQL |
| Containerisation | Docker Compose |

---

## Requirement Traceability Matrix

| Requirement | Maps To | Priority |
|---|---|---|
| FR-1 SAST scan | Code detection target (>60% / >85%) | P0 |
| FR-2 DAST scan | Runtime detection target (>50% / >80%) | P0 |
| FR-3 Common format | Enables FR-5 correlation | P0 |
| FR-4 Route map | Enables FR-5 correlation (URL → function) | P0 |
| FR-5 Correlate | Correct links target (>50% / >80%) | **P0 — judged most** |
| FR-6 Merge duplicates | Wrong links target (<20% / <5%) | P0 |
| FR-7 Labels | Prioritisation; False alarms target | P0 |
| FR-8 Issue detail | Actionability; Demo quality | P1 |
| FR-9 Prioritised list | Confirmed issues first | P1 |
| FR-10 CLI/API/page | Judges can run it | P0 |
| B-1 Auto-verify | Upgrades Code only → Confirmed | Bonus |
| B-2 Cut SAST noise | False alarms target (<30% / <10%) | Bonus |
| B-3 Explain links | Transparency / trust | Bonus |
| B-4 Fix suggestion | Actionability | Bonus |
| B-5 Scan diff | Regression tracking | Bonus |
| B-6 SARIF export + CI | DevSecOps integration | Bonus |
| B-7 Second language | Unseen app generalisation | Bonus |

---

*PRD version: 1.0 · Source: Anuj, 30 October 2026*  
*Related documents: [P06-SAST-DAST-Correlation-Engine.md](P06-SAST-DAST-Correlation-Engine.md) · [P06-Build-Plan.md](P06-Build-Plan.md) · [P06-Architecture.md](P06-Architecture.md)*
