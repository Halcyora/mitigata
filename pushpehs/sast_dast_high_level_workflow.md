# SAST--DAST Vulnerability Correlation Tool

## High-Level Workflow

### Project overview

The tool scans a web application's source code and running instance,
combines the results, and presents one prioritised list of security
issues. For confirmed issues, it also provides a plain-English
suggestion explaining how a developer can fix the problem.

We will validate the tool sequentially against two applications:

1.  **Vulnerable Flask App** --- Python and Flask.
2.  **OWASP Juice Shop** --- JavaScript/TypeScript, Express and Angular.

The scanning and correlation workflow stays the same for both
applications. Only the language-specific source-code parser and
framework route mapper change.

------------------------------------------------------------------------

## Workflow

### 1. Select and configure the application

-   Provide the application's source-code folder.
-   Provide the URL of its running instance.
-   Identify the programming language and framework.

**Output:** Application profile and scan configuration.

### 2. Scan the source code (SAST)

-   Run Semgrep against the source code.
-   Use the appropriate language-specific parser, such as Python AST or
    the TypeScript Compiler API.
-   Identify potential vulnerabilities and capture their file paths,
    line numbers and code snippets.

**Output:** Static-analysis findings.

### 3. Map application routes

-   Discover the application's routes and HTTP methods.
-   Identify the functions that handle those routes.
-   Map each route to its source file and relevant line numbers.

**Output:** Route map linking URLs to source-code locations.

### 4. Test the running application (DAST)

-   Connect to the running application.
-   Crawl accessible pages and endpoints.
-   Use OWASP ZAP to send controlled security test requests.
-   Capture the affected URL, method, parameter, payload and response
    evidence.

**Output:** Dynamic-analysis findings.

### 5. Normalise findings

-   Convert SAST and DAST results into one common finding format.
-   Map vulnerability types to CWE identifiers.
-   Standardise fields such as severity and evidence.

**Output:** Unified findings that can be compared.

### 6. Correlate, merge and classify issues

-   Compare SAST and DAST findings using CWE, route mapping and
    available evidence.
-   Link runtime findings to relevant source-code locations where the
    evidence supports the match.
-   Merge duplicate findings while retaining their evidence.
-   Classify each issue as:
    -   **Confirmed:** matching code and runtime evidence.
    -   **Code only:** detected in source code, but not demonstrated at
        runtime.
    -   **Runtime only:** detected at runtime, but no corresponding
        source-code location was found.

**Output:** Deduplicated and classified issues.

### 7. Prioritise issues and suggest fixes

-   Calculate a risk score using severity and exploitability.
-   Order issues so that higher-risk issues appear first.
-   For each confirmed issue, provide a plain-English fix suggestion
    (B-4), explaining what is wrong and how a developer can address it.

**Output:** Prioritised issues with remediation guidance.

### 8. Display the report

-   Show one prioritised list containing issues from both scanners.
-   Provide an issue detail view with CWE, severity, URL, parameter,
    payload, file, line, code snippet and supporting evidence where
    available.
-   Show the suggested fix for confirmed issues.
-   Retain scan history and results.

**Output:** A developer-friendly security report through the dashboard
or API.

------------------------------------------------------------------------

## Sequential application testing

  -----------------------------------------------------------------------
  Test stage              Application             Language-specific
                                                  analysis
  ----------------------- ----------------------- -----------------------
  Test 1                  Vulnerable Flask App    Python AST and Flask
                                                  route mapping

  Test 2                  OWASP Juice Shop        TypeScript/JavaScript
                                                  parsing and Express
                                                  route mapping
  -----------------------------------------------------------------------

Both applications use the same core components:

-   Semgrep and OWASP ZAP integration
-   Common finding format and CWE mapping
-   Correlation and deduplication
-   Issue classification and risk prioritisation
-   Plain-English fix suggestions for confirmed issues
-   Dashboard, API and scan reporting

## Overall flow

**Select application → SAST scan → Route mapping → DAST scan → Normalise
findings → Correlate and deduplicate → Classify and prioritise → Suggest
fixes → Display report**

## Key design principle

Build the core correlation and reporting engine once. Use language- and
framework-specific adapters for source-code parsing and route discovery.
This allows the same workflow to be tested against different application
technology stacks without creating separate scanners.
