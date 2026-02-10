# Burp Suite Regex Generator Pro v2.1

Production-ready Burp Suite extension for generating safe, performance-optimized regex patterns from selected HTTP request/response text.

## Key Features

### Pattern Categories
- **Exact Match**: Captured `(value)` and Anchored `^(value)$` modes
- **[RECOMMENDED]**: Context-aware patterns (JSON fields, HTML attributes)
- **[TYPE]**: Data-type specific patterns (URLs, emails, IDs, numbers)
- **[DEFAULT]**: Complete set of 19 textbook patterns always available

### Smart Detection
- Automatic JSON field detection: `"key":"value"`
- HTML attribute recognition: `attribute="value"`
- Flexible anchors using `\s*` instead of literal spaces
- Automatic pattern deduplication

## Installation

### Requirements
- Burp Suite Professional or Community Edition
- Jython 2.7.3+ standalone JAR

### Steps
1. Download Jython from https://www.jython.org/download
2. Burp Suite: `Extensions` -> `Extension Settings` -> Set Python Environment to Jython JAR
3. `Extensions` -> `Installed` -> `Add` -> Select `regex_generator_v2_refactored.py`
4. Verify: "Regex Generator Pro loaded successfully"

## Usage

1. Select text in any HTTP request/response
2. Right-click -> `Generate Regex for Selection`
3. Choose from three sections:
   - **Exact Match Options** (2 patterns)
   - **Context-Based Pattern Variations** (recommended and type-based)
   - **Default Textbook Patterns** (19 always-available patterns)
4. Copy pattern to clipboard

## Pattern Categories

### 1. Exact Match Options
- **Exact Match (Captured)**: `(selectedtext)` - For extraction
- **Exact Match (Anchored)**: `^(selectedtext)$` - For full-line matching

### 2. Context-Based Pattern Variations

#### [RECOMMENDED] Patterns (Context-Aware)
- **Exact with Context**: Includes surrounding JSON/HTML context
- **JSON Field - Any Value**: `"key":"([^"]{1,200})"` - Captures any JSON value (safe)
- **HTML Attribute - Any Value**: `attribute="([^"']{1,200})"` - Captures any attribute value (safe)

#### [TYPE] Patterns (Data-Type Specific)
- **URL - Any Protocol**: `(https?://[^\s"]{1,200})` - HTTP/HTTPS URLs
- **URL - Protocol Specific**: HTTPS only or HTTP only
- **URL - Same Domain**: Matches specific domain
- **Email - Any Address**: `([a-zA-Z0-9._%+-]{1,64}@[a-zA-Z0-9.-]{1,100}\.[a-zA-Z]{2,10})`
- **ID - Flexible Length**: `([a-zA-Z0-9_-]{min,max})` - Alphanumeric identifiers
- **Number - Exact Length**: `(\d{n})` - Fixed-length numbers
- **Dash-Separated Pattern**: Matches dash-separated structures

### 3. Default Textbook Patterns (19 Total)

Always available regardless of selected text:

| Pattern | Regex | Use Case |
|---------|-------|----------|
| JWT Token | `(eyJ[a-zA-Z0-9_-]{10,100}\.eyJ[a-zA-Z0-9_-]{10,100}\.[a-zA-Z0-9_-]{10,100})` | Authentication tokens |
| JSESSIONID | `(JSESSIONID=[A-F0-9]{16,64})` | Java session cookies |
| ASP.NET Session | `(ASP\.NET_SessionId=[a-zA-Z0-9]{16,64})` | .NET session IDs |
| Generic Token | `([a-zA-Z0-9_-]{20,80})` | Generic session/API tokens |
| UUID | `([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})` | Universal IDs |
| IPv4 Address | `(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})` | IP addresses |
| Email | `([a-zA-Z0-9._%+-]{1,64}@[a-zA-Z0-9.-]{1,100}\.[a-zA-Z]{2,10})` | Email validation |
| MD5 Hash | `([a-fA-F0-9]{32})` | MD5 checksums |
| SHA1 Hash | `([a-fA-F0-9]{40})` | SHA1 checksums |
| SHA256 Hash | `([a-fA-F0-9]{64})` | SHA256 checksums |
| Base64 | `([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}\|[A-Za-z0-9+/]{3}=\|[A-Za-z0-9+/]{2}==)` | Base64 encoded |
| MAC Address | `([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})` | Network addresses |
| Hex Color | `(#[a-fA-F0-9]{6})` | Color codes |
| Date (YYYY-MM-DD) | `(\d{4}-\d{2}-\d{2})` | ISO dates |
| Date (MM/DD/YYYY) | `(\d{2}/\d{2}/\d{4})` | US dates |
| Time (24h) | `(\d{2}:\d{2}:\d{2})` | Time format |
| Phone (US) | `(\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4})` | US phone numbers |
| Credit Card | `(\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4})` | Card numbers |
| US SSN | `(\d{3}-\d{2}-\d{4})` | Social Security |

### Hard Limits (Code-Enforced)
- Absolute maximum: 500 characters (cannot be bypassed)
- Blocks nested quantifiers: `(.+)+`, `(.*)*`, `.*.*`
- Blocks unbounded patterns: `{0,}`, `.+`, `.*`, `[^\s]+`
- Safe fallback: `(.{1,100})` for dangerous patterns

### Unsafe Patterns (Never Generated)
```regex
(.+)              # Unbounded
([^\s"]+)         # Unbounded character class
(.*)*             # Nested quantifiers
(.+)+             # Catastrophic backtracking
{0,}              # Equivalent to * (unbounded)
```
---
