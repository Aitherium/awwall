# awwall

Egress allowlist that fails closed: declare what a workload may reach, watch everything else fail with the rule that denied it.

## What It Does

**awwall** is a Python package that provides an egress allowlist policy engine. It works by:

1. **Failing closed by default** — an empty policy denies all outbound connections
2. **Allowing only what you declare** — add rules for hosts you trust
3. **Explaining denials** — when a connection is blocked, you see exactly which rule (or lack thereof) caused it
4. **Multiple output formats** — emit policy as JSON, `/etc/hosts`, or shell commands for iptables

Rules come in three types:
- **exact** — `example.com` matches only `example.com`
- **domain** — `example.com` matches `example.com`, `api.example.com`, `v1.api.example.com`, etc.
- **glob** — `*.example.com` matches any subdomain

## Installation

```bash
pip install awwall
```

## The Adoption Guarantee

Block one outbound host for one workload and watch the call fail closed with the rule that denied it.

```bash
# 1. Create an empty policy (denies everything)
$ awwall list
No rules defined (default: deny everything)

# 2. Check if google.com is allowed
$ awwall check google.com
$ echo $?
1  # Denied!

# 3. Explain why
$ awwall explain google.com
DENIED: google.com
  Reason: Policy is empty (default deny)

# 4. Allow one host
$ awwall allow github.com --type domain --description "GitHub repositories"
Added: github.com (domain)

# 5. Check again
$ awwall check github.com
$ echo $?
0  # Allowed!

$ awwall check api.github.com
$ echo $?
0  # Subdomains allowed too (domain rule)

# 6. But google.com is still blocked
$ awwall check google.com
$ echo $?
1  # Still denied

$ awwall explain google.com
DENIED: google.com
  Reason: No rule matched (checked 1 rule(s))
```

## CLI Commands

### `awwall allow <host>`
Add a host to the allowlist.

```bash
awwall allow api.example.com                    # Inferred as exact match
awwall allow example.com --type domain          # Explicit domain rule (allows subdomains)
awwall allow *.cdn.com --type glob              # Glob pattern
awwall allow example.com --description "Prod API" --type exact
```

### `awwall check <host>`
Check if a host is allowed (exit 0 = allowed, exit 1 = denied).

```bash
awwall check example.com        # Silent
awwall check example.com -v     # Verbose output
```

### `awwall explain <host>`
Explain why a host is allowed or denied.

```bash
$ awwall explain api.example.com
ALLOWED: api.example.com
  Matched rule: example.com (type: domain)
  Description: Production API
```

### `awwall emit --format <format>`
Emit policy in different formats.

```bash
awwall emit --format json                # Print as JSON
awwall emit --format hosts               # /etc/hosts format
awwall emit --format iptables            # Shell script with iptables rules
awwall emit --format json --output policy.json  # Save to file
```

### `awwall list`
List all rules in the policy.

```bash
$ awwall list
Policy rules (2 total):

  1. api.example.com [exact] - Production API
  2. example.com [domain] - All subdomains
```

### `awwall --self-test`
Run self-tests to verify the policy engine.

```bash
$ awwall --self-test
Running awwall self-tests...
  [PASS] Empty policy denies all
  [PASS] Exact match works
  [PASS] Exact match rejects subdomains
  [PASS] Domain match includes subdomains
  [PASS] Domain match rejects different domain
  [PASS] Glob pattern works
  [PASS] Glob rejects non-matching
  [PASS] Case insensitive matching
  [PASS] Whitespace trimming works
  [PASS] Rejects malformed policy
  [PASS] Missing policy file defaults to deny-all

All self-tests passed!
```

## Policy File Format

By default, policies are stored in `~/.awwall/policy.json`:

```json
{
  "rules": [
    {
      "pattern": "api.example.com",
      "rule_type": "exact",
      "description": "Production API"
    },
    {
      "pattern": "example.com",
      "rule_type": "domain",
      "description": "All example.com subdomains"
    },
    {
      "pattern": "*.cdn.com",
      "rule_type": "glob",
      "description": "CDN patterns"
    }
  ]
}
```

Specify a different file with `--policy-file`:

```bash
awwall --policy-file /etc/awwall/prod.json check example.com
```

## Exit Codes

- **0** — Success (check: host allowed, command worked)
- **1** — Denied (check: host blocked) or command failed
- **2** — Cannot judge (malformed policy, missing file in strict mode)

A policy file that cannot be parsed exits with code 2 (cannot judge), never 0. This prevents silent failures.

## Python API

```python
from awwall import Policy, AllowRule

# Create a policy
policy = Policy([
    AllowRule("example.com", "exact"),
    AllowRule("api.other.com", "domain"),
])

# Check a host
allowed, matching_rule = policy.check("api.other.com")
if allowed:
    print(f"Allowed by rule: {matching_rule.pattern}")
else:
    print("Denied: no rule matched")

# Load from file
policy = Policy.from_file("/path/to/policy.json")

# Load from dict
policy = Policy.from_dict({"rules": [...]})

# Export
print(policy.to_hosts_format())
print(policy.to_iptables_format())
```

## Testing

```bash
pytest tests/test_awwall.py -v
```

The test suite includes:
- **Default deny verification** — empty policy blocks everything
- **Rule type tests** — exact, domain, and glob matching
- **Negative tests** — verify rules DON'T match when they shouldn't
- **Fail-closed proofs** — malformed policy is treated as empty (deny all)
- **Roundtrip tests** — export and reimport preserves semantics

## Design Principles

1. **Fail closed by default** — empty policy denies all, malformed policy denies all
2. **Transparent denials** — every denied connection names the rule that caused it
3. **Simple rules** — exact, domain suffix, and glob patterns cover 99% of real use cases
4. **No magic** — no attempt to detect "safe" IPs or make assumptions
5. **Exportable** — policy can be rendered for other tools (hosts file, iptables, etc.)

## License

MIT
