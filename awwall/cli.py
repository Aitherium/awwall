"""awwall CLI: check and manage egress allowlists."""

import argparse
import json
import sys
from pathlib import Path

from awwall import AllowRule, Policy

DEFAULT_POLICY_FILE = Path.home() / ".awwall" / "policy.json"

def load_policy(policy_file=None):
    """Load policy from file or return empty policy."""
    if policy_file is None:
        policy_file = DEFAULT_POLICY_FILE

    if isinstance(policy_file, str):
        policy_file = Path(policy_file)

    if policy_file.exists():
        try:
            with open(policy_file, encoding='utf-8') as f:
                data = json.load(f)
            return Policy.from_dict(data)
        except Exception as e:
            print(f"ERROR: Failed to load policy: {e}", file=sys.stderr)
            return None

    return Policy()

def save_policy(policy, policy_file=None):
    """Save policy to file."""
    if policy_file is None:
        policy_file = DEFAULT_POLICY_FILE

    if isinstance(policy_file, str):
        policy_file = Path(policy_file)

    policy_file.parent.mkdir(parents=True, exist_ok=True)

    with open(policy_file, 'w', encoding='utf-8') as f:
        json.dump(policy.to_dict(), f, indent=2)

def cmd_allow(args):
    """Add an allowed host to the policy."""
    policy = load_policy(args.policy_file)
    if policy is None:
        return 2

    # Determine rule type
    if args.type:
        rule_type = args.type
    else:
        if '*' in args.host:
            rule_type = 'glob'
        elif args.host.startswith('.') or '.' not in args.host:
            rule_type = 'domain' if '.' not in args.host or args.host.startswith('.') else 'exact'
        else:
            rule_type = 'domain' if args.as_domain else 'exact'

    new_rule = AllowRule(args.host, rule_type, args.description or "")

    # Check for duplicates
    for rule in policy.rules:
        if rule.pattern.lower() == args.host.lower() and rule.rule_type == rule_type:
            print(f"Rule already exists: {rule.pattern} ({rule_type})", file=sys.stderr)
            return 1

    policy.rules.append(new_rule)
    save_policy(policy, args.policy_file)
    print(f"Added: {args.host} ({rule_type})")
    return 0

def cmd_check(args):
    """Check if a host is allowed."""
    policy = load_policy(args.policy_file)
    if policy is None:
        return 2

    allowed, rule = policy.check(args.host)

    if allowed:
        if args.verbose:
            print(f"ALLOWED: {args.host} (matches: {rule.pattern})")
        return 0
    else:
        if args.verbose:
            print(f"DENIED: {args.host} (no rule matched)")
        return 1

def cmd_explain(args):
    """Explain why a host was allowed or denied."""
    policy = load_policy(args.policy_file)
    if policy is None:
        return 2

    allowed, rule = policy.check(args.host)

    if allowed:
        print(f"ALLOWED: {args.host}")
        print(f"  Matched rule: {rule.pattern} (type: {rule.rule_type})")
        if rule.description:
            print(f"  Description: {rule.description}")
        return 0
    else:
        print(f"DENIED: {args.host}")
        if policy.rules:
            print(f"  Reason: No rule matched (checked {len(policy.rules)} rule(s))")
        else:
            print("  Reason: Policy is empty (default deny)")
        return 1

def cmd_emit(args):
    """Emit policy in different formats."""
    policy = load_policy(args.policy_file)
    if policy is None:
        return 2

    if args.format == 'hosts':
        output = policy.to_hosts_format()
    elif args.format == 'iptables':
        output = policy.to_iptables_format()
    elif args.format == 'json':
        output = json.dumps(policy.to_dict(), indent=2)
    else:
        print(f"Unknown format: {args.format}", file=sys.stderr)
        return 1

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(output)
        print(f"Wrote {args.format} format to {args.output}")
        return 0
    else:
        print(output, end='')
        return 0

def cmd_list(args):
    """List all rules in the policy."""
    policy = load_policy(args.policy_file)
    if policy is None:
        return 2

    if not policy.rules:
        print("No rules defined (default: deny everything)")
        return 0

    print(f"Policy rules ({len(policy.rules)} total):\n")
    for i, rule in enumerate(policy.rules, 1):
        desc = f" - {rule.description}" if rule.description else ""
        print(f"  {i}. {rule.pattern} [{rule.rule_type}]{desc}")

    return 0

def cmd_self_test(args):
    """Run self-tests to verify the policy engine."""
    print("Running awwall self-tests...")

    # Test 1: Default deny (empty policy)
    empty_policy = Policy()
    allowed, _ = empty_policy.check("example.com")
    assert not allowed, "FAIL: Empty policy should deny all hosts"
    print("  [PASS] Empty policy denies all")

    # Test 2: Exact match
    exact_policy = Policy([AllowRule("example.com", "exact")])
    allowed, rule = exact_policy.check("example.com")
    assert allowed and rule.pattern == "example.com", "FAIL: Exact match failed"
    print("  [PASS] Exact match works")

    # Test 3: Exact match negative (should deny similar)
    allowed, _ = exact_policy.check("api.example.com")
    assert not allowed, "FAIL: Exact match should not match subdomain"
    print("  [PASS] Exact match rejects subdomains")

    # Test 4: Domain match (includes subdomains)
    domain_policy = Policy([AllowRule("example.com", "domain")])
    allowed, _ = domain_policy.check("api.example.com")
    assert allowed, "FAIL: Domain match should include subdomains"
    print("  [PASS] Domain match includes subdomains")

    # Test 5: Domain doesn't match different domain
    allowed, _ = domain_policy.check("notexample.com")
    assert not allowed, "FAIL: Domain match should not match different domain"
    print("  [PASS] Domain match rejects different domain")

    # Test 6: Glob pattern
    glob_policy = Policy([AllowRule("*.example.com", "glob")])
    allowed, _ = glob_policy.check("api.example.com")
    assert allowed, "FAIL: Glob pattern failed"
    print("  [PASS] Glob pattern works")

    # Test 7: Glob denies non-matching
    allowed, _ = glob_policy.check("api.other.com")
    assert not allowed, "FAIL: Glob should deny non-matching"
    print("  [PASS] Glob rejects non-matching")

    # Test 8: Case insensitivity
    allowed, _ = exact_policy.check("EXAMPLE.COM")
    assert allowed, "FAIL: Policy should be case-insensitive"
    print("  [PASS] Case insensitive matching")

    # Test 9: Whitespace trimming
    allowed, _ = exact_policy.check("  example.com  ")
    assert allowed, "FAIL: Policy should trim whitespace"
    print("  [PASS] Whitespace trimming works")

    # Test 10: Malformed policy rejection
    try:
        Policy.from_dict({"rules": "not-a-list"})
        assert False, "FAIL: Should reject malformed policy"
    except ValueError:
        print("  [PASS] Rejects malformed policy")

    # Test 11: Fail-closed on missing policy file
    missing_policy = load_policy("/nonexistent/path/policy.json")
    allowed, _ = missing_policy.check("example.com")
    assert not allowed, "FAIL: Missing policy file should use empty (deny-all) policy"
    print("  [PASS] Missing policy file defaults to deny-all")

    print("\nAll self-tests passed!")
    return 0

def main():
    """Main CLI entry point."""
    # GENERATED doctor intercept (gen_aw_doctor.py) -- do not edit
    _dv = locals().get("argv")
    if (_dv if _dv is not None else __import__("sys").argv[1:])[:1] == ["doctor"]:
        from ._doctor import report
        return report()
    parser = argparse.ArgumentParser(
        prog='awwall',
        description='Egress allowlist that fails closed: declare what a workload '
                    'may reach, watch everything else fail with the rule that '
                    'denied it.'
    )

    parser.add_argument(
        '--policy-file', type=str,
        help=f'Policy file (default: {DEFAULT_POLICY_FILE})')
    parser.add_argument('--self-test', action='store_true', help='Run self-tests')

    subparsers = parser.add_subparsers(dest='command', help='Command to run')

    # allow command
    allow_parser = subparsers.add_parser('allow', help='Add a host to the allowlist')
    allow_parser.add_argument('host', help='Hostname to allow')
    allow_parser.add_argument(
        '--type', choices=['exact', 'domain', 'glob'],
        help='Rule type (auto-detect if not specified)')
    allow_parser.add_argument(
        '--as-domain', action='store_true',
        help='Treat as domain rule (default for multi-part hosts)')
    allow_parser.add_argument('--description', help='Rule description')
    allow_parser.set_defaults(func=cmd_allow)

    # check command
    check_parser = subparsers.add_parser('check', help='Check if a host is allowed')
    check_parser.add_argument('host', help='Hostname to check')
    check_parser.add_argument(
        '-v', '--verbose', action='store_true', help='Verbose output')
    check_parser.set_defaults(func=cmd_check)

    # explain command
    explain_parser = subparsers.add_parser(
        'explain', help='Explain why a host is allowed or denied')
    explain_parser.add_argument('host', help='Hostname to explain')
    explain_parser.set_defaults(func=cmd_explain)

    # emit command
    emit_parser = subparsers.add_parser('emit', help='Emit policy in different formats')
    emit_parser.add_argument(
        '--format', choices=['hosts', 'iptables', 'json'],
        default='json', help='Output format')
    emit_parser.add_argument('--output', help='Output file (default: stdout)')
    emit_parser.set_defaults(func=cmd_emit)

    # list command
    list_parser = subparsers.add_parser('list', help='List all rules in the policy')
    list_parser.set_defaults(func=cmd_list)

    args = parser.parse_args()

    if args.self_test:
        return cmd_self_test(args)
    elif hasattr(args, 'func'):
        return args.func(args)
    else:
        parser.print_help()
        return 0

if __name__ == '__main__':
    sys.exit(main())

