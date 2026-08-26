"""Test suite for awwall."""

import pytest
from awwall import AllowRule, Policy


class TestAllowRule:
    """Test AllowRule creation."""

    def test_create_exact_rule(self):
        rule = AllowRule("example.com", "exact")
        assert rule.pattern == "example.com"
        assert rule.rule_type == "exact"
        assert rule.description == ""

    def test_create_rule_with_description(self):
        rule = AllowRule("example.com", "domain", "Production API")
        assert rule.description == "Production API"

class TestPolicyDefaults:
    """Test default deny behavior."""

    def test_empty_policy_denies_all(self):
        policy = Policy()
        allowed, rule = policy.check("example.com")
        assert not allowed, "Empty policy must deny all hosts"
        assert rule is None, "No rule should match on empty policy"

    def test_empty_policy_denies_localhost(self):
        policy = Policy()
        allowed, _ = policy.check("localhost")
        assert not allowed, "Empty policy must deny all hosts including localhost"

    def test_empty_policy_denies_ip(self):
        policy = Policy()
        allowed, _ = policy.check("127.0.0.1")
        assert not allowed, "Empty policy must deny all hosts including IPs"

class TestExactMatch:
    """Test exact match rules."""

    def test_exact_match_allows(self):
        policy = Policy([AllowRule("example.com", "exact")])
        allowed, rule = policy.check("example.com")
        assert allowed, "Exact match should allow exact hostname"
        assert rule.pattern == "example.com"

    def test_exact_match_denies_subdomain(self):
        policy = Policy([AllowRule("example.com", "exact")])
        allowed, _ = policy.check("api.example.com")
        assert not allowed, "Exact match should NOT allow subdomains"

    def test_exact_match_denies_partial(self):
        policy = Policy([AllowRule("example.com", "exact")])
        allowed, _ = policy.check("notexample.com")
        assert not allowed, "Exact match should NOT allow partial matches"

    def test_exact_match_case_insensitive(self):
        policy = Policy([AllowRule("Example.Com", "exact")])
        allowed, _ = policy.check("example.com")
        assert allowed, "Exact match should be case-insensitive"

        allowed, _ = policy.check("EXAMPLE.COM")
        assert allowed, "Exact match should be case-insensitive"

class TestDomainMatch:
    """Test domain match rules (with subdomain support)."""

    def test_domain_allows_exact(self):
        policy = Policy([AllowRule("example.com", "domain")])
        allowed, _ = policy.check("example.com")
        assert allowed, "Domain rule should allow exact domain"

    def test_domain_allows_subdomain(self):
        policy = Policy([AllowRule("example.com", "domain")])
        allowed, _ = policy.check("api.example.com")
        assert allowed, "Domain rule should allow subdomains"

    def test_domain_allows_deep_subdomain(self):
        policy = Policy([AllowRule("example.com", "domain")])
        allowed, _ = policy.check("v1.api.example.com")
        assert allowed, "Domain rule should allow deep subdomains"

    def test_domain_denies_different_domain(self):
        policy = Policy([AllowRule("example.com", "domain")])
        allowed, _ = policy.check("notexample.com")
        assert not allowed, "Domain rule should NOT allow similar but different domains"

    def test_domain_denies_suffix_without_dot(self):
        policy = Policy([AllowRule("example.com", "domain")])
        allowed, _ = policy.check("fakeexample.com")
        assert not allowed, "Domain rule should NOT allow suffix without dot separator"

    def test_domain_case_insensitive(self):
        policy = Policy([AllowRule("Example.Com", "domain")])
        allowed, _ = policy.check("API.EXAMPLE.COM")
        assert allowed, "Domain rule should be case-insensitive"

class TestGlobMatch:
    """Test glob pattern rules."""

    def test_glob_star_pattern(self):
        policy = Policy([AllowRule("*.example.com", "glob")])
        allowed, _ = policy.check("api.example.com")
        assert allowed, "Glob *.example.com should match api.example.com"

    def test_glob_multiple_stars(self):
        policy = Policy([AllowRule("*.*.example.com", "glob")])
        allowed, _ = policy.check("v1.api.example.com")
        assert allowed, "Glob *.*.example.com should match v1.api.example.com"

    def test_glob_denies_non_matching(self):
        policy = Policy([AllowRule("*.example.com", "glob")])
        allowed, _ = policy.check("api.other.com")
        assert not allowed, "Glob *.example.com should NOT match api.other.com"

    def test_glob_middle_pattern(self):
        policy = Policy([AllowRule("api.*.com", "glob")])
        allowed, _ = policy.check("api.example.com")
        assert allowed, "Glob api.*.com should match api.example.com"

    def test_glob_case_insensitive(self):
        policy = Policy([AllowRule("*.EXAMPLE.COM", "glob")])
        allowed, _ = policy.check("api.example.com")
        assert allowed, "Glob patterns should be case-insensitive"

class TestMultipleRules:
    """Test policies with multiple rules."""

    def test_multiple_rules_any_match(self):
        rules = [
            AllowRule("example.com", "exact"),
            AllowRule("api.othersite.com", "exact"),
        ]
        policy = Policy(rules)

        allowed1, _ = policy.check("example.com")
        allowed2, _ = policy.check("api.othersite.com")

        assert allowed1, "First rule should match"
        assert allowed2, "Second rule should match"

    def test_multiple_rules_first_match_wins(self):
        rules = [
            AllowRule("example.com", "domain", "First rule"),
            AllowRule("example.com", "exact", "Second rule"),
        ]
        policy = Policy(rules)

        allowed, rule = policy.check("api.example.com")
        assert allowed, "First matching rule should allow"
        assert rule.description == "First rule", "First matching rule should be returned"

    def test_multiple_rules_none_match(self):
        rules = [
            AllowRule("example.com", "exact"),
            AllowRule("other.com", "exact"),
        ]
        policy = Policy(rules)

        allowed, _ = policy.check("notinlist.com")
        assert not allowed, "Should deny if no rules match"

class TestWhitespaceHandling:
    """Test whitespace trimming and normalization."""

    def test_check_trims_whitespace(self):
        policy = Policy([AllowRule("example.com", "exact")])
        allowed, _ = policy.check("  example.com  ")
        assert allowed, "Check should trim whitespace from input"

    def test_check_tabs_and_newlines(self):
        policy = Policy([AllowRule("example.com", "exact")])
        allowed, _ = policy.check("\texample.com\n")
        assert allowed, "Check should trim all types of whitespace"

class TestPolicyFromDict:
    """Test loading policy from dictionary."""

    def test_load_valid_policy(self):
        data = {
            "rules": [
                {"pattern": "example.com", "rule_type": "exact"},
                {"pattern": "api.other.com", "rule_type": "domain", "description": "API"},
            ]
        }
        policy = Policy.from_dict(data)
        assert len(policy.rules) == 2
        assert policy.rules[0].pattern == "example.com"
        assert policy.rules[1].description == "API"

    def test_load_policy_missing_required_field(self):
        data = {
            "rules": [
                {"pattern": "example.com"},
            ]
        }
        with pytest.raises(ValueError):
            Policy.from_dict(data)

    def test_load_policy_invalid_rule_type(self):
        data = {
            "rules": [
                {"pattern": "example.com", "rule_type": "invalid"},
            ]
        }
        with pytest.raises(ValueError):
            Policy.from_dict(data)

    def test_load_policy_not_dict(self):
        with pytest.raises(ValueError):
            Policy.from_dict(["not", "a", "dict"])

    def test_load_policy_rules_not_list(self):
        data = {"rules": "not-a-list"}
        with pytest.raises(ValueError):
            Policy.from_dict(data)

    def test_load_empty_rules(self):
        data = {"rules": []}
        policy = Policy.from_dict(data)
        assert len(policy.rules) == 0
        assert not policy.check("example.com")[0], "Empty policy should deny"

    def test_load_policy_missing_rules_key_creates_empty(self):
        data = {"other_key": "value"}
        policy = Policy.from_dict(data)
        assert len(policy.rules) == 0, "Missing rules key should default to empty"

class TestPolicyToDict:
    """Test exporting policy to dictionary."""

    def test_export_to_dict(self):
        rules = [
            AllowRule("example.com", "exact", "Production"),
            AllowRule("*.api.com", "glob"),
        ]
        policy = Policy(rules)

        data = policy.to_dict()
        assert len(data["rules"]) == 2
        assert data["rules"][0]["pattern"] == "example.com"
        assert data["rules"][0]["description"] == "Production"

    def test_roundtrip_to_dict(self):
        original_data = {
            "rules": [
                {"pattern": "example.com", "rule_type": "exact", "description": "Main"},
                {"pattern": "*.api.com", "rule_type": "glob", "description": ""},
            ]
        }

        policy = Policy.from_dict(original_data)
        exported = policy.to_dict()

        assert exported == original_data

class TestPolicyExport:
    """Test exporting policy in different formats."""

    def test_export_hosts_format(self):
        policy = Policy([
            AllowRule("example.com", "exact"),
            AllowRule("api.other.com", "domain"),
        ])

        output = policy.to_hosts_format()
        assert "127.0.0.1 example.com" in output
        assert "127.0.0.1 api.other.com" in output
        assert "# Generated by awwall" in output

    def test_export_iptables_format(self):
        policy = Policy([
            AllowRule("example.com", "exact"),
        ])

        output = policy.to_iptables_format()
        assert "#!/bin/bash" in output
        assert "iptables -P OUTPUT DROP" in output
        assert "example.com" in output

class TestFailClosed:
    """Critical tests that policy fails closed in all cases."""

    def test_malformed_policy_raises(self):
        """Malformed policy should raise, not allow all."""
        with pytest.raises(ValueError):
            Policy.from_dict(["not", "a", "dict"])

    def test_no_default_allow(self):
        """Policy should never have a default allow."""
        policy = Policy()
        allowed, _ = policy.check("any.hostname.com")
        assert not allowed, "Policy must never default to allow"

    def test_deny_on_error_parsing_host(self):
        """Deny if host cannot be parsed (edge case)."""
        policy = Policy([AllowRule("example.com", "exact")])

        allowed, _ = policy.check("")
        assert not allowed, "Empty host should be denied"

        allowed, _ = policy.check(" " * 10)
        assert not allowed, "Whitespace-only host should be denied"

    def test_multiple_matching_rules_still_allowed(self):
        """Multiple rules matching should still allow (first match)."""
        policy = Policy([
            AllowRule("example.com", "exact"),
            AllowRule("example.com", "domain"),
        ])
        allowed, rule = policy.check("example.com")
        assert allowed, "Any matching rule should allow"
        assert rule is not None

if __name__ == "__main__":
    pytest.main([__file__, "-v"])

