#!/usr/bin/env python3
"""
BurpMask - Burp Suite MCP De-Identification Proxy

Sits between Claude Code and the real Burp MCP server.

- stdout (Burp -> Claude): replaces real domains/keywords with fake ones
- stdin  (Claude -> Burp): reverse-replaces fake domains back to real ones
                           (domains only, no keywords, to avoid false positives)
- Safety net: stdout is scanned for any remaining real domains/keywords
              before being sent to Claude. If found, the message is blocked.
"""

import json
import os
import re
import subprocess
import sys
import threading

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(SCRIPT_DIR, "deid-config.json")


def load_config():
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def build_replacements(config):
    """Build a list of (pattern, replacement) tuples from config."""
    pairs = []
    replacements = config.get("replacements", {})

    # Exact domain replacements (longest first to avoid partial matches)
    domains = replacements.get("domains", {})
    exact_domains = {k: v for k, v in domains.items() if not k.startswith("*.")}
    wildcard_domains = {k: v for k, v in domains.items() if k.startswith("*.")}

    for domain, replacement in sorted(exact_domains.items(), key=lambda x: -len(x[0])):
        pairs.append((re.compile(re.escape(domain), re.IGNORECASE), replacement))

    # Wildcard domain replacements: *.example.com -> any subdomain
    for pattern, replacement in wildcard_domains.items():
        suffix = pattern[1:]  # Remove leading *
        repl_suffix = replacement[1:]  # Remove leading *
        regex = re.compile(
            r"([a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?)" + re.escape(suffix),
            re.IGNORECASE,
        )
        pairs.append((regex, r"\1" + repl_suffix))

    # Keyword replacements (longest first)
    keywords = replacements.get("keywords", {})
    for keyword, replacement in sorted(keywords.items(), key=lambda x: -len(x[0])):
        pairs.append((re.compile(re.escape(keyword)), replacement))

    # Regex patterns (user-supplied)
    patterns = replacements.get("patterns", {})
    for pattern, replacement in patterns.items():
        pairs.append((re.compile(pattern), replacement))

    return pairs


def build_reverse_domain_pairs(config):
    """Build reverse replacement pairs for domains only (fake -> real).

    Only domains are reversed to avoid false positives from short keywords.
    Handles both literal domains and regex-escaped versions (e.g. portal\.acme\.test).
    """
    pairs = []
    replacements = config.get("replacements", {})
    domains = replacements.get("domains", {})

    # Reverse: fake exact domains -> real exact domains (longest fake first)
    exact = {k: v for k, v in domains.items() if not k.startswith("*.")}
    for real_domain, fake_domain in sorted(exact.items(), key=lambda x: -len(x[1])):
        # Regex-escaped version first (longer match takes priority)
        fake_escaped = fake_domain.replace(".", r"\.")
        real_escaped = real_domain.replace(".", r"\.")
        pairs.append((re.compile(re.escape(fake_escaped), re.IGNORECASE), real_escaped))
        # Literal version
        pairs.append((re.compile(re.escape(fake_domain), re.IGNORECASE), real_domain))

    # Reverse: fake wildcard domains -> real wildcard domains
    wildcard = {k: v for k, v in domains.items() if k.startswith("*.")}
    for real_pattern, fake_pattern in wildcard.items():
        fake_suffix = fake_pattern[1:]  # e.g. ".client-a.test"
        real_suffix = real_pattern[1:]  # e.g. ".example.com"
        # Regex-escaped version first
        fake_suffix_escaped = fake_suffix.replace(".", r"\.")
        real_suffix_escaped = real_suffix.replace(".", r"\.")
        regex_escaped = re.compile(
            r"([a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?)" + re.escape(fake_suffix_escaped),
            re.IGNORECASE,
        )
        pairs.append((regex_escaped, r"\1" + real_suffix_escaped))
        # Literal version
        regex_literal = re.compile(
            r"([a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?)" + re.escape(fake_suffix),
            re.IGNORECASE,
        )
        pairs.append((regex_literal, r"\1" + real_suffix))

    return pairs


def build_leak_check_patterns(config):
    """Build patterns to detect any real sensitive data that was not masked.

    This is the safety net: scan stdout for real domains AND keywords.
    If any match is found, the message is blocked.
    """
    patterns = []
    replacements = config.get("replacements", {})

    # Real domains
    domains = replacements.get("domains", {})
    for domain in domains:
        raw = domain.lstrip("*.")
        patterns.append(re.compile(re.escape(raw), re.IGNORECASE))

    # Real keywords
    keywords = replacements.get("keywords", {})
    for keyword in keywords:
        patterns.append(re.compile(re.escape(keyword)))

    return patterns


def apply_pairs(text, pairs):
    """Apply all replacement pairs to text."""
    for pattern, replacement in pairs:
        text = pattern.sub(replacement, text)
    return text


def apply_pairs_obj(obj, pairs):
    """Recursively apply replacement pairs to all string values in a JSON object."""
    if isinstance(obj, str):
        return apply_pairs(obj, pairs)
    elif isinstance(obj, dict):
        return {k: apply_pairs_obj(v, pairs) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [apply_pairs_obj(item, pairs) for item in obj]
    return obj


def contains_leak(text, leak_patterns):
    """Check if text contains any real sensitive data."""
    for pattern in leak_patterns:
        if pattern.search(text):
            return True
    return False


def forward_stderr(proc):
    """Forward subprocess stderr to our stderr."""
    for line in proc.stderr:
        sys.stderr.buffer.write(line)
        sys.stderr.buffer.flush()


def main():
    config = load_config()
    deid_pairs = build_replacements(config)        # real -> fake (for stdout)
    reid_pairs = build_reverse_domain_pairs(config) # fake -> real (for stdin, domains only)
    leak_patterns = build_leak_check_patterns(config) # safety net patterns

    # Build the real MCP proxy command
    mcp_jar = os.path.join(SCRIPT_DIR, "mcp-proxy.jar")
    cmd = ["java", "-jar", mcp_jar] + sys.argv[1:]

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Forward stderr in background
    stderr_thread = threading.Thread(target=forward_stderr, args=(proc,), daemon=True)
    stderr_thread.start()

    # Forward stdin from Claude -> real MCP (reverse domain replacement)
    def forward_stdin():
        try:
            for line in sys.stdin.buffer:
                try:
                    msg = json.loads(line)
                    msg = apply_pairs_obj(msg, reid_pairs)
                    output = json.dumps(msg, ensure_ascii=False) + "\n"
                    proc.stdin.write(output.encode("utf-8"))
                except (json.JSONDecodeError, ValueError):
                    # Not JSON, apply reverse replacement on raw text
                    text = line.decode("utf-8", errors="replace")
                    text = apply_pairs(text, reid_pairs)
                    proc.stdin.write(text.encode("utf-8"))
                proc.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
        finally:
            try:
                proc.stdin.close()
            except OSError:
                pass

    stdin_thread = threading.Thread(target=forward_stdin, daemon=True)
    stdin_thread.start()

    # Read stdout from real MCP, de-identify, send to Claude
    try:
        for line in proc.stdout:
            try:
                msg = json.loads(line)
                msg = apply_pairs_obj(msg, deid_pairs)
                output = json.dumps(msg, ensure_ascii=False) + "\n"
            except json.JSONDecodeError:
                # Not JSON, de-identify raw text
                output = apply_pairs(line.decode("utf-8", errors="replace"), deid_pairs)

            # Safety net: block message if real data leaked through
            if contains_leak(output, leak_patterns):
                blocked = {
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32000,
                        "message": "[BLOCKED] Response contained unmasked sensitive data and was not forwarded.",
                    },
                }
                output = json.dumps(blocked, ensure_ascii=False) + "\n"
                sys.stderr.write("[BurpMask] BLOCKED: response contained unmasked sensitive data\n")
                sys.stderr.flush()

            sys.stdout.buffer.write(output.encode("utf-8"))
            sys.stdout.buffer.flush()
    except (BrokenPipeError, OSError):
        pass
    finally:
        proc.terminate()
        proc.wait()


if __name__ == "__main__":
    main()
