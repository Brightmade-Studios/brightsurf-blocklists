#!/usr/bin/env python3
"""Turns EasyList and EasyPrivacy into WebKit content blocking rules for Brightsurf.

WebKit can't read Adblock Plus filter lists directly, so this converts the parts
it can understand (blocked addresses, hidden page elements, and exceptions) into
its JSON rule format, and skips the rest. Every pattern is checked against the
regular expression features WebKit supports, because one bad rule stops a whole
list from loading on the phone.

The output is split into chunks of at most CHUNK_SIZE rules, so if WebKit ever
rejects one, the others still work. Each list's exceptions are repeated at the
end of each of its chunks, because an exception only applies inside its own list.

Usage (run by Claude or by the refresh workflow, not by hand):
    python3 tools/blocklists/convert.py easylist.txt easyprivacy.txt Brightsurf/Blocking/Lists
"""

import hashlib
import json
import os
import re
import sys

CHUNK_SIZE = 25000

# Adblock Plus resource types and the WebKit names for them.
TYPE_MAP = {
    "script": ["script"],
    "image": ["image"],
    "stylesheet": ["style-sheet"],
    "font": ["font"],
    "media": ["media"],
    "xmlhttprequest": ["fetch"],
    "websocket": ["websocket"],
    "ping": ["ping"],
    "other": ["other"],
    "object": ["other"],
    "popup": ["popup"],
    "subdocument": ["document"],
}
# Everything a page loads except the page itself. Used when a rule must not block
# the page you are opening, only what it loads.
ALL_TYPES = sorted({t for ts in TYPE_MAP.values() for t in ts if t not in ("popup", "document")})

# Options that change behavior in ways WebKit can't copy. Rules with these are skipped.
UNSUPPORTED = {
    "csp", "rewrite", "redirect", "redirect-rule", "removeparam", "replace", "header",
    "permissions", "urltransform", "badfilter", "sitekey", "genericblock", "webrtc",
    "elemhide", "ehide", "generichide", "ghide", "specifichide", "shide", "content",
    "jsinject", "urlblock", "extension", "stealth", "cookie", "network", "app",
    "strict1p", "strict3p", "to", "method", "denyallow", "inline-script", "inline-font",
}
IGNORED = {"important", "all", "match-case", "document", "doc"}

SEPARATOR = "[^-a-zA-Z0-9_.%]"
DOMAIN_START = "^[a-z-]+://([^/?#]*\\.)?"

# Characters a WebKit url-filter may use. Anything else (|, {, \d and so on) is refused by WebKit.
_ALLOWED_REGEX = re.compile(r"^[\x20-\x7e]*$")


def webkit_regex_ok(rx: str) -> bool:
    """A conservative check of WebKit's url-filter grammar (URLFilterParser.cpp)."""
    if not rx or not _ALLOWED_REGEX.match(rx):
        return False
    if "|" in rx or "{" in rx or "}" in rx:
        return False
    depth = 0
    i = 0
    in_class = False
    while i < len(rx):
        c = rx[i]
        if c == "\\":
            if i + 1 >= len(rx):
                return False
            nxt = rx[i + 1]
            # Only escapes of punctuation are safe; \d, \w, \b and friends are not supported.
            if nxt.isalnum():
                return False
            i += 2
            continue
        if in_class:
            if c == "]":
                in_class = False
            i += 1
            continue
        if c == "[":
            in_class = True
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth < 0:
                return False
        elif c == "^" and i != 0:
            return False
        elif c == "$" and i != len(rx) - 1:
            return False
        elif c in "*+?" and (i == 0 or rx[i - 1] in "(^"):
            return False
        i += 1
    return depth == 0 and not in_class


def pattern_to_regex(pattern: str):
    """Adblock Plus address pattern to a WebKit url-filter, or None if it can't be expressed."""
    if pattern.startswith("/") and pattern.endswith("/") and len(pattern) > 1:
        return None  # Raw regular expressions use features WebKit lacks; skip them.
    prefix = ""
    if pattern.startswith("||"):
        prefix = DOMAIN_START
        pattern = pattern[2:]
    elif pattern.startswith("|"):
        prefix = "^"
        pattern = pattern[1:]
    suffix = ""
    if pattern.endswith("|"):
        suffix = "$"
        pattern = pattern[:-1]
    pattern = pattern.strip("*") if not prefix else pattern.rstrip("*")
    if not pattern:
        return None
    out = []
    for ch in pattern:
        if ch == "*":
            out.append(".*")
        elif ch == "^":
            out.append(SEPARATOR)
        elif ch in ".?+()[]{}\\$|/":
            out.append("\\" + ch if ch != "/" else "/")
        else:
            out.append(ch)
    rx = prefix + "".join(out) + suffix
    # A domain rule must start with the host, so the first piece can't be empty.
    return rx if webkit_regex_ok(rx) else None


def parse_domains(value: str):
    """'a.com|~b.com' to (if-domain, unless-domain), or None if WebKit can't express it."""
    include, exclude = [], []
    for d in value.split("|"):
        d = d.strip().lower()
        if not d:
            continue
        neg = d.startswith("~")
        d = d.lstrip("~")
        if not re.match(r"^[a-z0-9.-]+$", d) or d.endswith(".*") or "*" in d:
            return None
        (exclude if neg else include).append("*" + d)
    if include and exclude:
        # WebKit can't do "on a.com but not b.a.com" in one rule. Keep the broader "on" list.
        exclude = []
    return include, exclude


def network_rule(line: str):
    exception = line.startswith("@@")
    if exception:
        line = line[2:]
    pattern, _, opts = line.partition("$")
    if opts and "/" in opts and pattern.startswith("/"):
        return None
    trigger = {}
    action = {"type": "ignore-previous-rules" if exception else "block"}
    types, not_types = [], []
    is_document_exception = False
    for opt in filter(None, opts.split(",")) if opts else []:
        name, _, value = opt.partition("=")
        name = name.strip().lower()
        neg = name.startswith("~")
        bare = name.lstrip("~")
        if bare in ("third-party", "3p"):
            trigger["load-type"] = ["first-party" if neg else "third-party"]
        elif bare in ("first-party", "1p"):
            trigger["load-type"] = ["third-party" if neg else "first-party"]
        elif bare == "domain":
            parsed = parse_domains(value)
            if parsed is None:
                return None
            inc, exc = parsed
            if inc:
                trigger["if-domain"] = inc
            if exc:
                trigger["unless-domain"] = exc
        elif bare in TYPE_MAP:
            (not_types if neg else types).extend(TYPE_MAP[bare])
        elif bare in ("document", "doc"):
            if exception and not neg:
                is_document_exception = True
            elif not neg:
                types.append("document")
        elif bare == "match-case":
            trigger["url-filter-is-case-sensitive"] = True
        elif bare in UNSUPPORTED:
            return None
        elif bare in IGNORED:
            continue
        else:
            return None

    if is_document_exception:
        # "@@||site.com^$document" turns blocking off on that whole site.
        m = re.match(r"^\|\|([a-z0-9.-]+)\^?$", pattern)
        if not m:
            return None
        return {"trigger": {"url-filter": ".*", "if-domain": ["*" + m.group(1)]},
                "action": {"type": "ignore-previous-rules"}}

    rx = pattern_to_regex(pattern)
    if rx is None:
        return None
    if len(pattern.replace("*", "").replace("^", "").replace("|", "")) < 4 and "if-domain" not in trigger:
        return None  # Too short to be safe on every page.
    trigger = {"url-filter": rx, **trigger}
    if types:
        resource = sorted(set(types))
        if "document" in resource and "subdocument" in opts:
            trigger["load-context"] = ["child-frame"]
        trigger["resource-type"] = resource
    elif not_types:
        trigger["resource-type"] = [t for t in ALL_TYPES if t not in set(not_types)]
    elif not pattern.startswith("||") and not exception:
        # A loose address pattern such as "/ads/" should block what a page loads,
        # never the article you tapped. Known ad domains ("||ads.com^") block everything.
        trigger["resource-type"] = ALL_TYPES
    return {"trigger": trigger, "action": action}


# Selector features WebKit can't use in content blocking rules, or that are list-specific extensions.
_BAD_SELECTOR = re.compile(
    r":-abp-|:has-text|:contains|:xpath|:upward|:matches-|:style|:remove|:watch-attr|"
    r":min-text|:others|:if|:nth-ancestor|:has\(|:is\(|:where\(|:not\(.*:|\{|\}|\\"
)


def cosmetic_rule(line: str):
    if "#@#" in line or "#?#" in line or "#$#" in line or "#%#" in line:
        return None
    domains, _, selector = line.partition("##")
    selector = selector.strip()
    if not selector or _BAD_SELECTOR.search(selector) or not _ALLOWED_REGEX.match(selector):
        return None
    if selector.count("(") != selector.count(")") or selector.count("[") != selector.count("]"):
        return None
    if domains:
        parsed = parse_domains(domains.replace(",", "|"))
        if parsed is None:
            return None
        inc, exc = parsed
        return ("domain", selector, inc, exc)
    return ("generic", selector, [], [])


def convert(path: str):
    blocks, exceptions, generic, specific = [], [], [], {}
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("!") or line.startswith("["):
                continue
            if "##" in line or "#@#" in line or "#?#" in line or "#$#" in line:
                parsed = cosmetic_rule(line)
                if not parsed:
                    continue
                kind, selector, inc, exc = parsed
                if kind == "generic":
                    generic.append(selector)
                else:
                    specific.setdefault((tuple(inc), tuple(exc)), []).append(selector)
                continue
            rule = network_rule(line)
            if rule is None:
                continue
            (exceptions if rule["action"]["type"] == "ignore-previous-rules" else blocks).append(rule)

    css = []
    # Generic hiding: group selectors so WebKit builds one shared style sheet.
    for i in range(0, len(generic), 100):
        css.append({"trigger": {"url-filter": ".*"},
                    "action": {"type": "css-display-none", "selector": ", ".join(generic[i:i + 100])}})
    for (inc, exc), selectors in specific.items():
        trigger = {"url-filter": ".*"}
        if inc:
            trigger["if-domain"] = list(inc)
        if exc:
            trigger["unless-domain"] = list(exc)
        css.append({"trigger": trigger, "action": {"type": "css-display-none", "selector": ", ".join(selectors)}})
    return blocks + css, exceptions


def write_chunks(name: str, rules, exceptions, out_dir: str):
    files = []
    room = CHUNK_SIZE - len(exceptions)
    for n, i in enumerate(range(0, len(rules), room), start=1):
        chunk = rules[i:i + room] + exceptions
        filename = f"{name}-{n}.json"
        with open(os.path.join(out_dir, filename), "w", encoding="utf-8") as f:
            json.dump(chunk, f, separators=(",", ":"))
        files.append((filename, len(chunk)))
    return files


def list_version(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.startswith("! Version:"):
                return line.split(":", 1)[1].strip()
    return "unknown"


def main():
    if len(sys.argv) != 4:
        print(__doc__)
        sys.exit(1)
    easylist, easyprivacy, out_dir = sys.argv[1:]
    os.makedirs(out_dir, exist_ok=True)
    for old in os.listdir(out_dir):
        if old.endswith(".json"):
            os.remove(os.path.join(out_dir, old))

    manifest = {"format": 1, "lists": []}
    digest = hashlib.sha256()
    for name, path in (("ads", easylist), ("trackers", easyprivacy)):
        rules, exceptions = convert(path)
        for filename, count in write_chunks(name, rules, exceptions, out_dir):
            with open(os.path.join(out_dir, filename), "rb") as f:
                digest.update(f.read())
            manifest["lists"].append({"file": filename, "rules": count})
        manifest[f"{name}Version"] = list_version(path)
        print(f"{name}: {len(rules)} rules, {len(exceptions)} exceptions")
    manifest["version"] = digest.hexdigest()[:12]
    with open(os.path.join(out_dir, "blocklists.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
