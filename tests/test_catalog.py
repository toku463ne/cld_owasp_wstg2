import textwrap

import pytest

from wstg import catalog


def test_repository_catalog_is_valid():
    c = catalog.load()
    assert c.wstg_version == "4.2"
    assert len(c.tests) == 97
    assert c.tests["WSTG-INFO-09"].merged_into == "WSTG-INFO-08"
    assert c.tests["WSTG-INFO-01"].owasp_url.startswith(catalog.OWASP_BASE + "01-Information_Gathering/01-")


def test_every_scenario_evidence_is_light_or_marked():
    c = catalog.load()
    for e in c.evidence.values():
        if e.heavy:
            assert e.level == "full" and e.load_note


def test_evidence_shared_between_tests_is_listed_once():
    c = catalog.load()
    ids = [e.id for e in c.evidence_for("WSTG-INFO-01")]
    assert ids.count("search-dorks") == 1
    assert "WSTG-INFO-01" in c.tests_using("search-dorks")


INDEX = """\
wstg_version: "4.2"
tests:
  - id: WSTG-INFO-01
    category: INFO
    category_name: Information Gathering
    title: Search
    summary: s
    target_types: [domain]
    owasp_path: 01-Information_Gathering/01-Search
  - id: WSTG-INFO-02
    category: INFO
    category_name: Information Gathering
    title: Fingerprint
    summary: s
    target_types: [fqdn]
    owasp_path: 01-Information_Gathering/02-Fingerprint
"""


TOOLS = "tools:\n" + "".join(f"  - {{name: {n}}}\n" for n in ("whois", "dig", "curl", "nikto"))


def make(tmp_path, evidence: str, scenarios: dict[str, str], tools: str = TOOLS):
    (tmp_path / "tools.yaml").write_text(tools)
    (tmp_path / "evidence").mkdir()
    (tmp_path / "wstg").mkdir()
    (tmp_path / "wstg_index.yaml").write_text(INDEX)
    (tmp_path / "evidence" / "e.yaml").write_text(textwrap.dedent(evidence))
    for name, body in scenarios.items():
        (tmp_path / "wstg" / f"{name}.yaml").write_text(textwrap.dedent(body))
    return tmp_path


GOOD_EVIDENCE = """\
evidence:
  - id: dns-whois
    title: WHOIS
    target_type: domain
    kind: auto
    level: light
    passive: true
    argv: [whois, "{domain}"]
  - id: http-root
    title: root
    target_type: fqdn
    kind: auto
    level: light
    argv: [curl, -o, "{out}/b", -w, "%{http_code}", "{base_url}/"]
"""


def test_minimal_catalog_loads(tmp_path):
    root = make(tmp_path, GOOD_EVIDENCE, {"WSTG-INFO-02": """\
        id: WSTG-INFO-02
        overview: o
        pass: p
        fail: f
        steps:
          - summary: headers
            evidence: [http-root, dns-whois]
            command: grep -i server {ev:http-root}/stdout.txt
        """})
    c = catalog.load(root)
    assert [e.id for e in c.evidence_for("WSTG-INFO-02")] == ["http-root", "dns-whois"]


def problems_for(tmp_path, evidence, scenarios=None):
    with pytest.raises(catalog.CatalogError) as ei:
        catalog.load(make(tmp_path, evidence, scenarios or {}))
    return "\n".join(ei.value.problems)


def test_domain_evidence_must_be_passive(tmp_path):
    p = problems_for(tmp_path, """\
        evidence:
          - id: dns-zone
            title: z
            target_type: domain
            kind: auto
            level: light
            argv: [dig, axfr, "{domain}"]
        """)
    assert "passive" in p


def test_heavy_evidence_must_be_full_with_note(tmp_path):
    p = problems_for(tmp_path, """\
        evidence:
          - id: nikto
            title: n
            target_type: fqdn
            kind: auto
            level: light
            heavy: true
            argv: [nikto, -h, "{base_url}"]
        """)
    assert "must be level full" in p and "load_note" in p


def test_placeholders_are_checked(tmp_path):
    p = problems_for(tmp_path, """\
        evidence:
          - id: dns-a
            title: a
            target_type: domain
            kind: auto
            level: light
            passive: true
            argv: [dig, "{fqdn}", "{nope}"]
        """)
    assert "{fqdn}" in p and "{nope}" in p


def test_manual_evidence_has_no_command(tmp_path):
    p = problems_for(tmp_path, """\
        evidence:
          - id: shots
            title: s
            target_type: fqdn
            kind: manual
            argv: [true]
        """)
    assert "must not set argv" in p and "description" in p


def test_scenario_references_are_checked(tmp_path):
    p = problems_for(tmp_path, GOOD_EVIDENCE, {
        "WSTG-INFO-01": """\
            id: WSTG-INFO-01
            overview: o
            pass: p
            fail: f
            steps:
              - summary: uses fqdn evidence on a domain-only test
                evidence: [http-root, missing-one]
              - summary: nothing to do
              - summary: ref not listed
                evidence: [dns-whois]
                command: cat {ev:http-root}/stdout.txt {out}/x
            """,
        "WSTG-ZZZZ-99": """\
            id: WSTG-INFO-02
            overview: o
            pass: p
            fail: f
            steps: []
            """,
    })
    assert "is for FQDN targets" in p
    assert "unknown evidence 'missing-one'" in p
    assert "needs a command, an operation, or evidence" in p
    assert "{ev:http-root} must also be listed" in p
    assert "{out} is not available" in p
    assert "does not match the file name" in p
    assert "no steps" in p


def test_unknown_keys_and_duplicates(tmp_path):
    p = problems_for(tmp_path, GOOD_EVIDENCE + """\
  - id: dns-whois
    title: again
    target_type: domain
    kind: manual
    description: d
    colour: red
""")
    assert "unknown key 'colour'" in p and "defined in both" in p


def test_auto_evidence_tools_must_be_listed(tmp_path):
    with pytest.raises(catalog.CatalogError) as ei:
        catalog.load(make(tmp_path, GOOD_EVIDENCE, {}, tools="tools:\n  - {name: whois}\n  - {name: x, install: brew}\n"))
    p = "\n".join(ei.value.problems)
    assert "tool 'curl' is not listed in tools.yaml" in p and "install must be one of" in p


def test_repository_tools_cover_every_command():
    c = catalog.load()
    assert {e.argv[0] for e in c.evidence.values() if e.kind == "auto"} <= set(c.tools)
    assert c.tools["testssl"].package == "testssl.sh"


def test_proxy_args_are_checked(tmp_path):
    p = problems_for(tmp_path, """\
        evidence:
          - id: a-root
            title: a
            target_type: fqdn
            kind: auto
            level: light
            argv: [curl, "{base_url}/"]
            proxy_args: [-x, "{proxy_url}"]
          - id: b-root
            title: b
            target_type: fqdn
            kind: auto
            level: light
            argv: [curl, "{proxy_args}", "{base_url}/"]
          - id: c-root
            title: c
            target_type: fqdn
            kind: auto
            level: light
            direct: true
            argv: [curl, "{proxy_args}", "{base_url}/"]
            proxy_args: [-x, "{fqdn}"]
        """)
    assert 'a-root: proxy_args needs exactly one "{proxy_args}"' in p
    assert 'b-root: argv has "{proxy_args}" but no proxy_args' in p
    assert "c-root: direct and proxy_args exclude each other" in p
    assert "not {fqdn}" in p
