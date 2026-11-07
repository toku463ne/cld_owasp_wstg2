import pytest

from wstg import cvss

# Scores from the FIRST CVSS v3.1 calculator.
CASES = [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "Critical"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "Critical"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "Medium"),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9, "Medium"),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, "High"),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", 4.3, "Medium"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3, "Medium"),
    ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6, "Low"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "None"),
]


@pytest.mark.parametrize("vector,expected,sev", CASES)
def test_scores(vector, expected, sev):
    r = cvss.score(vector)
    assert r["score"] == expected and r["severity"] == sev


def test_normalize_and_errors():
    assert cvss.normalize("A:N/I:N/C:L/S:U/UI:N/PR:N/AC:L/AV:N") == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    for bad, msg in [("", "empty"), ("CVSS:3.0/AV:N", "only CVSS v3.1"), ("AV:X", "bad value"),
                     ("AV:N/AC:L", "missing"), ("AV:N/AV:N", "twice"), ("E:F", "unknown metric")]:
        with pytest.raises(cvss.CvssError, match=msg):
            cvss.score(bad)
    assert cvss.try_score("nonsense") is None
