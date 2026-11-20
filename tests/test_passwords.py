"""Password derivation. Synthetic hints only: no real secrets, ever."""
from finkit import passwords as pr

FAKE_PAN = "ABCDE1234F"          # the documented example format, not anyone's PAN


def test_password_rule_sbi_text_synthetic():
    rule = "last five digits of registered mobile number and date of birth in DDMMYY format"
    assert pr.derive(pr.parse_rule(rule), {"mobile": "9990054321", "dob": "01011990"}) == ["54321010190"]


def test_password_rule_rbl_caps_name_synthetic():
    rule = "first four letters of your name in CAPITALS followed by date of birth in DDMMYY"
    assert pr.derive(pr.parse_rule(rule), {"name": "Sample Name", "dob": "01011990"}) == ["SAMP010190"]


def test_candidates_puts_rule_first_and_customs_before_that():
    hints = {"custom": ["explicit"], "mobile": "9990054321", "dob": "01011990",
             "rule_text": "last five digits of mobile and date of birth in DDMMYY"}
    c = pr.candidates(hints)
    assert c[0] == "explicit" and "54321010190" in c[:3]


def test_no_hints_no_candidates():
    assert pr.candidates({}) == []


def test_pan_rule_is_parsed_from_the_stated_sentence():
    # contract notes and CAS say "your PAN in capital letters"
    comps = pr.parse_rule("The password to open this document is your PAN in capital letters.")
    assert comps == [{"kind": "pan", "case": "upper"}]
    assert pr.derive(comps, {"pan": "abcde1234f"}) == [FAKE_PAN]


def test_pan_is_tried_early_even_without_a_stated_rule():
    c = pr.candidates({"pan": "abcde1234f", "name": "Sample Name", "dob": "01011990"})
    assert c[:2] == [FAKE_PAN, FAKE_PAN.lower()], c[:3]


def test_a_malformed_pan_derives_nothing():
    # a PAN is exactly 10 characters; anything else is a typo, not a password to try
    assert pr.derive([{"kind": "pan", "case": "upper"}], {"pan": "ABCDE123"}) == []
    assert FAKE_PAN not in pr.candidates({"pan": "ABCDE123"})
