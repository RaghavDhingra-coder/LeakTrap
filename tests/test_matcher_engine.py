"""Confidence rules of the matcher, tested on plain objects (no database).

Each rule's reason is documented on SIGNAL_CONFIDENCE in backend/services/matcher.py.
"""

import random
from types import SimpleNamespace

import pytest

from backend.services.matcher import CONFIDENCE_ORDER, MAX_CANDIDATES, SIGNAL_CONFIDENCE, Clues, score


def signup(id, site_name="Shop", site_domain="shop.example.com", alias=None, nickname=None,
           surname_variant=None):
    return SimpleNamespace(id=id, site_name=site_name, site_domain=site_domain, alias=alias,
                           nickname=nickname, surname_variant=surname_variant)


SHOP = signup(1, alias="ab12@leaktrap.xyz", nickname="Ocelot", surname_variant="Dhingraa")
NEWS = signup(2, site_name="News", site_domain="news.example.org", alias="cd34@leaktrap.xyz",
              nickname="Zephyr")


def types(candidate) -> set[str]:
    return {s.type for s in candidate.signals}


def test_rule_table_is_conservative() -> None:
    assert SIGNAL_CONFIDENCE == {
        "alias_exact": "high",
        "nickname_exact": "medium",
        "surname_variant_exact": "low",
        "sender_domain": "low",
    }
    assert CONFIDENCE_ORDER == ("none", "low", "medium", "high")


def test_exact_alias_match_is_high() -> None:
    result = score([SHOP, NEWS], Clues(recipient="ab12@leaktrap.xyz"))
    assert (result.status, result.confidence) == ("matched", "high")
    assert [m.signup_id for m in result.matches] == [1]
    assert types(result.matches[0]) == {"alias_exact"}
    assert result.matches[0].site_name == "Shop"
    assert result.matches[0].site_domain == "shop.example.com"


def test_unknown_alias_is_none() -> None:
    result = score([SHOP, NEWS], Clues(recipient="zzzz@leaktrap.xyz"))
    assert (result.status, result.confidence, result.matches) == ("no_match", "none", [])
    assert any("does not match any alias" in w for w in result.warnings)


def test_no_clues_matching_is_none() -> None:
    assert score([SHOP], Clues(sender="a@other.example")).confidence == "none"
    assert score([], Clues(recipient="ab12@leaktrap.xyz")).status == "no_match"


def test_sender_domain_alone_is_only_low() -> None:
    result = score([SHOP], Clues(sender="promo@mail.shop.example.com"))
    assert (result.status, result.confidence) == ("matched", "low")
    assert types(result.matches[0]) == {"sender_domain"}


def test_sender_domain_does_not_match_parent_of_site() -> None:
    assert score([SHOP], Clues(sender="a@example.com")).status == "no_match"
    assert score([SHOP], Clues(sender="a@notshop.example.com")).status == "no_match"


def test_nickname_clue_is_medium_never_high() -> None:
    result = score([SHOP], Clues(nickname="ocelot"))
    assert result.confidence == "medium"
    assert types(result.matches[0]) == {"nickname_exact"}


def test_surname_variant_alone_is_low() -> None:
    result = score([SHOP], Clues(surname_variant="dhingraa"))
    assert result.confidence == "low"


def test_weak_signals_combined_do_not_reach_high() -> None:
    clues = Clues(sender="x@shop.example.com", nickname="ocelot", surname_variant="dhingraa")
    result = score([SHOP], clues)
    assert result.confidence == "medium"
    assert types(result.matches[0]) == {"sender_domain", "nickname_exact", "surname_variant_exact"}


def test_same_nickname_in_field_and_subject_counts_once() -> None:
    result = score([SHOP], Clues(nickname="ocelot", subject="Hi OCELOT, a deal"))
    signals = result.matches[0].signals
    assert [s.type for s in signals] == ["nickname_exact"]
    assert "nickname clue and the subject line" in signals[0].explanation


def test_subject_nickname_must_be_a_whole_word() -> None:
    assert score([SHOP], Clues(recipient="ab12@leaktrap.xyz", subject="Ocelots for sale")
                 ).matches[0].signals[-1].type == "alias_exact"
    hit = score([SHOP], Clues(recipient="ab12@leaktrap.xyz", subject="Dear Ocelot!"))
    assert types(hit.matches[0]) == {"alias_exact", "nickname_exact"}


def test_alias_with_site_sender_warns_expected_mail() -> None:
    result = score([SHOP], Clues(recipient="ab12@leaktrap.xyz", sender="news@shop.example.com"))
    assert result.confidence == "high"
    assert types(result.matches[0]) == {"alias_exact", "sender_domain"}
    assert any("site's own mail" in w for w in result.warnings)


def test_alias_with_third_party_sender_warns_without_claiming_leak() -> None:
    result = score([SHOP], Clues(recipient="ab12@leaktrap.xyz", sender="deals@broker.example"))
    warning = next(w for w in result.warnings if "not associated with the site" in w)
    assert "does not prove" in warning


def test_alias_without_site_domain_warns_cannot_compare() -> None:
    nodomain = signup(3, site_domain=None, alias="ef56@leaktrap.xyz")
    result = score([nodomain], Clues(recipient="ef56@leaktrap.xyz", sender="a@b.example"))
    assert any("no site domain recorded" in w for w in result.warnings)


def test_conflicting_clues_are_ambiguous_and_downgraded() -> None:
    # Alias points at Shop, nickname points at News.
    result = score([SHOP, NEWS], Clues(recipient="ab12@leaktrap.xyz", nickname="zephyr"))
    assert result.status == "ambiguous"
    assert result.confidence == "medium"  # high, lowered one step
    assert [(m.signup_id, m.confidence) for m in result.matches] == [(1, "high"), (2, "medium")]
    assert any("2 different signups" in w for w in result.warnings)


def test_ambiguous_low_signals_stay_low() -> None:
    a = signup(1, surname_variant="Smith")
    b = signup(2, surname_variant="Smith")
    result = score([a, b], Clues(surname_variant="smith"))
    assert (result.status, result.confidence) == ("ambiguous", "low")


def test_candidates_are_capped() -> None:
    many = [signup(i, surname_variant="Smith") for i in range(1, MAX_CANDIDATES + 2)]
    result = score(many, Clues(surname_variant="smith"))
    assert len(result.matches) == MAX_CANDIDATES
    assert any("Only the first" in w for w in result.warnings)


@pytest.mark.parametrize("seed", range(5))
def test_result_is_deterministic_regardless_of_order(seed: int) -> None:
    signups = [SHOP, NEWS, signup(3, surname_variant="Dhingraa"), signup(4, site_domain="news.example.org")]
    clues = Clues(recipient="ab12@leaktrap.xyz", sender="x@news.example.org",
                  surname_variant="dhingraa", subject="Hi Zephyr")
    baseline = score(signups, clues)
    shuffled = signups[:]
    random.Random(seed).shuffle(shuffled)
    assert score(shuffled, clues) == baseline


def test_results_never_claim_a_confirmed_leak() -> None:
    result = score([SHOP], Clues(recipient="ab12@leaktrap.xyz", sender="x@broker.example"))
    assert result.status in {"matched", "ambiguous", "no_match"}
    text = " ".join([*result.warnings, *result.limitations,
                     *(s.explanation for m in result.matches for s in m.signals)]).lower()
    assert "not proof" in text
    assert "confirmed" not in text
