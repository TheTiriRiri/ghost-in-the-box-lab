"""Structural checks on Polish scenario narrative files."""
import pathlib

SCENARIO = pathlib.Path(__file__).parent.parent / "core" / "scenario"


def test_briefing_exists_and_nonempty():
    p = SCENARIO / "briefing.md"
    assert p.is_file()
    assert len(p.read_text(encoding="utf-8")) > 400


def test_briefing_mentions_victim_hostname():
    text = (SCENARIO / "briefing.md").read_text(encoding="utf-8")
    assert "workstation-042" in text


def test_attacker_profile_exists_and_nonempty():
    p = SCENARIO / "attacker-profile.md"
    assert p.is_file()
    assert len(p.read_text(encoding="utf-8")) > 400


def test_attacker_profile_mentions_alias():
    text = (SCENARIO / "attacker-profile.md").read_text(encoding="utf-8")
    assert "ghost" in text.lower()


def test_narrative_is_polish_not_english():
    """Quick heuristic: Polish diacritics should appear at least a few times."""
    for fname in ("briefing.md", "attacker-profile.md"):
        text = (SCENARIO / fname).read_text(encoding="utf-8")
        polish_letters = sum(text.count(ch) for ch in "ąćęłńóśźżĄĆĘŁŃÓŚŹŻ")
        assert polish_letters >= 5, f"{fname} looks insufficiently Polish ({polish_letters} diacritics)"
