"""End-to-end pipeline tests over scripted scenarios."""

from __future__ import annotations

from conftest import analyze_scenario


def test_benign_scenario_has_low_score():
    _, _, indicators = analyze_scenario("benign")
    assert indicators == []


def test_benign_network_scenario_clean():
    _, behaviors, indicators = analyze_scenario("benign_network")
    assert any(b.op == "connect" for b in behaviors)
    assert not any(i.severity in ("HIGH", "CRITICAL") for i in indicators)


def test_evil_scenario_flags_memory_and_c2():
    events, behaviors, indicators = analyze_scenario("evil")

    assert any(b.op == "rwx_alloc" for b in behaviors)
    assert any(b.op == "protect_none" for b in behaviors)
    assert any(b.op == "persistence_write" for b in behaviors)

    names = [i.technique for i in indicators]
    assert any("RWX" in n for n in names)
    assert any("Beaconing" in n for n in names)
    assert any("autostart" in n.lower() for n in names)
    assert any("temp" in n.lower() or "Write-then-delete" in n for n in names)
    assert any("anti" in n.lower() or "Trace-state" in n or "ptrace" in n.lower() for n in names)


def test_evil_scenario_score_is_high():
    _, _, indicators = analyze_scenario("evil")
    total = sum(i.score for i in indicators)
    assert total >= 10
