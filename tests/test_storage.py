"""Storage and replay tests."""

from __future__ import annotations

from conftest import analyze_scenario

from chronos.storage.sqlite import TraceStore


def test_store_and_replay_roundtrip(tmp_path):
    db = str(tmp_path / "trace.db")
    events, behaviors, _ = analyze_scenario("evil")

    store = TraceStore(db)
    run_id = store.save("simulated:evil", 0.0, 1.0, False, 0, events, behaviors)
    assert run_id >= 1

    loaded_events = store.load_events()
    loaded_behaviors = store.load_behaviors()
    assert len(loaded_events) == len(events)
    assert len(loaded_behaviors) == len(behaviors)
    assert loaded_behaviors[0].seq == behaviors[0].seq
    assert store.runs()[0]["sample"] == "simulated:evil"
    store.close()


def test_replay_reanalysis_matches(tmp_path):
    db = str(tmp_path / "trace.db")
    events, behaviors, indicators = analyze_scenario("evil")

    store = TraceStore(db)
    store.save("simulated:evil", 0.0, 1.0, False, 0, events, behaviors)
    store.close()

    from chronos.sandbox import Sandbox

    replay = Sandbox().replay(db)
    assert len(replay.indicators) == len(indicators)
