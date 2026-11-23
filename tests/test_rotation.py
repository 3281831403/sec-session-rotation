"""Fixed acceptance tests for the session-rotation bugfix exercise.

These tests describe the intended secure behavior.  They are intentionally
immutable: only ``session/rotation.py`` may be changed.
"""

from session.rotation import (
    DEFAULT_TTL_SECONDS,
    SESSION_ID_LENGTH,
    bind,
    invalidate_all,
    new_id,
    replay_guard,
    rotate,
    session_batch,
    validate,
    validate_store,
)

NOW = 1_700_000_000_000  # milliseconds
TTL_MS = DEFAULT_TTL_SECONDS * 1000


def _new_store(principal="alice", now=NOW, secret=b"0" * 32):
    return {
        "ttl": DEFAULT_TTL_SECONDS,
        "principal": principal,
        "now": now,
        "secret": secret,
        "sessions": [],
        "nonces": {},
    }


def _copy_store(store):
    """Copy persistent state while rebinding private record back-references."""
    clone = {
        "ttl": store["ttl"],
        "principal": store["principal"],
        "now": store["now"],
        "secret": store["secret"],
        "sessions": [dict(record) for record in store["sessions"]],
        "nonces": {
            sid: set(nonces) for sid, nonces in store.get("nonces", {}).items()
        },
    }
    for record in clone["sessions"]:
        if "_store" in record:
            record["_store"] = clone
    return clone


def _batch_events():
    alice_sid = "a" * SESSION_ID_LENGTH
    bob_sid = "b" * SESSION_ID_LENGTH
    return [
        {"at": NOW + 1000, "user": "alice", "op": "bind", "sid": alice_sid},
        {"at": NOW + 2000, "user": "bob", "op": "bind", "sid": bob_sid},
        {"at": NOW + 3000, "user": "alice", "op": "validate", "sid": alice_sid},
        {"at": NOW + 4000, "user": "bob", "op": "validate", "sid": alice_sid},
        {"at": NOW + 5000, "user": "bob", "op": "validate", "sid": bob_sid},
    ]


def test_defect_01_new_id_uses_explicit_entropy_deterministically():
    entropy_a = bytes(range(32))
    entropy_b = bytes(range(1, 33))

    first = new_id(entropy_a, "alice")
    repeated = new_id(entropy_a, "alice")
    other_entropy = new_id(entropy_b, "alice")
    other_user = new_id(entropy_a, "bob")

    assert first == repeated
    assert first != other_entropy
    assert first != other_user
    assert len(first) == 64
    assert all(character in "0123456789abcdef" for character in first)


def test_defect_02_fixed_id_attack_is_blocked_by_rotation():
    entropy_a = bytes(range(32))
    entropy_b = bytes(range(1, 33))
    assert new_id(entropy_a, "alice") != new_id(entropy_b, "alice")

    fixed_id = "a" * SESSION_ID_LENGTH
    store = _new_store(principal="alice")
    old = bind(store, fixed_id, "alice", NOW)
    assert validate(store, fixed_id, NOW)["valid"] is True

    rotated = rotate(old, "alice", NOW + 1000)
    assert rotated["ok"] is True
    assert rotated["new_id"] != fixed_id
    assert validate(store, fixed_id, NOW + 1000)["valid"] is False
    assert validate(store, rotated["new_id"], NOW + 1000)["valid"] is True

    other_store = _new_store(principal="alice", secret=b"1" * 32)
    other_old = bind(other_store, fixed_id, "alice", NOW)
    other_rotated = rotate(other_old, "alice", NOW + 1000)
    assert other_rotated["ok"] is True
    assert other_rotated["new_id"] != rotated["new_id"]


def test_defect_03_concurrent_rotation_removes_old_id():
    old_id = "b" * SESSION_ID_LENGTH
    store = _new_store(principal="alice")
    old = bind(store, old_id, "alice", NOW)

    winner = rotate(old, "alice", NOW + 1000)
    loser = rotate(old, "alice", NOW + 1001)

    assert winner["ok"] is True
    assert winner["old_id"] == old_id
    assert loser["ok"] is False
    assert loser["reason"] == "stale"
    assert validate(store, old_id, NOW + 1001)["valid"] is False
    assert not any(record["id"] == old_id for record in store["sessions"])
    assert len([record for record in store["sessions"] if record["user"] == "alice"]) == 1


def test_defect_04_rotate_resets_ttl():
    store = _new_store(principal="alice")
    old = bind(store, "c" * SESSION_ID_LENGTH, "alice", NOW)
    rotated_at = NOW + 250_000
    rotated = rotate(old, "alice", rotated_at)
    assert rotated["ok"] is True

    new_sid = rotated["new_id"]
    assert validate(store, new_sid, rotated_at + TTL_MS - 1)["valid"] is True
    assert validate(store, new_sid, rotated_at + TTL_MS)["valid"] is False


def test_defect_05_bind_records_created_at_and_ttl():
    store = _new_store(principal="alice")
    sid = "d" * SESSION_ID_LENGTH
    record = bind(store, sid, "alice", NOW)

    assert record["id"] == sid
    assert record["user"] == "alice"
    assert record["created_at"] == NOW
    assert record["ttl"] == 300
    assert record["ttl"] == DEFAULT_TTL_SECONDS

    stored = [item for item in store["sessions"] if item["id"] == sid]
    assert len(stored) == 1
    assert stored[0]["created_at"] == NOW
    assert validate(store, sid, NOW + TTL_MS - 1)["valid"] is True
    assert validate_store(store) == []


def test_defect_06_validate_rejects_cross_user_binding():
    alice_sid = "e" * SESSION_ID_LENGTH
    bob_sid = "f" * SESSION_ID_LENGTH
    store = _new_store(principal="alice")
    bind(store, alice_sid, "alice", NOW)
    bind(store, bob_sid, "bob", NOW)

    assert validate(store, alice_sid, NOW)["valid"] is True
    assert validate(store, bob_sid, NOW)["valid"] is False

    store["principal"] = "bob"
    rejected = validate(store, alice_sid, NOW)
    assert rejected["valid"] is False
    assert rejected["reason"] == "binding_mismatch"
    assert validate(store, bob_sid, NOW)["valid"] is True


def test_defect_07_validate_normalizes_milliseconds_and_seconds():
    store = _new_store(principal="alice")
    sid = "1" * SESSION_ID_LENGTH
    bind(store, sid, "alice", NOW)

    assert store["sessions"][0]["created_at"] == NOW
    assert validate(store, sid, NOW + 250_000)["valid"] is True
    expired = validate(store, sid, NOW + TTL_MS)
    assert expired["valid"] is False
    assert expired["reason"] == "expired"


def test_defect_08_replay_guard_persists_nonce_in_store():
    store = _new_store(principal="alice")
    sid = "2" * SESSION_ID_LENGTH
    bind(store, sid, "alice", NOW)

    assert replay_guard(store, sid, "nonce-1") is True
    assert replay_guard(store, sid, "nonce-1") is False
    assert "nonce-1" in store["nonces"][sid]

    restarted = _copy_store(store)
    assert replay_guard(restarted, sid, "nonce-1") is False


def test_defect_09_invalidate_all_removes_every_device():
    store = _new_store(principal="alice")
    alice_one = "3" * SESSION_ID_LENGTH
    alice_two = "4" * SESSION_ID_LENGTH
    bob_sid = "5" * SESSION_ID_LENGTH
    bind(store, alice_one, "alice", NOW)
    bind(store, alice_two, "alice", NOW)
    bind(store, bob_sid, "bob", NOW)
    assert replay_guard(store, alice_one, "nonce-1") is True

    removed = invalidate_all(store, "alice")

    assert removed == 2
    assert validate(store, alice_one, NOW)["valid"] is False
    assert validate(store, alice_two, NOW)["valid"] is False
    assert not store["nonces"].get(alice_one)
    store["principal"] = "bob"
    assert validate(store, bob_sid, NOW)["valid"] is True


def test_defect_10_session_batch_isolates_users():
    events = _batch_events()
    result = session_batch(events, {"ttl": 300})

    assert set(result) == {"alice", "bob"}
    alice_results = result["alice"]["results"]
    assert [item["op"] for item in alice_results] == ["bind", "validate"]
    assert alice_results[1]["ok"] is True

    bob_cross_user = [
        item
        for item in result["bob"]["results"]
        if item["op"] == "validate" and item["sid"] == "a" * SESSION_ID_LENGTH
    ]
    assert len(bob_cross_user) == 1
    assert bob_cross_user[0]["ok"] is False


def test_old_id_invalid_after_rotation():
    store = _new_store(principal="alice")
    old_id = "6" * SESSION_ID_LENGTH
    old = bind(store, old_id, "alice", NOW)
    rotated = rotate(old, "alice", NOW + 1000)
    assert rotated["ok"] is True

    assert validate(store, old_id, NOW + 1000)["valid"] is False
    assert validate(store, old_id, NOW + 2000)["valid"] is False
    assert validate(store, rotated["new_id"], NOW + 2000)["valid"] is True


def test_expired_session_rejected_at_zero_tolerance():
    store = _new_store(principal="alice")
    sid = "7" * SESSION_ID_LENGTH
    bind(store, sid, "alice", NOW)

    assert validate(store, sid, NOW + TTL_MS - 1)["valid"] is True
    expired = validate(store, sid, NOW + TTL_MS)
    assert expired["valid"] is False
    assert expired["reason"] == "expired"
    assert validate(store, sid, NOW + TTL_MS + 1)["valid"] is False


def test_binding_user_mismatch_rejected():
    alice_sid = "8" * SESSION_ID_LENGTH
    bob_sid = "9" * SESSION_ID_LENGTH
    store = _new_store(principal="alice")
    bind(store, alice_sid, "alice", NOW)
    bind(store, bob_sid, "bob", NOW)

    assert validate(store, alice_sid, NOW)["valid"] is True
    assert validate(store, bob_sid, NOW)["reason"] == "binding_mismatch"

    store["principal"] = "bob"
    assert validate(store, alice_sid, NOW)["reason"] == "binding_mismatch"
    assert validate(store, bob_sid, NOW)["valid"] is True


def test_invalidate_all_leaves_no_active_session():
    store = _new_store(principal="alice")
    alice_sids = ["a1" + "0" * 62, "a2" + "0" * 62, "a3" + "0" * 62]
    for sid in alice_sids:
        bind(store, sid, "alice", NOW)
    bind(store, "b1" + "0" * 62, "bob", NOW)

    removed = invalidate_all(store, "alice")
    assert removed == 3
    for sid in alice_sids:
        assert validate(store, sid, NOW)["valid"] is False

    assert validate_store(store) == []
    store["principal"] = "bob"
    assert validate(store, "b1" + "0" * 62, NOW)["valid"] is True


def test_two_users_batch_matches_separate_runs():
    events = _batch_events()
    together = session_batch(events, {"ttl": 300})

    alice_events = [event for event in events if event["user"] == "alice"]
    bob_events = [event for event in events if event["user"] == "bob"]
    alice_only = session_batch(alice_events, {"ttl": 300})
    bob_only = session_batch(bob_events, {"ttl": 300})

    assert together["alice"] == alice_only["alice"]
    assert together["bob"] == bob_only["bob"]
    assert together["alice"]["active"] == ["a" * SESSION_ID_LENGTH]
    assert together["bob"]["active"] == ["b" * SESSION_ID_LENGTH]
