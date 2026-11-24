"""Session rotation and fixation-resistant session handling.

Data model
----------
A store is a plain ``dict`` with these keys::

    {
        "ttl": 300,                 # int seconds
        "principal": "alice",       # authenticated user for this request
        "now": 1700000000000,       # optional int milliseconds for maintenance
        "secret": b"...",           # server-side rotation key, >= 32 bytes
        "sessions": [record, ...],
        "nonces": {sid: {nonce, ...}},
    }

The ``secret`` is an explicit, server-held random value supplied by the
caller.  It must never be exposed in a session ID or derived from the old ID
alone; :func:`rotate` needs it so that an attacker who fixed the pre-login ID
cannot predict the post-login ID.

A session record is a ``dict`` with ``id``, ``user``, ``created_at`` (integer
milliseconds), and ``ttl`` (integer seconds).  Records may also carry a private
``_store`` back-reference so that :func:`rotate` can mutate the owning store.
Durable replay state belongs to the store, never to module globals.

Time contract: every ``now`` / ``created_at`` value is Unix epoch milliseconds;
``ttl`` is in seconds.  Tolerance is exactly zero, so a session whose age is
greater than or equal to its TTL is already expired.
"""

import hashlib
import hmac

SESSION_ID_LENGTH = 64
DEFAULT_TTL_SECONDS = 300
MIN_ENTROPY_BYTES = 32

_HEX_DIGITS = frozenset("0123456789abcdef")


def _is_valid_sid(sid):
    return (
        isinstance(sid, str)
        and len(sid) == SESSION_ID_LENGTH
        and all(character in _HEX_DIGITS for character in sid)
    )


def _find_records(store, sid):
    """Return every live record carrying ``sid`` (duplicates included)."""
    return [record for record in store.get("sessions", []) if record.get("id") == sid]


# ---------------------------------------------------------------------------
# Defect 1 / 2: unpredictable IDs built from explicit entropy, never derived
# from the user name alone or from a predictable global random source.
# ---------------------------------------------------------------------------
def new_id(entropy, user):
    """Create a fixed-length, unpredictable session identifier.

    Args:
        entropy: Explicit bytes-like random source, at least
            ``MIN_ENTROPY_BYTES`` bytes.  The function must not read a global
            random source or the clock.
        user: Non-empty user identifier bound into the derivation.

    Returns:
        A string of exactly ``SESSION_ID_LENGTH`` lowercase hexadecimal
        characters.  For the same ``entropy`` and ``user`` the result is
        deterministic; changing either input must change the result.  The
        derivation must use the entropy as keying material (for example
        HMAC-SHA256), not merely hash the user name.

    Raises:
        ValueError: If entropy is too short or user is empty.
    """
    if not isinstance(entropy, (bytes, bytearray, memoryview)):
        raise ValueError("entropy must be bytes-like")
    if len(entropy) < MIN_ENTROPY_BYTES:
        raise ValueError(
            "entropy must be at least %d bytes" % MIN_ENTROPY_BYTES
        )
    if not isinstance(user, str) or not user:
        raise ValueError("user must be a non-empty string")

    # HMAC-SHA256 uses the explicit entropy as the key; the user is bound into
    # the message so two users with the same entropy get distinct IDs.
    digest = hmac.new(
        bytes(entropy),
        b"session-id" + user.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return digest[:SESSION_ID_LENGTH]


def bind(store, sid, user, now):
    """Bind a session ID to a user with a creation time and TTL.

    The record is appended to ``store["sessions"]`` and returned.  Its fields
    are ``id`` (the supplied ``sid``), ``user``, ``created_at`` (``now`` in
    milliseconds), and ``ttl`` (``store["ttl"]`` in seconds).  A private
    ``_store`` back-reference may be included.  Duplicate IDs must not silently
    replace existing records; callers are expected to use :func:`new_id`.

    Raises:
        ValueError: If ``sid`` is not exactly ``SESSION_ID_LENGTH`` lowercase
            hexadecimal characters or ``user`` is empty.
    """
    if not _is_valid_sid(sid):
        raise ValueError(
            "sid must be exactly %d lowercase hexadecimal characters"
            % SESSION_ID_LENGTH
        )
    if not isinstance(user, str) or not user:
        raise ValueError("user must be a non-empty string")

    # Defect 5: always record the creation time (ms) and TTL (seconds) so
    # expiry checks have an explicit, unit-aware basis.
    record = {
        "id": sid,
        "user": user,
        "created_at": now,
        "ttl": store["ttl"],
        "_store": store,
    }
    # Append instead of replacing: duplicate IDs remain visible to validation
    # and maintenance rather than silently shadowing an existing session.
    store.setdefault("sessions", []).append(record)
    return record


# ---------------------------------------------------------------------------
# Defects 2-4: post-login rotation.
# ---------------------------------------------------------------------------
def rotate(old, user, now):
    """Rotate an authenticated session after login.

    ``old`` is a record returned by :func:`bind` or a previous
    :func:`rotate`.  A successful rotation must:

    * create a new ID with :func:`new_id`, using the store's server-side
      ``secret`` together with the old ID, user, and ``now`` as keying
      material, then binding the same user; the old ID alone is attacker-known
      in a fixation attack and must not be the only entropy;
    * delete the old record from its owner store so the old ID is invalid
      immediately;
    * insert a fresh record whose ``created_at`` is ``now`` and whose TTL is
      the store's TTL, not the old record's remaining lifetime;
    * be atomic with respect to concurrent calls on the same old record: at
      most one call may succeed, every other call reports ``"stale"``.

    Returns:
        On success::

            {
                "ok": True,
                "reason": "rotated",
                "old_id": old["id"],
                "new_id": new_sid,
                "session": new_record,
            }

        On failure::

            {
                "ok": False,
                "reason": "stale" | "user_mismatch" | "missing_store"
                          | "missing_secret",
                "old_id": old["id"],
                "new_id": None,
            }
    """
    old_id = old.get("id")

    def _fail(reason):
        return {
            "ok": False,
            "reason": reason,
            "old_id": old_id,
            "new_id": None,
        }

    # The back-reference is the only link to the owning store; a record with
    # none cannot be rotated (its old ID could not be revoked).
    owner = old.get("_store")
    if not isinstance(owner, dict):
        return _fail("missing_store")

    secret = owner.get("secret")
    if not isinstance(secret, (bytes, bytearray, memoryview)) or len(secret) < MIN_ENTROPY_BYTES:
        return _fail("missing_secret")

    if old.get("user") != user:
        return _fail("user_mismatch")

    # Atomicity: only the call that still finds this exact record in its owner
    # store may rotate it.  A second call on the same record sees it gone and
    # reports "stale".
    sessions = owner.setdefault("sessions", [])
    for index, record in enumerate(sessions):
        if record is old:
            break
    else:
        return _fail("stale")

    # Defect 2/3: keying material combines the server secret (unknown to a
    # fixation attacker), old ID, user, and rotation time -- never the old ID
    # alone.
    derivation_material = b"".join(
        (
            old_id.encode("utf-8"),
            b"\x00",
            user.encode("utf-8"),
            b"\x00",
            str(now).encode("ascii"),
        )
    )
    new_sid = new_id(secret + hmac.new(secret, derivation_material, hashlib.sha256).digest(), user)

    # Defect 3: revoke the old ID before installing the new one, so there is
    # no window in which both IDs are valid.
    del sessions[index]
    # Defect 4: the fresh record starts a full TTL at ``now`` instead of
    # inheriting the old record's remaining lifetime.
    new_record = bind(owner, new_sid, user, now)

    return {
        "ok": True,
        "reason": "rotated",
        "old_id": old_id,
        "new_id": new_sid,
        "session": new_record,
    }


# ---------------------------------------------------------------------------
# Defects 6-7: validation binds the principal and normalizes time units.
# ---------------------------------------------------------------------------
def validate(store, sid, now):
    """Validate a session for the store's current principal.

    A session is valid only when all of the following hold:

    * a record with ``sid`` exists and has not been revoked or removed;
    * ``created_at`` plus ``ttl`` is still in the future; at exactly the
      boundary the session is expired (tolerance is zero);
    * ``record["user"]`` equals ``store["principal"]``.

    The check must normalize milliseconds and seconds correctly:
    ``now - created_at < ttl * 1000`` is the valid-age condition.

    Returns:
        A dict with ``valid`` (bool), ``reason`` (``"ok"``, ``"missing"``,
        ``"expired"``, ``"binding_mismatch"``, or ``"duplicate"``), ``id``,
        ``user`` (the bound user, or ``None``), ``created_at``, and ``ttl``.
        The function must not mutate the store.
    """
    matches = _find_records(store, sid)

    if not matches:
        return {
            "valid": False,
            "reason": "missing",
            "id": sid,
            "user": None,
            "created_at": None,
            "ttl": None,
        }

    record = matches[0]

    if len(matches) > 1:
        reason = "duplicate"
    else:
        reason = "ok"

    # Defect 7: created_at/now are milliseconds, ttl is seconds; convert the
    # TTL to milliseconds explicitly.  Zero tolerance: age == ttl is expired.
    age_ms = now - record["created_at"]
    if age_ms >= record["ttl"] * 1000:
        reason = "expired"
    # Defect 6: the bound user must match the authenticated principal, so a
    # session created for A can never authenticate B.
    elif record["user"] != store.get("principal"):
        reason = "binding_mismatch"

    return {
        "valid": reason == "ok",
        "reason": reason,
        "id": sid,
        "user": record["user"],
        "created_at": record["created_at"],
        "ttl": record["ttl"],
    }


# ---------------------------------------------------------------------------
# Defect 8: replay state lives in the durable store, never in module globals.
# ---------------------------------------------------------------------------
def replay_guard(store, sid, nonce):
    """Detect replay or concurrent reuse of a session ID and nonce pair.

    The first use of ``nonce`` for ``sid`` records it in the store and returns
    ``True``.  A repeated use returns ``False``.  The nonce set must live in
    ``store["nonces"]`` (keyed by session ID) so the replay window survives a
    process restart; a module-level or per-call set is not sufficient.  The
    operation must be atomic for concurrent requests carrying the same pair.

    Args:
        store: Session store.
        sid: Session ID to scope the nonce to.
        nonce: Non-empty opaque string supplied by the caller.

    Returns:
        ``True`` for the first observed pair, ``False`` for a replay or for an
        unknown session ID.
    """
    if not nonce or not _find_records(store, sid):
        return False

    nonces = store.setdefault("nonces", {})
    seen = nonces.setdefault(sid, set())
    if nonce in seen:
        return False
    # Check-then-add on one set: within a single interpreter only one caller
    # can observe the absence and perform the insert.
    seen.add(nonce)
    return True


# ---------------------------------------------------------------------------
# Defect 9: logging out everywhere revokes every device, not just one.
# ---------------------------------------------------------------------------
def invalidate_all(store, user):
    """Invalidate every session belonging to ``user`` on every device.

    All matching records are removed from ``store["sessions"]`` and their
    nonce state is removed from ``store["nonces"]``.  Sessions belonging to
    other users must be untouched.

    Returns:
        The number of session records invalidated (``0`` when there are none).
    """
    removed_ids = [
        record["id"]
        for record in store.get("sessions", [])
        if record.get("user") == user
    ]
    store["sessions"] = [
        record
        for record in store.get("sessions", [])
        if record.get("user") != user
    ]

    nonces = store.get("nonces", {})
    for sid in removed_ids:
        nonces.pop(sid, None)

    return len(removed_ids)


def validate_store(store):
    """Inspect a store and return human-readable consistency problems.

    Uses ``store["now"]`` (milliseconds) as the maintenance clock.  The returned
    list is empty for a clean store.  Each string starts with one of these
    stable prefixes so tests and operators can classify it:

    * ``"duplicate id: <sid>"`` for the same active ID appearing more than once;
    * ``"expired id: <sid>"`` for a session at or beyond its TTL still present;
    * ``"missing binding: <sid>"`` when ``user`` is absent or empty;
    * ``"bad record: <sid>"`` for malformed ``created_at`` or ``ttl`` values.

    The function must not mutate the store.
    """
    now = store.get("now")
    problems = []
    seen_ids = set()

    for record in store.get("sessions", []):
        sid = record.get("id")

        if sid in seen_ids:
            problems.append("duplicate id: %s" % sid)
        else:
            seen_ids.add(sid)

        created_at = record.get("created_at")
        ttl = record.get("ttl")
        if (
            not isinstance(created_at, int)
            or isinstance(created_at, bool)
            or not isinstance(ttl, int)
            or isinstance(ttl, bool)
            or ttl < 0
        ):
            problems.append("bad record: %s" % sid)
            continue

        # Same explicit ms/s normalization as validate(); zero tolerance.
        if now is not None and now - created_at >= ttl * 1000:
            problems.append("expired id: %s" % sid)

        if not record.get("user"):
            problems.append("missing binding: %s" % sid)

    return problems


# ---------------------------------------------------------------------------
# Defect 10: per-user isolation inside one batch; stores must never be shared
# across users.
# ---------------------------------------------------------------------------
def session_batch(events, config):
    """Process per-user session events in chronological order.

    ``config`` is ``{"ttl": <seconds>, "secret": b"..."}``; ``secret`` is
    required only when the batch contains ``"rotate"`` events.  ``events`` is
    an iterable of dicts::

        {"at": 1700000000000, "user": "alice", "op": "bind",
         "sid": "..."}

    Supported ``op`` values are ``"bind"``, ``"rotate"`` (``sid`` is the old),
    ``"validate"``, ``"replay"`` (with ``nonce``), and ``"invalidate_all"``.
    Events are processed in ascending ``at`` order (stable for ties).  Each
    user's state must be isolated: one user's events must never see or mutate
    another user's sessions, even though a single batch store is reused.

    Returns:
        ``{user: {"active": [sorted active session IDs at the end],
                  "results": [per-event result dicts in chronological order]}}``

        Each result contains at least ``at``, ``op``, ``sid``, ``ok``, and
        ``reason``.  ``active`` is sorted lexicographically and uses the last
        event time as the validation clock.
    """
    ordered = sorted(events, key=lambda event: event["at"])

    # One independent store per user: a user's events can only ever hit their
    # own sessions and nonces, regardless of interleaving in the batch.
    stores = {}
    last_event_at = {}
    results = {}

    def _store_for(user):
        if user not in stores:
            stores[user] = {
                "ttl": config["ttl"],
                "principal": user,
                "now": None,
                "secret": config.get("secret"),
                "sessions": [],
                "nonces": {},
            }
            results[user] = []
        return stores[user]

    for event in ordered:
        user = event["user"]
        store = _store_for(user)
        at = event["at"]
        sid = event.get("sid")
        last_event_at[user] = at

        op = event["op"]
        if op == "bind":
            try:
                bind(store, sid, user, at)
                outcome = {"ok": True, "reason": "bound"}
            except ValueError:
                outcome = {"ok": False, "reason": "bad_sid"}

        elif op == "rotate":
            matches = _find_records(store, sid)
            if not matches:
                outcome = {
                    "ok": False,
                    "reason": "stale",
                }
            else:
                rotated = rotate(matches[0], user, at)
                # Result rows always echo the event's (old) sid; the new ID
                # is observable through the store / active list.
                outcome = {
                    "ok": rotated["ok"],
                    "reason": rotated["reason"],
                }

        elif op == "validate":
            checked = validate(store, sid, at)
            outcome = {
                "ok": checked["valid"],
                "reason": checked["reason"],
            }

        elif op == "replay":
            fresh = replay_guard(store, sid, event.get("nonce"))
            outcome = {
                "ok": fresh,
                "reason": "ok" if fresh else "replay",
            }

        elif op == "invalidate_all":
            invalidate_all(store, user)
            outcome = {
                "ok": True,
                "reason": "invalidated",
            }

        else:
            outcome = {"ok": False, "reason": "unknown_op"}

        results[user].append(
            {
                "at": at,
                "op": op,
                "sid": sid,
                "ok": outcome["ok"],
                "reason": outcome["reason"],
            }
        )

    summary = {}
    for user, store in stores.items():
        clock = last_event_at[user]
        active = sorted(
            record["id"]
            for record in store["sessions"]
            if validate(store, record["id"], clock)["valid"]
        )
        summary[user] = {
            "active": active,
            "results": results[user],
        }
    return summary
