import pytest

from app.services import audit_chain, vault_repo


class _FakeResult:
    def __init__(self, data):
        self.data = data


class _FakeQuery:
    """Minimal in-memory stand-in for the chunk of the supabase-py query
    builder that audit_chain.py actually calls: select/order/limit/insert/execute."""

    def __init__(self, rows, insert_row=None):
        self._rows = rows
        self._desc = False
        self._limit = None
        self._insert_row = insert_row

    def select(self, *_args, **_kwargs):
        return self

    def order(self, _col, desc=False):
        self._desc = desc
        return self

    def limit(self, n):
        self._limit = n
        return self

    def execute(self):
        if self._insert_row is not None:
            self._rows.append(self._insert_row)
            return _FakeResult([self._insert_row])
        data = sorted(self._rows, key=lambda r: r["seq"], reverse=self._desc)
        if self._limit is not None:
            data = data[: self._limit]
        return _FakeResult(data)


class _FakeTable:
    def __init__(self, rows):
        self._rows = rows

    def select(self, *_args, **_kwargs):
        return _FakeQuery(self._rows)

    def insert(self, row):
        seq = len(self._rows) + 1
        full_row = {"id": f"id-{seq}", "seq": seq, "created_at": f"2026-01-01T00:00:{seq:02d}Z", **row}
        return _FakeQuery(self._rows, insert_row=full_row)


class _FakeAdmin:
    def __init__(self):
        self._tables: dict[str, list[dict]] = {}

    def table(self, name):
        self._tables.setdefault(name, [])
        return _FakeTable(self._tables[name])


@pytest.fixture
def fake_admin(monkeypatch):
    admin = _FakeAdmin()
    monkeypatch.setattr(audit_chain, "get_supabase_admin", lambda: admin)
    return admin


def test_first_entry_uses_genesis(fake_admin):
    entry = audit_chain.append_entry("t", {"action": "guardar"})
    assert entry["prev_hash"] == audit_chain.GENESIS
    assert entry["entry_hash"] == audit_chain.compute_hash(audit_chain.GENESIS, {"action": "guardar"})


def test_each_entry_chains_the_previous_hash(fake_admin):
    first = audit_chain.append_entry("t", {"action": "guardar"})
    second = audit_chain.append_entry("t", {"action": "listar"})
    assert second["prev_hash"] == first["entry_hash"]
    assert second["entry_hash"] == audit_chain.compute_hash(first["entry_hash"], {"action": "listar"})


def test_verify_chain_ok_on_untouched_chain(fake_admin):
    audit_chain.append_entry("t", {"action": "guardar"})
    audit_chain.append_entry("t", {"action": "consultar"})
    ok, broken_id = audit_chain.verify_chain("t")
    assert ok is True
    assert broken_id is None


def test_verify_chain_detects_mutated_entry(fake_admin):
    audit_chain.append_entry("t", {"action": "guardar"})
    second = audit_chain.append_entry("t", {"action": "consultar"})
    fake_admin._tables["t"][1]["action"] = "eliminar"  # tamper after the fact

    ok, broken_id = audit_chain.verify_chain("t")
    assert ok is False
    assert broken_id == second["id"]


def test_vault_audit_payload_never_carries_secrets(fake_admin):
    entry = vault_repo.insert_audit(user_id="u1", item_id="i1", action="guardar", result="ok")
    forbidden = {"service_name", "password", "notes", "username", "ciphertext"}
    assert forbidden.isdisjoint(entry.keys())
