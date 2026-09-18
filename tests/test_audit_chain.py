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


def test_actor_user_id_siempre_esta_en_el_payload(fake_admin):
    """El key set del payload es fijo: si una entrada omitiera la clave cuando
    vale None, la reconstrucción de verify_chain (que lee todas las columnas de
    la fila) dejaría de cuadrar. Es lo que obligó a recrear la tabla en HU21."""
    entry = vault_repo.insert_audit(user_id="u1", item_id="i1", action="guardar")
    assert "actor_user_id" in entry
    assert entry["actor_user_id"] is None


def test_cadena_mixta_con_y_sin_actor_verifica(fake_admin):
    """Entradas del propio dueño (actor None) y de su empresa (actor con id)
    conviven en la misma cadena global."""
    vault_repo.insert_audit(user_id="trabajador-1", item_id="i1", action="guardar")
    vault_repo.insert_audit(
        user_id="trabajador-1",
        item_id="i1",
        action="consultar_admin",
        actor_user_id="empresa-1",
    )
    vault_repo.insert_audit(user_id="trabajador-1", item_id="i1", action="consultar")

    ok, broken_id = audit_chain.verify_chain(vault_repo.VAULT_AUDIT_TABLE)
    assert ok is True
    assert broken_id is None


def test_alterar_el_actor_rompe_la_cadena(fake_admin):
    """actor_user_id está cubierto por el hash: falsear quién consultó una
    credencial ajena es detectable, que es el punto de AC7."""
    vault_repo.insert_audit(user_id="trabajador-1", item_id="i1", action="guardar")
    second = vault_repo.insert_audit(
        user_id="trabajador-1",
        item_id="i1",
        action="consultar_admin",
        actor_user_id="empresa-1",
    )
    fake_admin._tables[vault_repo.VAULT_AUDIT_TABLE][1]["actor_user_id"] = "otra-empresa"

    ok, broken_id = audit_chain.verify_chain(vault_repo.VAULT_AUDIT_TABLE)
    assert ok is False
    assert broken_id == second["id"]
