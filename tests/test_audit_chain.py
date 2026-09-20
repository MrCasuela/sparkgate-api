import pytest

from datetime import datetime, timezone

from app.services import audit_chain, dashboard_repo, vault_repo


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


# --------------------------------------------------------------------------
# Cadena por payload jsonb (dashboard_audit_log)
# --------------------------------------------------------------------------

PANEL_TABLE = "dashboard_audit_log"


def test_la_cadena_jsonb_tolera_una_clave_nueva(fake_admin):
    """Es la prueba de que se aplicó la lección de la cadena por columnas: ahí agregar
    una columna invalidaba toda la historia (obligó a recrear la tabla en HU21). Con el
    payload en una columna jsonb, una entrada con una clave más no toca lo ya hasheado."""
    audit_chain.append_entry_jsonb(PANEL_TABLE, {"action": "crear_trabajador", "org_id": "o1"})
    audit_chain.append_entry_jsonb(
        PANEL_TABLE, {"action": "guardar_secreto", "org_id": "o1", "clave_nueva_de_mañana": "x"}
    )
    audit_chain.append_entry_jsonb(PANEL_TABLE, {"action": "consultar_secreto", "org_id": "o1"})

    ok, broken_id = audit_chain.verify_chain_jsonb(PANEL_TABLE)
    assert ok is True
    assert broken_id is None


def test_alterar_el_payload_jsonb_rompe_la_cadena(fake_admin):
    audit_chain.append_entry_jsonb(PANEL_TABLE, {"action": "crear_trabajador", "actor_user_id": "u1"})
    second = audit_chain.append_entry_jsonb(
        PANEL_TABLE, {"action": "consultar_secreto", "actor_user_id": "u1"}
    )
    # Falsear quién consultó el secreto, después del hecho.
    fake_admin._tables[PANEL_TABLE][1]["payload"]["actor_user_id"] = "otro-usuario"

    ok, broken_id = audit_chain.verify_chain_jsonb(PANEL_TABLE)
    assert ok is False
    assert broken_id == second["id"]


def test_extra_queda_fuera_del_hash_y_se_puede_anular_sin_romper_la_cadena(fake_admin):
    """actor_email es un dato personal en texto plano. Si el dueño de la cuenta empresa
    ejerce su derecho de supresión (Ley 21.719) se anula sin romper la cadena: es el
    mismo dilema que la ADR de supresión ya resolvió para vault_audit_log."""
    audit_chain.append_entry_jsonb(
        PANEL_TABLE, {"action": "crear_trabajador"}, extra={"actor_email": "admin@pyme.cl"}
    )
    audit_chain.append_entry_jsonb(
        PANEL_TABLE, {"action": "consultar_secreto"}, extra={"actor_email": "admin@pyme.cl"}
    )
    for row in fake_admin._tables[PANEL_TABLE]:
        row["actor_email"] = None  # supresión

    ok, _ = audit_chain.verify_chain_jsonb(PANEL_TABLE)
    assert ok is True


@pytest.mark.parametrize(
    "value",
    [1.0, 3, datetime(2026, 9, 18, tzinfo=timezone.utc), ["lista"], {"anidado": "x"}],
)
def test_el_payload_jsonb_rechaza_valores_que_jsonb_normalizaria(fake_admin, value):
    """jsonb normaliza los números (1.0 vuelve como 1) y no serializa datetimes: releer
    cambiaría el json.dumps y rompería el hash sin que nadie tocara la fila. Se rechaza
    en el origen en vez de descubrirlo en verify_chain."""
    with pytest.raises(TypeError):
        audit_chain.append_entry_jsonb(PANEL_TABLE, {"action": "x", "valor": value})
    assert fake_admin._tables.get(PANEL_TABLE, []) == []


def test_insert_audit_log_hashea_el_payload_completo_y_deja_el_email_fuera(fake_admin):
    entry = dashboard_repo.insert_audit_log(
        org_id="org-1",
        actor_user_id="admin-1",
        actor_email="admin@pyme.cl",
        member_id="member-1",
        action="consultar_secreto",
        credential_id="cred-1",
        credential_type="externa",
    )
    # Igualdad EXACTA del payload: es lo que hace demostrable que ningún secreto entra.
    assert entry["payload"] == {
        "org_id": "org-1",
        "actor_user_id": "admin-1",
        "member_id": "member-1",
        "target_member_id": None,
        "credential_id": "cred-1",
        "credential_type": "externa",
        "vault_item_id": None,
        "action": "consultar_secreto",
    }
    assert entry["actor_email"] == "admin@pyme.cl"
    assert "actor_email" not in entry["payload"]
    forbidden = {"password", "new_password", "notes", "ciphertext", "wrapped_dek", "secret"}
    assert forbidden.isdisjoint(entry["payload"])
    assert audit_chain.verify_chain_jsonb(PANEL_TABLE) == (True, None)


def test_list_audit_log_proyecta_solo_claves_conocidas():
    """Una clave que se agregue al payload más adelante no puede aflorar sola en la
    respuesta de la API: la proyección es explícita."""
    flat = dashboard_repo._flatten_audit_row(
        {
            "id": "a1",
            "actor_email": None,
            "created_at": "2026-09-18T00:00:00Z",
            "payload": {
                "action": "reasignar_credencial",
                "actor_user_id": "u1",
                "member_id": "m1",
                "target_member_id": "m2",
                "clave_futura_no_prevista": "no debe salir",
            },
        }
    )
    assert flat["target_member_id"] == "m2"
    assert flat["actor_email"] is None
    assert "clave_futura_no_prevista" not in flat


# --------------------------------------------------------------------------
# Carrera sobre prev_hash: reintento
# --------------------------------------------------------------------------


class _UniqueViolation(Exception):
    code = "23505"


class _RacyQuery(_FakeQuery):
    def __init__(self, rows, insert_row, on_insert):
        super().__init__(rows, insert_row=insert_row)
        self._on_insert = on_insert

    def execute(self):
        self._on_insert()
        return super().execute()


class _RacyTable(_FakeTable):
    def __init__(self, rows, on_insert):
        super().__init__(rows)
        self._on_insert = on_insert

    def insert(self, row):
        return _RacyQuery(self._rows, super().insert(row)._insert_row, self._on_insert)


class _RacyAdmin(_FakeAdmin):
    """Simula que OTRO escritor gana la cola justo antes de nuestro insert: el segundo
    insert choca con la restricción UNIQUE de prev_hash."""

    def __init__(self, fail_times, error=None):
        super().__init__()
        self.fail_times = fail_times
        self.attempts = 0
        self.error = error or _UniqueViolation("duplicate key value violates unique constraint")

    def table(self, name):
        self._tables.setdefault(name, [])
        return _RacyTable(self._tables[name], lambda: self._race(name))

    def _race(self, name):
        self.attempts += 1
        if self.attempts > self.fail_times:
            return
        rows = self._tables[name]
        prev = rows[-1]["entry_hash"] if rows else audit_chain.GENESIS
        competitor = {"action": "escritura-concurrente"}
        seq = len(rows) + 1
        rows.append(
            {
                "id": f"id-{seq}",
                "seq": seq,
                "created_at": f"2026-01-01T00:00:{seq:02d}Z",
                **competitor,
                "prev_hash": prev,
                "entry_hash": audit_chain.compute_hash(prev, competitor),
            }
        )
        raise self.error


@pytest.fixture
def racy_admin(monkeypatch):
    def _make(fail_times, error=None):
        admin = _RacyAdmin(fail_times, error)
        monkeypatch.setattr(audit_chain, "get_supabase_admin", lambda: admin)
        return admin

    return _make


def test_append_reintenta_cuando_otra_escritura_gana_la_cola(racy_admin):
    admin = racy_admin(fail_times=1)
    entry = audit_chain.append_entry("t", {"action": "guardar"})

    assert admin.attempts == 2
    rows = admin._tables["t"]
    assert [r["action"] for r in rows] == ["escritura-concurrente", "guardar"]
    # El reintento recalculó desde la cola NUEVA: reintentar el mismo insert habría
    # repetido el mismo prev_hash y vuelto a chocar.
    assert entry["prev_hash"] == rows[0]["entry_hash"]
    assert audit_chain.verify_chain("t") == (True, None)


def test_append_jsonb_tambien_reintenta(racy_admin):
    admin = racy_admin(fail_times=2)
    audit_chain.append_entry_jsonb("t", {"action": "consultar_secreto"})

    assert admin.attempts == 3
    assert len(admin._tables["t"]) == 3  # dos concurrentes + la nuestra


def test_append_se_rinde_tras_los_intentos_maximos(racy_admin):
    admin = racy_admin(fail_times=99)
    with pytest.raises(_UniqueViolation):
        audit_chain.append_entry("t", {"action": "guardar"})
    assert admin.attempts == audit_chain.MAX_APPEND_ATTEMPTS


def test_un_error_que_no_es_colision_no_se_reintenta(racy_admin):
    admin = racy_admin(fail_times=99, error=RuntimeError("la base se cayó"))
    with pytest.raises(RuntimeError):
        audit_chain.append_entry("t", {"action": "guardar"})
    assert admin.attempts == 1


# --------------------------------------------------------------------------
# denied_reason (HU18): por qué el segundo factor rechazó una operación
# --------------------------------------------------------------------------


def _insert_denied(reason, action="revocar_interna_denegado"):
    return dashboard_repo.insert_audit_log(
        org_id="org-1",
        actor_user_id="admin-1",
        actor_email="admin@pyme.cl",
        member_id="member-1",
        action=action,
        credential_id="cred-1",
        credential_type="interna",
        denied_reason=reason,
    )


def test_denied_reason_va_en_el_payload_solo_cuando_existe(fake_admin):
    con = _insert_denied("totp_invalido")
    sin = dashboard_repo.insert_audit_log(
        org_id="org-1", actor_user_id="a", actor_email=None, member_id=None, action="crear_trabajador"
    )

    assert con["payload"]["denied_reason"] == "totp_invalido"
    # Las demás acciones quedan con el payload de siempre: el de igualdad exacta no cambia.
    assert "denied_reason" not in sin["payload"]


def test_una_cadena_con_y_sin_denied_reason_sigue_verificando(fake_admin):
    """Agregar una clave al payload no invalida lo ya hasheado: es la propiedad por la que
    esta tabla se encadena por jsonb y no por columnas."""
    dashboard_repo.insert_audit_log(
        org_id="o", actor_user_id="a", actor_email=None, member_id=None, action="crear_trabajador"
    )
    _insert_denied("totp_no_enrolado")
    dashboard_repo.insert_audit_log(
        org_id="o", actor_user_id="a", actor_email=None, member_id=None, action="consultar_secreto"
    )
    _insert_denied("totp_reutilizado", action="sugerir_externa_denegado")

    assert audit_chain.verify_chain_jsonb(PANEL_TABLE) == (True, None)


def test_alterar_el_motivo_de_una_denegacion_rompe_la_cadena(fake_admin):
    """El motivo queda protegido por el hash: nadie puede reescribir «totp_invalido» como
    «totp_reutilizado» sin que se note."""
    entry = _insert_denied("totp_invalido")
    fake_admin._tables[PANEL_TABLE][0]["payload"]["denied_reason"] = "totp_reutilizado"

    ok, broken_id = audit_chain.verify_chain_jsonb(PANEL_TABLE)
    assert ok is False and broken_id == entry["id"]


@pytest.mark.parametrize("valor", ["123456", "12 34 56", "totp invalido", "TOTP_INVALIDO", "", "a" * 41])
def test_denied_reason_rechaza_todo_lo_que_no_sea_un_enum(fake_admin, valor):
    """El guard es del repositorio y no de quien llama: aunque una ruta le pasara un código
    TOTP por error, no llega a la auditoría."""
    with pytest.raises(ValueError):
        _insert_denied(valor)
    assert fake_admin._tables.get(PANEL_TABLE, []) == []


def test_list_audit_log_proyecta_denied_reason_y_la_api_lo_expone():
    """Los tres lugares del fallo G8: payload, proyección y schema de salida."""
    from app.schemas.dashboard import AuditLogEntryOut

    flat = dashboard_repo._flatten_audit_row(
        {
            "id": "a1",
            "actor_email": None,
            "created_at": "2026-09-19T00:00:00Z",
            "payload": {"action": "revocar_interna_denegado", "denied_reason": "totp_invalido"},
        }
    )
    assert flat["denied_reason"] == "totp_invalido"
    assert AuditLogEntryOut(**flat).model_dump()["denied_reason"] == "totp_invalido"


def test_denied_reason_es_none_en_las_filas_anteriores_a_hu18():
    flat = dashboard_repo._flatten_audit_row(
        {"id": "a1", "actor_email": None, "created_at": "2026-09-18T00:00:00Z",
         "payload": {"action": "consultar_secreto"}}
    )
    assert flat["denied_reason"] is None
