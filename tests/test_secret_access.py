"""Punto de paso único para leer secretos ajenos (HU21 etapa C).

Dos tipos de test acá:
- HERMÉTICOS: escanean el código fuente para que la garantía no dependa de que alguien
  se acuerde. Si una cuarta ruta descifra por fuera del punto de paso, o un módulo nuevo
  nombra las columnas del criptograma, se cae la suite.
- Unitarios de read_foreign_secret: el orden del contrato, y que el segundo factor de
  HU18 entra por UN solo lugar.
"""

import re
from pathlib import Path

import pytest

from app.api.dependencies import optional_step_up_code
from app.core.exceptions import ServiceUnavailableError
from app.services import secret_access, vault_crypto

APP = Path(__file__).resolve().parent.parent / "app"

ENVELOPE = {
    "ciphertext": "Y2lwaGVy",
    "nonce": "bm9uY2U",
    "wrapped_dek": "d3JhcHBlZA",
    "dek_nonce": "ZGVrbm9uY2U",
    "kek_version": 1,
}
CALLER = {"id": "empresa-1", "email": "admin@pyme.cl"}


# --------------------------------------------------------------------------
# Herméticos
# --------------------------------------------------------------------------


def _py_files(*parts):
    return sorted(APP.joinpath(*parts).rglob("*.py")) if parts else sorted(APP.rglob("*.py"))


def test_ninguna_ruta_descifra_fuera_del_punto_de_paso():
    """decrypt_secret solo puede aparecer en el camino del DUEÑO leyendo lo suyo
    (vault.py). Toda lectura de un secreto ajeno pasa por secret_access, que es donde
    HU18 agrega el segundo factor: una ruta que descifre por su cuenta se lo saltaría."""
    offenders = {
        path.name
        for path in _py_files("api", "routes")
        if re.search(r"\bdecrypt_secret\(", path.read_text(encoding="utf-8"))
    }
    assert offenders == {"vault.py"}


def test_solo_los_modulos_autorizados_nombran_el_criptograma():
    """Las columnas del sobre de la organización solo las nombra credential_secret_repo
    (y vault_crypto, que las produce). Si un listado las nombrara, el criptograma
    viajaría del DB al proceso en cada carga del panel."""
    naming = {
        path.name
        for path in _py_files()
        if re.search(r"ciphertext|wrapped_dek", path.read_text(encoding="utf-8"))
    }
    assert naming == {"credential_secret_repo.py", "vault_crypto.py"}


def test_los_listados_del_panel_usan_columnas_explicitas():
    """select("*") arrastraría al proceso cualquier columna que se agregue después. Hoy
    Pydantic descartaría lo que sobre, pero descartar en silencio es el mecanismo que ya
    falló una vez (G8) y no debe custodiar un secreto."""
    source = (APP / "services" / "dashboard_repo.py").read_text(encoding="utf-8")
    # Una llamada real `.select("*...")`, no la mención en un comentario.
    assert not re.search(r"""\.select\(\s*f?["']\*""", source)


def test_el_schema_de_credencial_no_tiene_ningun_campo_de_secreto():
    from app.schemas.dashboard import CredentialOut

    fields = set(CredentialOut.model_fields) | set(CredentialOut.model_computed_fields)
    assert not fields & {"password", "ciphertext", "nonce", "wrapped_dek", "dek_nonce", "notes"}


# --------------------------------------------------------------------------
# read_foreign_secret
# --------------------------------------------------------------------------


@pytest.fixture
def crypto(monkeypatch):
    """Reemplaza vault_crypto y deja constancia del ORDEN en que se lo llamó."""
    events = []
    state = {"available": True, "plaintext": {"password": "P#1", "notes": None}}

    monkeypatch.setattr(
        secret_access.vault_crypto,
        "is_available",
        lambda: (events.append("disponible?"), state["available"])[1],
    )

    def _decrypt(row, aad):
        events.append(f"descifra(aad={aad})")
        return state["plaintext"]

    monkeypatch.setattr(secret_access.vault_crypto, "decrypt_secret", _decrypt)
    state["events"] = events
    return state


def _read(**overrides):
    kwargs = dict(
        caller=CALLER,
        scope="org_credential",
        subject_id="org-1",
        target_id="cred-1",
        envelope=dict(ENVELOPE),
    )
    kwargs.update(overrides)
    return secret_access.read_foreign_secret(**kwargs)


def test_el_aad_es_el_dueno_del_dato_no_el_de_quien_pregunta(crypto):
    """El AAD identifica de quién es el dato, no quién lo pide. Por eso el acceso de la
    empresa no debilita el cifrado: mover una fila bajo otro dueño sigue fallando."""
    _read(caller={"id": "empresa-1"}, subject_id="org-1")

    assert crypto["events"][-1] == "descifra(aad=org-1)"
    assert "empresa-1" not in crypto["events"][-1]


def test_el_orden_del_contrato_es_disponibilidad_segundo_factor_descifrado(crypto, monkeypatch):
    monkeypatch.setattr(
        secret_access,
        "_verify_step_up",
        lambda caller, scope, code: crypto["events"].append("segundo-factor"),
    )
    _read()
    assert crypto["events"] == ["disponible?", "segundo-factor", "descifra(aad=org-1)"]


def test_sin_clave_maestra_no_se_pide_segundo_factor_ni_se_descifra(crypto, monkeypatch):
    crypto["available"] = False
    called = []
    monkeypatch.setattr(secret_access, "_verify_step_up", lambda *a: called.append("segundo-factor"))

    with pytest.raises(ServiceUnavailableError):
        _read()

    assert called == []
    assert not any(e.startswith("descifra") for e in crypto["events"])


def test_el_segundo_factor_entra_por_un_solo_lugar(crypto, monkeypatch):
    """ES LA PRUEBA DE QUE HU18 ES UN SOLO CAMBIO. Se reemplaza _verify_step_up por uno que
    exige el factor, y read_foreign_secret rechaza sin descifrar y avisa a la ruta con
    on_denied. Ninguna ruta, ninguna firma, ningún contrato de error cambia."""

    def _exige_totp(caller, scope, code):
        if code != "123456":
            raise secret_access.StepUpRequired()

    monkeypatch.setattr(secret_access, "_verify_step_up", _exige_totp)
    denied = []

    with pytest.raises(secret_access.StepUpRequired) as exc:
        _read(step_up_code=None, on_denied=denied.append)
    assert exc.value.status_code == 403
    assert denied == [secret_access.DENIED_STEP_UP]
    assert not any(e.startswith("descifra") for e in crypto["events"])

    # Con el factor correcto, la misma llamada pasa.
    denied.clear()
    assert _read(step_up_code="123456", on_denied=denied.append)["password"] == "P#1"
    assert denied == []


def test_por_defecto_no_se_exige_segundo_factor(crypto):
    """Hoy _verify_step_up es un no-op: HU21 no exige TOTP (R-HU21-1). Este test existe
    para que el día que HU18 lo implemente y falle, sea una decisión y no un accidente."""
    assert _read(step_up_code=None)["password"] == "P#1"


def test_un_fallo_de_integridad_responde_503_y_avisa_a_la_ruta(crypto, monkeypatch):
    def _explode(row, aad):
        raise vault_crypto.InvalidTag()

    monkeypatch.setattr(secret_access.vault_crypto, "decrypt_secret", _explode)
    denied = []

    # 503 y no 404 (escondería una adulteración) ni 500 (sin traza).
    with pytest.raises(ServiceUnavailableError) as exc:
        _read(on_denied=denied.append)

    assert exc.value.status_code == 503
    assert denied == [secret_access.DENIED_INTEGRITY]


def test_seal_secret_cifra_con_el_dueno_del_dato_como_aad(monkeypatch):
    captured = {}

    def _encrypt(payload, aad):
        captured.update(payload=payload, aad=aad)
        return dict(ENVELOPE)

    monkeypatch.setattr(secret_access.vault_crypto, "encrypt_secret", _encrypt)

    envelope = secret_access.seal_secret(subject_id="org-1", password="P#2", notes="nota")

    assert captured == {"payload": {"password": "P#2", "notes": "nota"}, "aad": "org-1"}
    assert set(envelope) == set(ENVELOPE)


@pytest.mark.asyncio
async def test_optional_step_up_code_devuelve_el_header_tal_cual():
    assert await optional_step_up_code(x_sparkgate_totp="123456") == "123456"
    assert await optional_step_up_code(x_sparkgate_totp=None) is None
