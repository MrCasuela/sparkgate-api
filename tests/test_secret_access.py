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
from tests.totp_fakes import enroll_real_factor, totp_env

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


def test_decrypt_secret_solo_lo_llaman_los_modulos_previstos_en_todo_app():
    """La versión sobre TODO app/ (no solo rutas). Suma totp_service, que abre el sobre del
    factor de la persona: ahí el dueño del dato y quien lo lee son la misma persona, y es el
    único caso. Un cuarto módulo que descifre por su cuenta se saltaría el punto de paso, así
    que la lista se cierra acá en vez de crecer con excepciones."""
    naming = {
        path.name
        for path in _py_files()
        if re.search(r"\bdecrypt_secret\(", path.read_text(encoding="utf-8"))
    }
    assert naming == {"vault_crypto.py", "vault.py", "totp_service.py", "secret_access.py"}


def test_el_segundo_factor_solo_lo_verifica_secret_access():
    """La afirmación central de HU18: hay UNA puerta. Ninguna ruta llama al verificador ni a
    totp_service.verify por su cuenta; entran por read_foreign_secret o require_step_up."""
    def files_with(pattern):
        return {
            path.name for path in _py_files()
            if re.search(pattern, path.read_text(encoding="utf-8"))
        }

    assert files_with(r"totp_service\.verify\(") == {"secret_access.py"}
    assert files_with(r"\b_verify_step_up\(") == {"secret_access.py"}


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


def test_el_sobre_del_factor_solo_lo_nombran_su_repositorio_y_su_servicio():
    """El sobre del factor TOTP viaja entero en `secret_envelope`. Un guard hermano del de
    arriba: el material nuevo no queda en una zona sin vigilar."""
    naming = {
        path.name
        for path in _py_files()
        if re.search(r"secret_envelope", path.read_text(encoding="utf-8"))
    }
    assert naming == {"totp_repo.py", "totp_service.py"}


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
    # Estos tests miden el ORDEN del contrato y el AAD, no el factor: se anula el verificador.
    # Los que miden el factor lo reponen con totp_env() y llevan «segundo factor» en el nombre.
    monkeypatch.setattr(secret_access, "_verify_step_up", lambda caller, scope, code: None)
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
    # on_denied sigue siendo de UN argumento; ahora ese argumento es el motivo concreto.
    assert denied == [secret_access.TOTP_INVALIDO]
    assert not any(e.startswith("descifra") for e in crypto["events"])

    # Con el factor correcto, la misma llamada pasa.
    denied.clear()
    assert _read(step_up_code="123456", on_denied=denied.append)["password"] == "P#1"
    assert denied == []


def test_por_defecto_se_exige_segundo_factor(crypto, monkeypatch):
    """El tripwire de HU21, invertido. Se llamaba test_por_defecto_no_se_exige_segundo_factor
    y decía: «hoy _verify_step_up es un no-op (R-HU21-1); este test existe para que el día que
    HU18 lo implemente y falle, sea una decisión y no un accidente». Este es ese día: sin
    factor enrolado, leer un secreto ajeno ya NO pasa, y nada se descifra."""
    totp_env(monkeypatch)  # verificador REAL; nadie enrolado
    denied = []

    with pytest.raises(secret_access.StepUpRequired) as exc:
        _read(step_up_code=None, on_denied=denied.append)

    assert exc.value.status_code == 403
    assert exc.value.code == "totp_no_enrolado"
    assert denied == [secret_access.TOTP_NO_ENROLADO]
    assert not any(e.startswith("descifra") for e in crypto["events"])


def test_segundo_factor_no_enrolado_e_invalido_son_403_distintos(crypto, monkeypatch):
    """La decisión de los dos 403: la UI lleva a enrolarse en un caso y pide el código de
    nuevo en el otro. Con el verificador y el servicio REALES, no un stub."""
    env = totp_env(monkeypatch)
    denied = []

    with pytest.raises(secret_access.StepUpRequired) as sin_factor:
        _read(step_up_code="123456", on_denied=denied.append)

    factor = enroll_real_factor(env, "empresa-1")
    with pytest.raises(secret_access.StepUpRequired) as mal_codigo:
        _read(step_up_code="000000" if factor.code() != "000000" else "000001", on_denied=denied.append)

    assert (sin_factor.value.code, mal_codigo.value.code) == ("totp_no_enrolado", "totp_invalido")
    assert denied == [secret_access.TOTP_NO_ENROLADO, secret_access.TOTP_INVALIDO]
    assert not any(e.startswith("descifra") for e in crypto["events"])


def test_segundo_factor_con_el_codigo_correcto_descifra_una_sola_vez(crypto, monkeypatch):
    env = totp_env(monkeypatch)
    factor = enroll_real_factor(env, "empresa-1")
    denied = []

    assert _read(step_up_code=factor.code(), on_denied=denied.append)["password"] == "P#1"
    assert denied == []
    # Orden del contrato con el factor REAL en medio: KEK -> (factor) -> descifrado.
    assert crypto["events"] == ["disponible?", "descifra(aad=org-1)"]

    # El mismo código no sirve de nuevo (anti-replay), y no descifra.
    with pytest.raises(secret_access.StepUpRequired) as exc:
        _read(step_up_code=factor.code(), on_denied=denied.append)
    assert exc.value.code == "totp_reutilizado"
    assert denied == [secret_access.TOTP_REUTILIZADO]
    assert [e for e in crypto["events"] if e.startswith("descifra")] == ["descifra(aad=org-1)"]


def test_segundo_factor_sin_clave_del_factor_falla_cerrado_con_503_y_no_descifra(crypto, monkeypatch):
    """No poder verificar NO es «código inválido» y jamás deja pasar. 503, no 403: y no es una
    denegación del usuario, así que no llama a on_denied."""
    from app.core.config import settings

    env = totp_env(monkeypatch)
    factor = enroll_real_factor(env, "empresa-1")
    monkeypatch.setattr(settings, "totp_master_key", "")
    denied = []

    with pytest.raises(ServiceUnavailableError) as exc:
        _read(step_up_code=factor.code(), on_denied=denied.append)

    assert exc.value.status_code == 503
    assert denied == []
    assert not any(e.startswith("descifra") for e in crypto["events"])


# --------------------------------------------------------------------------
# require_step_up: la puerta de las ESCRITURAS sensibles
# --------------------------------------------------------------------------


def test_require_step_up_y_read_foreign_secret_entran_por_el_mismo_verificador(crypto, monkeypatch):
    llamadas = []
    monkeypatch.setattr(
        secret_access, "_verify_step_up", lambda caller, scope, code: llamadas.append((scope, code))
    )

    secret_access.require_step_up(caller=CALLER, scope="credential_rotation", code="111111")
    _read(step_up_code="222222")

    assert llamadas == [("credential_rotation", "111111"), ("org_credential", "222222")]


def test_require_step_up_avisa_a_la_ruta_con_el_motivo_y_relanza(monkeypatch):
    def _rechaza(caller, scope, code):
        raise secret_access.StepUpRequired(code="totp_reutilizado")

    monkeypatch.setattr(secret_access, "_verify_step_up", _rechaza)
    denied = []

    with pytest.raises(secret_access.StepUpRequired) as exc:
        secret_access.require_step_up(
            caller=CALLER, scope="credential_secret_write", code="1", on_denied=denied.append
        )

    assert exc.value.code == "totp_reutilizado"
    assert denied == ["totp_reutilizado"]


def test_require_step_up_no_depende_de_la_clave_de_la_boveda(crypto, monkeypatch):
    """La razón de tener dos claves: revocar a alguien no puede depender de la KEK. Con la
    KEK caída, el segundo factor de una ESCRITURA se verifica igual."""
    env = totp_env(monkeypatch)
    factor = enroll_real_factor(env, "empresa-1")
    crypto["available"] = False  # la KEK de la bóveda, caída

    secret_access.require_step_up(caller=CALLER, scope="credential_rotation", code=factor.code())

    # ...mientras que LEER un secreto sí sigue exigiéndola (no hay nada que descifrar).
    factor.tick()
    with pytest.raises(ServiceUnavailableError):
        _read(step_up_code=factor.code())


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
