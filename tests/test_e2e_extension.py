"""PT07 — E2E: flujo completo desde la extensión Chrome contra el backend real.

Skeleton, no garantizado end-to-end todavía: requiere selenium instalado
(`pip install selenium`, no está en requirements.txt — es manual-only), un
navegador basado en Chromium (Brave/Chrome) y la extensión sin empaquetar en
`sparkgate-extension/dist/`. El backend debe estar corriendo en :8000
(`./start.sh` en sparkgate-api).

Ejecutar: SPARKGATE_RUN_E2E=1 BRAVE_BINARY=/usr/bin/brave-browser pytest tests/test_e2e_extension.py -v

TODO antes de que esto corra de verdad:
- Confirmar selectores reales del popup (`index.html` no tiene data-testid;
  hay que inspeccionar el DOM renderizado y reemplazar los `# TODO selector`).
- `_get_extension_id` usa un truco de shadow-DOM sobre chrome://extensions;
  si Chrome/Brave cambia su UI interna esto se rompe y hay que ajustarlo.
"""
import os
from pathlib import Path

import pytest

RUN_E2E = os.environ.get("SPARKGATE_RUN_E2E") == "1"
EXTENSION_DIST = os.environ.get(
    "SPARKGATE_EXTENSION_DIST",
    str(Path(__file__).resolve().parents[2] / "sparkgate-extension" / "dist"),
)
BROWSER_BINARY = os.environ.get("BRAVE_BINARY")
BACKEND_URL = os.environ.get("SPARKGATE_BACKEND_URL", "http://localhost:8000")

pytestmark = pytest.mark.skipif(
    not RUN_E2E, reason="E2E manual — requiere selenium + navegador + extensión. Run with SPARKGATE_RUN_E2E=1"
)


def _get_extension_id(driver) -> str:
    """Best-effort: lee el id de la extensión cargada desde chrome://extensions.
    Chrome/Brave renderiza esa página con shadow DOM anidado; este selector
    puede necesitar ajuste según versión de navegador."""
    driver.get("chrome://extensions/")
    extension_id = driver.execute_script("""
        const manager = document.querySelector('extensions-manager');
        const itemList = manager.shadowRoot.querySelector('extensions-item-list');
        const item = itemList.shadowRoot.querySelector('extensions-item');
        return item ? item.getAttribute('id') : null;
    """)
    if not extension_id:
        pytest.fail("No se pudo resolver el id de la extensión desde chrome://extensions")
    return extension_id


@pytest.fixture
def driver():
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
    except ImportError:
        pytest.skip("selenium no instalado — pip install selenium")

    if not Path(EXTENSION_DIST).exists():
        pytest.skip(f"No se encontró la extensión en {EXTENSION_DIST}")

    options = Options()
    if BROWSER_BINARY:
        options.binary_location = BROWSER_BINARY
    options.add_argument(f"--load-extension={EXTENSION_DIST}")
    options.add_argument("--disable-extensions-file-access-check")

    drv = webdriver.Chrome(options=options)
    yield drv
    drv.quit()


def test_extension_popup_loads_and_reaches_backend(driver):
    """Flujo mínimo PT07: la extensión carga, su popup renderiza, y puede
    alcanzar el backend real (no mockeado)."""
    import httpx

    health = httpx.get(f"{BACKEND_URL}/api/v1/health", timeout=5.0)
    assert health.status_code == 200, "Backend no está corriendo — ./start.sh primero"

    extension_id = _get_extension_id(driver)
    driver.get(f"chrome-extension://{extension_id}/index.html")

    # TODO selector: reemplazar por el contenedor raíz real del popup React
    assert "SparkGate" in driver.page_source


@pytest.mark.skip(reason="Pendiente: mapear selectores reales del flujo generar→copiar (HU05/HU08)")
def test_generate_password_flow_end_to_end(driver):
    """Flujo completo: abrir popup, click en Generar, verificar que se muestra
    una contraseña, click en Copiar, verificar clipboard. Requiere selectores
    reales del popup — ver TODO en el docstring del módulo."""
    extension_id = _get_extension_id(driver)
    driver.get(f"chrome-extension://{extension_id}/index.html")

    # generate_btn = driver.find_element(By.CSS_SELECTOR, "# TODO selector")
    # generate_btn.click()
    # password_field = driver.find_element(By.CSS_SELECTOR, "# TODO selector")
    # assert len(password_field.text) > 0
    raise NotImplementedError("Completar selectores reales antes de destildar el skip")
