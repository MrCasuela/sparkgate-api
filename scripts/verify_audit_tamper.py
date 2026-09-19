"""Demuestra EN VIVO que la cadena de dashboard_audit_log detecta la alteración de una fila.

Cierra el paso 24 del E2E, que se había omitido porque alterar una fila deja la cadena de
desarrollo rota de forma permanente. Acá la alteración se REVIERTE en un `finally`, y el
script se niega a empezar si la cadena ya está rota (no toca una cadena que no puede
garantizar restaurar). Antes de modificar imprime el valor original, por si hiciera falta
restaurarlo a mano.

Qué prueba (contra la base real, con service_role):
  1. Cadena íntegra al empezar.
  2. Cambiar un campo hasheado del payload (actor_user_id) de una fila del medio ->
     verify_chain_jsonb devuelve (False, <id de ESA fila>).
  3. Restaurar el payload -> vuelve a (True, None).
  4. Cambiar actor_email, que está FUERA del hash a propósito (para poder anularlo por
     supresión, Ley 21.719) -> la cadena sigue íntegra. Restaurar.

Uso:  python scripts/verify_audit_tamper.py | tee docs/evidencia/hu21-audit-tamper.txt
"""

import sys
import uuid

from app.services import audit_chain
from app.services.db_client import get_supabase_admin

TABLE = "dashboard_audit_log"
FOREIGN_ACTOR = str(uuid.uuid4())
failures = 0


def check(label: str, condition: bool) -> None:
    global failures
    print(("PASS  " if condition else "FAIL  ") + label)
    if not condition:
        failures += 1


def main() -> int:
    admin = get_supabase_admin()

    intact, broken = audit_chain.verify_chain_jsonb(TABLE)
    if not intact:
        print(f"ABORTA: la cadena ya está rota (primera fila rota: {broken}). No se toca nada.")
        return 2

    rows = admin.table(TABLE).select("seq,id,payload,actor_email").order("seq").execute().data
    if len(rows) < 3:
        print("ABORTA: hace falta al menos 3 filas para alterar una del medio.")
        return 2
    target = rows[len(rows) // 2]
    original_payload, original_email = target["payload"], target["actor_email"]

    print(f"Filas en la cadena: {len(rows)}")
    check("1. Cadena íntegra antes de tocar nada", intact)
    print(f"Fila objetivo: seq={target['seq']} id={target['id']}")
    print(f"Payload original (para restaurar a mano si hiciera falta): {original_payload!r}")
    print(f"actor_email original: {original_email!r}")

    try:
        tampered = {**original_payload, "actor_user_id": FOREIGN_ACTOR}
        admin.table(TABLE).update({"payload": tampered}).eq("id", target["id"]).execute()
        ok, broken_id = audit_chain.verify_chain_jsonb(TABLE)
        check("2a. Alterar actor_user_id de una fila rompe la cadena", ok is False)
        check("2b. Y señala EXACTAMENTE esa fila", broken_id == target["id"])
    finally:
        admin.table(TABLE).update({"payload": original_payload}).eq("id", target["id"]).execute()

    ok, broken_id = audit_chain.verify_chain_jsonb(TABLE)
    check("3. Restaurado el payload, la cadena vuelve a ser íntegra", ok is True and broken_id is None)

    try:
        admin.table(TABLE).update({"actor_email": "anulado@supresion.test"}).eq("id", target["id"]).execute()
        ok, _ = audit_chain.verify_chain_jsonb(TABLE)
        check("4. Cambiar actor_email (fuera del hash) NO rompe la cadena", ok is True)
    finally:
        admin.table(TABLE).update({"actor_email": original_email}).eq("id", target["id"]).execute()

    ok, broken_id = audit_chain.verify_chain_jsonb(TABLE)
    check("5. Estado final: cadena íntegra y actor_email restaurado", ok is True and broken_id is None)
    restored = admin.table(TABLE).select("payload,actor_email").eq("id", target["id"]).execute().data[0]
    check("6. La fila quedó idéntica a como estaba", restored == {"payload": original_payload, "actor_email": original_email})

    print()
    print("TODO OK" if failures == 0 else f"{failures} FALLA(S)")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
