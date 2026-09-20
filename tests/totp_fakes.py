"""Repositorio del factor TOTP en memoria, compartido por los tests de HU18.

Replica la semántica CONDICIONAL de los UPDATE reales de totp_repo (mark_used solo gana si el
paso es mayor al último; confirm_factor solo si sigue pendiente). Los cuerpos reales de
totp_repo solo corren contra un Supabase de verdad: los cubre scripts/e2e_hu18_check.py.
"""

import copy


class FakeRepo:
    """totp_repo en memoria, con la misma semántica condicional que los UPDATE reales."""

    def __init__(self):
        self.rows: dict[str, dict] = {}
        self.envelopes_sealed: list[dict] = []

    def get_factor(self, user_id):
        return copy.deepcopy(self.rows.get(user_id))

    def upsert_pending_factor(self, *, user_id, envelope):
        self.envelopes_sealed.append(envelope)
        self.rows[user_id] = {
            "user_id": user_id, "secret_envelope": envelope, "confirmed_at": None,
            "last_time_step": None, "last_used_at": None, "failed_attempts": 0, "locked_until": None,
        }

    def confirm_factor(self, *, user_id, time_step):
        row = self.rows.get(user_id)
        if row is None or row["confirmed_at"]:
            return False
        row.update(confirmed_at="2026-01-01T00:00:00+00:00", last_time_step=time_step,
                   failed_attempts=0, locked_until=None)
        return True

    def mark_used(self, *, user_id, time_step):
        row = self.rows.get(user_id)
        if row is None:
            return False
        last = row["last_time_step"]
        if last is not None and last >= time_step:
            return False
        row.update(last_time_step=time_step, failed_attempts=0, locked_until=None,
                   last_used_at="2026-01-01T00:00:00+00:00")
        return True

    def mark_failure(self, *, user_id, failed_attempts, locked_until):
        self.rows[user_id].update(failed_attempts=failed_attempts, locked_until=locked_until)

    def delete_factor(self, user_id):
        return self.rows.pop(user_id, None) is not None
