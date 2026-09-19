from datetime import datetime

from pydantic import BaseModel, computed_field


class AssignedCredentialOut(BaseModel):
    """Una credencial de la organización que se le asignó al usuario.

    Nunca lleva el secreto: eso solo sale por el endpoint de reveal, que audita.
    """

    id: str
    organization_name: str
    service_name: str
    type: str
    username: str | None = None
    status: str
    secret_updated_at: datetime | None = None
    updated_at: datetime

    @computed_field  # type: ignore[prop-decorator]
    @property
    def has_secret(self) -> bool:
        return self.secret_updated_at is not None
