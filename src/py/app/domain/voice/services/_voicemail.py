from __future__ import annotations

from advanced_alchemy.extensions.litestar import repository, service

from app.db import models as m


class VoicemailBoxService(service.SQLAlchemyAsyncRepositoryService[m.VoicemailBox]):
    """Voicemail Box Service."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.VoicemailBox]):
        """Voicemail Box Repository."""

        model_type = m.VoicemailBox

    repository_type = Repo


class VoicemailMessageService(service.SQLAlchemyAsyncRepositoryService[m.VoicemailMessage]):
    """Voicemail Message Service."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.VoicemailMessage]):
        """Voicemail Message Repository."""

        model_type = m.VoicemailMessage

    repository_type = Repo
