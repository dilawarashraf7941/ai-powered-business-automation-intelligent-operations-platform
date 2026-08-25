"""Single fixed action executor; no registry or generic dispatch exists."""

from ai_business_automation.models import GHLAddContactTagParameters
from ai_business_automation.providers import GHLProvider


class ContactTagExecutor:
    """Expose only the dedicated provider contact-tag method."""

    def __init__(self, provider: GHLProvider) -> None:
        self._provider = provider

    def execute(self, parameters: GHLAddContactTagParameters) -> None:
        self._provider.add_contact_tag(parameters)
