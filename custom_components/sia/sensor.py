from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, State, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from .sia_entity_base import SIABaseEntity, SIAEntityDescription
from .const import AVAILABILITY_EVENT_CODE, CONF_ACCOUNT, CONF_ACCOUNTS
from .utils import get_attr_from_sia_event, get_event_data_from_sia_event
import logging
import re
from typing import Iterable

_LOGGER = logging.getLogger(__name__)

ENTITY_DESCRIPTION_LOG = SIAEntityDescription(
    key="log",
    device_class = None,
    code_consequences={},
)

class SIATextLog(SIABaseEntity):
    """SIA Log entity for text-based logs."""

    @property
    def state(self):
        """Return the latest log line."""
        return self._attr_state if self._attr_state else "Geen logs"


    def update_state(self, sia_event) -> bool:
        """Update the entity state and log the event."""

        if not getattr(sia_event, "sia_code", None):
            _LOGGER.debug("No SIA code present for event %s", sia_event)
            return False

        _LOGGER.info("Received SIA event: %s", sia_event.sia_code)
        # Check if the code has a description
        if sia_event.sia_code.code == "RP":
            return False

        # Build the log message
        add_message = ""
        if sia_event.message:

            actor = f" ({match.group(1)})" if (match := re.search(r"'([^']*)'", sia_event.message)) and match.group(1) else ""
            concerns = sia_event.sia_code.concerns or ""
            what = (match := re.match(r"(\w+)", concerns)) and concerns != "Unused" and match.group(1) or ""

            add_message = f" ({what}: {actor.strip()})" if actor and what else actor

        xsia_suffix = f" - XSIA: {sia_event.x_data}" if sia_event.x_data else ""
        log_entry = f"{sia_event.code} - {sia_event.sia_code.description}{add_message}{xsia_suffix}"
        event_attributes = get_event_data_from_sia_event(sia_event)
        event_attributes.update(get_attr_from_sia_event(sia_event))
        self._attr_extra_state_attributes = event_attributes
        self._attr_state = log_entry

        # Always return True because all logs are relevant
        return True

    def handle_last_state(self, last_state: State | None) -> None:
        """Handle the last state."""
        if last_state is not None:
            self._attr_state = last_state.state

    @callback
    def async_handle_event(self, sia_event) -> None:
        """Process all SIA events regardless of the zone."""
        _LOGGER.debug("Log entity handled event: %s", sia_event)

        relevant_event = self.update_state(sia_event)

        if relevant_event:
            self._attr_extra_state_attributes.update(get_attr_from_sia_event(sia_event))

        if relevant_event or sia_event.code == AVAILABILITY_EVENT_CODE:
            self._attr_available = True
            self._cancel_post_interval_update_cb()
            self.async_create_post_interval_update_cb()

        self.async_write_ha_state()

async def generate_text_logs(hass, entry: ConfigEntry) -> Iterable[SIATextLog]:
    """Generate log entities for each account."""
    entities = []

    # Iterate over all accounts in the configuration
    for account_data in entry.data[CONF_ACCOUNTS]:
        account = account_data[CONF_ACCOUNT]

        # Add a log entity for the hub zone (0)
        entities.append(
            SIATextLog(
                entry=entry,
                account=account,
                zone=0,
                entity_description=ENTITY_DESCRIPTION_LOG,
            )
        )

    return entities


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up SIA log sensors from a config entry."""
    async_add_entities(await generate_text_logs(hass, entry))
