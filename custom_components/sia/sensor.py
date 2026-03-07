"""Module for SIA log sensors."""

from collections.abc import Iterable
import logging
import re

from homeassistant.components.sensor import SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import MAX_LENGTH_STATE_STATE
from homeassistant.core import HomeAssistant, State, callback
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .const import AVAILABILITY_EVENT_CODE, CONF_ACCOUNT, CONF_ACCOUNTS
from .pysiaalarm import SIAEvent
from .sia_entity_base import SIABaseEntity, SIAEntityDescription
from .utils import get_attr_from_sia_event, get_event_data_from_sia_event

_LOGGER = logging.getLogger(__name__)

DEFAULT_LOG_STATE = "No logs"
ATTR_FULL_LOG_ENTRY = "full_log_entry"

ENTITY_DESCRIPTION_LOG = SIAEntityDescription(
    key="log",
    device_class=None,
    code_consequences={},
)


class SIATextLog(SIABaseEntity, SensorEntity):
    """SIA Log entity for text-based logs."""

    @property
    def native_value(self) -> str:
        """Return the latest log line."""
        return getattr(self, "_attr_native_value", None) or DEFAULT_LOG_STATE

    def update_state(self, sia_event: SIAEvent) -> bool:
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
            actor = (
                f" ({match.group(1)})"
                if (match := re.search(r"'([^']*)'", sia_event.message))
                and match.group(1)
                else ""
            )
            concerns = sia_event.sia_code.concerns or ""
            what = (
                (match := re.match(r"(\w+)", concerns))
                and concerns != "Unused"
                and match.group(1)
                or ""
            )

            add_message = f" ({what}: {actor.strip()})" if actor and what else actor

        xsia_suffix = f" - XSIA: {sia_event.x_data}" if sia_event.x_data else ""
        log_entry = (
            f"{sia_event.code} - {sia_event.sia_code.description}"
            f"{add_message}{xsia_suffix}"
        )
        summary = f"{sia_event.code} - {sia_event.sia_code.description}"[
            :MAX_LENGTH_STATE_STATE
        ]
        event_attributes = get_event_data_from_sia_event(sia_event)
        event_attributes.update(get_attr_from_sia_event(sia_event))
        event_attributes[ATTR_FULL_LOG_ENTRY] = log_entry
        self._attr_extra_state_attributes = event_attributes
        self._attr_native_value = summary

        # Always return True because all logs are relevant
        return True

    def handle_last_state(self, last_state: State | None) -> None:
        """Handle the last state."""
        if last_state is not None:
            self._attr_native_value = last_state.state

    @callback
    def async_handle_event(self, sia_event: SIAEvent) -> None:
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


def generate_text_logs(entry: ConfigEntry) -> Iterable[SIATextLog]:
    """Generate log entities for each account."""
    for account_data in entry.data[CONF_ACCOUNTS]:
        account = account_data[CONF_ACCOUNT]

        yield SIATextLog(
            entry=entry,
            account=account,
            zone=0,
            entity_description=ENTITY_DESCRIPTION_LOG,
        )


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up SIA log sensors from a config entry."""
    async_add_entities(generate_text_logs(entry))
