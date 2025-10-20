"""This is the class for the actual TCP handler override of the handle method."""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from .. import __author__, __copyright__, __license__, __version__
from ..account import SIAAccount
from ..base_server import BaseSIAServer
from ..const import EMPTY_BYTES
from ..event import SIAEvent
from ..utils import Counter, OsborneHoffman

_LOGGER = logging.getLogger(__name__)


class SIAServerTCP(BaseSIAServer):
    """Class for SIA TCP Server Async."""

    def __init__(
        self,
        accounts: dict[str, SIAAccount],
        func: Callable[[SIAEvent], Awaitable[None]],
        counts: Counter,
    ):
        """Create a SIA TCP Server.

        Arguments:
            accounts Dict[str, SIAAccount] -- accounts as dict with account_id as key, SIAAccount object as value.  # pylint: disable=line-too-long
            func Callable[[SIAEvent], None] -- Function called for each valid SIA event, that can be matched to a account.  # pylint: disable=line-too-long
            counts Counter -- counter kept by client to give insights in how many errorous events were discarded of each type.  # pylint: disable=line-too-long
        """
        BaseSIAServer.__init__(self, accounts, counts, async_func=func)

    async def handle_line(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle line for SIA Events. This supports TCP connections.

        Arguments:
            reader {asyncio.StreamReader} -- StreamReader with new data.
            writer {asyncio.StreamWriter} -- StreamWriter to respond.

        """

        while True and not self.shutdown_flag:  # pragma: no cover  # type: ignore
            try:
                data = await reader.read(1000)
            except ConnectionResetError:
                break
            if data == EMPTY_BYTES or reader.at_eof():
                break
            event = self.parse_and_check_event(data)
            if not event:
                continue
            writer.write(event.create_response())
            await writer.drain()
            # Lancer le traitement dans une tâche distincte pour ne pas bloquer l’ACK
            asyncio.create_task(self.async_func_wrap(event))

        writer.close()

class SIAServerOH(BaseSIAServer):
    """Class for SIA Osborne-Hoffman (OH) Server Async."""

    def __init__(
        self,
        accounts: dict[str, SIAAccount],
        func: Callable[[SIAEvent], Awaitable[None]],
        counts: Counter,
        oh: OsborneHoffman | Callable[[], OsborneHoffman] | None = None
    ):
        """Create a SIA OH Server."""
        BaseSIAServer.__init__(self, accounts, counts, async_func=func)
        if callable(oh):
            self._oh_factory = oh  # type: ignore[assignment]
        elif oh is not None:
            self._oh_factory = lambda: oh
        else:
            self._oh_factory = OsborneHoffman

    async def handle_line(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle line for SIA OH Events (Osborne-Hoffman encrypted format)."""

        peername = writer.get_extra_info("peername")
        _LOGGER.debug("New OH connection from: %s", peername)

        oh = self._oh_factory()
        scrambled_key = oh.get_scrambled_key()

        try:
            _LOGGER.debug("Sending scrambled key to: %s", peername)
            writer.write(scrambled_key)
            await writer.drain()

            while True and not self.shutdown_flag:
                buffer = bytearray()
                decrypted_data: bytes | None = None

                while not self.shutdown_flag:
                    try:
                        chunk = await reader.read(1024)
                    except ConnectionResetError:
                        _LOGGER.warning("Connection reset by peer: %s", peername)
                        buffer.clear()
                        break

                    if chunk == EMPTY_BYTES:
                        _LOGGER.debug("Connection closed by client: %s", peername)
                        buffer.clear()
                        break

                    buffer.extend(chunk)

                    if len(buffer) % 8 != 0:
                        continue

                    try:
                        candidate = oh.decrypt_data(bytes(buffer))
                    except ValueError:
                        continue

                    if candidate.startswith(b"SR"):
                        decrypted_data = candidate
                        break

                    if b"\r" not in candidate:
                        continue

                    decrypted_data = candidate
                    break

                if not buffer or decrypted_data is None:
                    if not buffer:
                        break
                    _LOGGER.debug(
                        "Incomplete frame from %s, awaiting additional data.", peername
                    )
                    continue

                data = bytes(buffer)
                _LOGGER.debug("Encrypted data received from %s: %s", peername, data)
                _LOGGER.debug("Decrypted data from %s: %s", peername, decrypted_data)

                event = self.parse_and_check_event(decrypted_data)
                if not event:
                    _LOGGER.warning("Failed to parse event from: %s", peername)
                    continue

                response = event.create_response()
                if isinstance(response, str):
                    response = response.encode()

                encrypted_response = oh.encrypt_data(response)

                _LOGGER.debug("Sending encrypted response to %s: %s", peername, encrypted_response)
                writer.write(encrypted_response)
                await writer.drain()

                asyncio.create_task(self.async_func_wrap(event))

        except Exception as e:
            _LOGGER.exception("Unhandled exception in OH handler for %s: %s", peername, e)

        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionResetError:
                _LOGGER.warning("Client %s reset the connection during close.", peername)
            except Exception as e:
                _LOGGER.warning("Unexpected error while closing connection with %s: %s", peername, e)

            _LOGGER.debug("Connection with %s closed.", peername)


class SIAServerUDP(BaseSIAServer, asyncio.DatagramProtocol):
    """Class for SIA UDP Server Async."""

    def __init__(
        self,
        accounts: dict[str, SIAAccount],
        func: Callable[[SIAEvent], Awaitable[None]],
        counts: Counter,
    ):
        """Create a SIA UDP Server.

        Arguments:
            server_address {tuple(string, int)} -- the address the server should listen on.
            accounts {Dict[str, SIAAccount]} -- accounts as dict with account_id as key, SIAAccount object as value.  # pylint: disable=line-too-long
            func {Callable[[SIAEvent], None]} -- Function called for each valid SIA event, that can be matched to a account.  # pylint: disable=line-too-long
            counts {Counter} -- counter kept by client to give insights in how many errorous events were discarded of each type.  # pylint: disable=line-too-long
        """
        BaseSIAServer.__init__(self, accounts, counts, async_func=func)
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """Connect callback for datagrams."""
        assert isinstance(transport, asyncio.DatagramTransport)
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        """Receive and process datagrams. This support UDP connections."""
        event = self.parse_and_check_event(data)
        if not event:
            return
        if self.transport is not None:
            self.transport.sendto(event.create_response(), addr)
        asyncio.create_task(self.async_func_wrap(event))

    def connection_lost(self, _: Any) -> None:
        """Close and reset transport when connection lost."""
        if self.transport:
            self.transport.close()
