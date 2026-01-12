"""
Tests for authorization methods in AlephClient.
"""

from typing import Any, Dict, Iterable, Optional, Tuple

import pytest
from aleph_message.models import AggregateMessage, Chain, MessageType
from aleph_message.status import MessageStatus

from aleph.sdk.client.abstract import AuthenticatedAlephClient
from aleph.sdk.types import (
    Account,
    Authorization,
    AuthorizationBuilder,
    SecurityAggregateContent,
)


class FakeAccount:
    """Minimal fake account for testing."""

    CHAIN = "ETH"
    CURVE = "secp256k1"

    def __init__(self, address: str = "0xTestAddress1234567890123456789012345678"):
        self._address = address

    async def sign_message(self, message: Dict) -> Dict:
        message["signature"] = "0x" + "ab" * 65
        return message

    async def sign_raw(self, buffer: bytes) -> bytes:
        return b"fake_signature"

    def get_address(self) -> str:
        return self._address

    def get_public_key(self) -> str:
        return "0x" + "cd" * 33


class MockAlephClient(AuthenticatedAlephClient):
    """
    A fake authenticated client that maintains an in-memory aggregate store.
    Aggregates are dictionaries that get merged/updated with each create_aggregate call.
    """

    def __init__(self, account: Optional[Account] = None):
        self.account = account or FakeAccount()
        # Storage: {address: {key: content}}
        self._aggregates: Dict[str, Dict[str, Any]] = {}

    async def fetch_aggregate(self, address: str, key: str) -> Dict[str, Any]:
        """Fetch a single aggregate by address and key."""
        if address not in self._aggregates:
            return {"authorizations": []}
        return self._aggregates[address].get(key, {"authorizations": []})

    async def fetch_aggregates(
        self, address: str, keys: Optional[Iterable[str]] = None
    ) -> Dict[str, Dict]:
        """Fetch multiple aggregates."""
        if address not in self._aggregates:
            return {}
        if keys is None:
            return self._aggregates[address]
        return {k: v for k, v in self._aggregates[address].items() if k in keys}

    async def create_aggregate(
        self,
        key: str,
        content: Dict[str, Any],
        address: Optional[str] = None,
        channel: Optional[str] = None,
        inline: bool = True,
        sync: bool = False,
    ) -> Tuple[AggregateMessage, MessageStatus]:
        """
        Create/update an aggregate. Merges content into existing aggregate.
        """
        address = address or self.account.get_address()

        if address not in self._aggregates:
            self._aggregates[address] = {}

        # Aggregates merge content (like a dict update)
        if key in self._aggregates[address]:
            self._aggregates[address][key].update(content)
        else:
            self._aggregates[address][key] = content

        # Return a minimal mock message
        mock_message = AggregateMessage.model_validate(
            {
                "item_hash": "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
                "type": "AGGREGATE",
                "chain": "ETH",
                "sender": address,
                "signature": "0x" + "ab" * 65,
                "item_type": "inline",
                "item_content": "{}",
                "content": {
                    "key": key,
                    "address": address,
                    "content": content,
                    "time": 0,
                },
                "time": 0,
                "channel": channel or "TEST",
            }
        )
        return mock_message, MessageStatus.PROCESSED

    # Stub implementations for abstract methods we don't need
    async def create_post(self, *args, **kwargs):
        raise NotImplementedError

    async def create_store(self, *args, **kwargs):
        raise NotImplementedError

    async def create_program(self, *args, **kwargs):
        raise NotImplementedError

    async def create_instance(self, *args, **kwargs):
        raise NotImplementedError

    async def forget(self, *args, **kwargs):
        raise NotImplementedError

    async def submit(self, *args, **kwargs):
        raise NotImplementedError

    async def get_posts(self, *args, **kwargs):
        raise NotImplementedError

    async def download_file(self, *args, **kwargs):
        raise NotImplementedError

    async def download_file_to_path(self, *args, **kwargs):
        raise NotImplementedError

    async def get_messages(self, *args, **kwargs):
        raise NotImplementedError

    async def get_message(self, *args, **kwargs):
        raise NotImplementedError

    def watch_messages(self, *args, **kwargs):
        raise NotImplementedError

    def get_estimated_price(self, *args, **kwargs):
        raise NotImplementedError

    def get_program_price(self, *args, **kwargs):
        raise NotImplementedError


# Fixtures
@pytest.fixture
def mock_client() -> MockAlephClient:
    """Create a fresh fake client for each test."""
    return MockAlephClient()


@pytest.fixture
def mock_client_with_existing_auth() -> MockAlephClient:
    """Create a fake client with pre-existing authorizations."""
    client = MockAlephClient()
    client._aggregates[client.account.get_address()] = {
        "security": {
            "authorizations": [
                {
                    "address": "0xExistingAddress123456789012345678901234",
                    "chain": "ETH",
                    "channels": ["existing_channel"],
                    "types": ["POST"],
                    "post_types": [],
                    "aggregate_keys": [],
                }
            ]
        }
    }
    return client


# Tests for get_authorizations
class TestGetAuthorizations:
    @pytest.mark.asyncio
    async def test_get_authorizations_empty(self, mock_client: MockAlephClient):
        """When no authorizations exist, returns empty list."""
        authorizations = await mock_client.get_authorizations(
            mock_client.account.get_address()
        )
        assert authorizations == []

    @pytest.mark.asyncio
    async def test_get_authorizations_returns_existing(
        self, mock_client_with_existing_auth: MockAlephClient
    ):
        """Returns existing authorizations from aggregate store."""
        authorizations = await mock_client_with_existing_auth.get_authorizations(
            mock_client_with_existing_auth.account.get_address()
        )

        assert len(authorizations) == 1
        assert authorizations[0].address == "0xExistingAddress123456789012345678901234"
        assert authorizations[0].chain == Chain.ETH
        assert authorizations[0].channels == ["existing_channel"]


# Tests for update_all_authorizations
class TestUpdateAllAuthorizations:
    @pytest.mark.asyncio
    async def test_update_replaces_all_authorizations(
        self, mock_client: MockAlephClient
    ):
        """update_all_authorizations replaces the entire authorization list."""
        auth1 = Authorization(address="0xAddress1111111111111111111111111111111111")
        auth2 = Authorization(address="0xAddress2222222222222222222222222222222222")

        await mock_client.update_all_authorizations([auth1, auth2])

        # Verify stored content
        stored = mock_client._aggregates[mock_client.account.get_address()]["security"]
        assert len(stored["authorizations"]) == 2

    @pytest.mark.asyncio
    async def test_update_with_empty_list_clears_authorizations(
        self, mock_client_with_existing_auth: MockAlephClient
    ):
        """Passing an empty list removes all authorizations."""
        await mock_client_with_existing_auth.update_all_authorizations([])

        authorizations = await mock_client_with_existing_auth.get_authorizations(
            mock_client_with_existing_auth.account.get_address()
        )
        assert authorizations == []

    @pytest.mark.asyncio
    async def test_update_preserves_authorization_fields(
        self, mock_client: MockAlephClient
    ):
        """All authorization fields are preserved when storing."""
        auth = Authorization(
            address="0xFullAuth111111111111111111111111111111111",
            chain=Chain.ETH,
            channels=["channel1", "channel2"],
            types=[MessageType.post, MessageType.aggregate],
            post_types=["blog", "comment"],
            aggregate_keys=["settings"],
        )

        await mock_client.update_all_authorizations([auth])

        authorizations = await mock_client.get_authorizations(
            mock_client.account.get_address()
        )
        assert len(authorizations) == 1
        retrieved = authorizations[0]
        assert retrieved.address == auth.address
        assert retrieved.chain == Chain.ETH
        assert retrieved.channels == ["channel1", "channel2"]
        assert MessageType.post in retrieved.types
        assert "blog" in retrieved.post_types


# Tests for add_authorization
class TestAddAuthorization:
    @pytest.mark.asyncio
    async def test_add_to_empty(self, mock_client: MockAlephClient):
        """Adding authorization when none exist."""
        auth = Authorization(address="0xNewAddress1111111111111111111111111111111")

        await mock_client.add_authorization(auth)

        authorizations = await mock_client.get_authorizations(
            mock_client.account.get_address()
        )
        assert len(authorizations) == 1
        assert (
            authorizations[0].address == "0xNewAddress1111111111111111111111111111111"
        )

    @pytest.mark.asyncio
    async def test_add_appends_to_existing(
        self, mock_client_with_existing_auth: MockAlephClient
    ):
        """Adding authorization appends to existing list."""
        new_auth = Authorization(
            address="0xNewAddress2222222222222222222222222222222",
            channels=["new_channel"],
        )

        await mock_client_with_existing_auth.add_authorization(new_auth)

        authorizations = await mock_client_with_existing_auth.get_authorizations(
            mock_client_with_existing_auth.account.get_address()
        )
        assert len(authorizations) == 2
        addresses = [a.address for a in authorizations]
        assert "0xExistingAddress123456789012345678901234" in addresses
        assert "0xNewAddress2222222222222222222222222222222" in addresses

    @pytest.mark.asyncio
    async def test_add_multiple_authorizations_sequentially(
        self, mock_client: MockAlephClient
    ):
        """Adding multiple authorizations one by one."""
        auth1 = Authorization(address="0xFirst11111111111111111111111111111111111")
        auth2 = Authorization(address="0xSecond2222222222222222222222222222222222")
        auth3 = Authorization(address="0xThird33333333333333333333333333333333333")

        await mock_client.add_authorization(auth1)
        await mock_client.add_authorization(auth2)
        await mock_client.add_authorization(auth3)

        authorizations = await mock_client.get_authorizations(
            mock_client.account.get_address()
        )
        assert len(authorizations) == 3


# Tests for revoke_all_authorizations
class TestRevokeAllAuthorizations:
    @pytest.mark.asyncio
    async def test_revoke_removes_matching_address(
        self, mock_client_with_existing_auth: MockAlephClient
    ):
        """Revoking removes all authorizations for the specified address."""
        await mock_client_with_existing_auth.revoke_all_authorizations(
            "0xExistingAddress123456789012345678901234"
        )

        authorizations = await mock_client_with_existing_auth.get_authorizations(
            mock_client_with_existing_auth.account.get_address()
        )
        assert len(authorizations) == 0

    @pytest.mark.asyncio
    async def test_revoke_keeps_other_addresses(self, mock_client: MockAlephClient):
        """Revoking only removes authorizations for the specified address."""
        auth1 = Authorization(address="0xToRevoke111111111111111111111111111111111")
        auth2 = Authorization(address="0xToKeep22222222222222222222222222222222222")
        auth3 = Authorization(
            address="0xToRevoke111111111111111111111111111111111"
        )  # Duplicate

        await mock_client.update_all_authorizations([auth1, auth2, auth3])

        await mock_client.revoke_all_authorizations(
            "0xToRevoke111111111111111111111111111111111"
        )

        authorizations = await mock_client.get_authorizations(
            mock_client.account.get_address()
        )
        assert len(authorizations) == 1
        assert (
            authorizations[0].address == "0xToKeep22222222222222222222222222222222222"
        )

    @pytest.mark.asyncio
    async def test_revoke_nonexistent_address_is_noop(
        self, mock_client: MockAlephClient
    ):
        """Revoking an address that doesn't exist does nothing."""
        auth = Authorization(address="0xExisting1111111111111111111111111111111111")
        await mock_client.add_authorization(auth)

        await mock_client.revoke_all_authorizations(
            "0xNonExistent22222222222222222222222222222"
        )

        authorizations = await mock_client.get_authorizations(
            mock_client.account.get_address()
        )
        assert len(authorizations) == 1

    @pytest.mark.asyncio
    async def test_revoke_from_empty_is_noop(self, mock_client: MockAlephClient):
        """Revoking when no authorizations exist doesn't error."""
        await mock_client.revoke_all_authorizations(
            "0xAnyAddress111111111111111111111111111111111"
        )

        authorizations = await mock_client.get_authorizations(
            mock_client.account.get_address()
        )
        assert authorizations == []


# Integration tests - full workflows
class TestAuthorizationWorkflows:
    @pytest.mark.asyncio
    async def test_full_lifecycle(self, mock_client: MockAlephClient):
        """Test complete authorization lifecycle: add, verify, revoke."""
        delegate_address = "0xDelegate111111111111111111111111111111111"

        # Initially empty
        authorizations = await mock_client.get_authorizations(
            mock_client.account.get_address()
        )
        assert len(authorizations) == 0

        # Add authorization
        auth = Authorization(
            address=delegate_address,
            channels=["MY_APP"],
            types=[MessageType.post],
        )
        await mock_client.add_authorization(auth)

        # Verify it exists
        authorizations = await mock_client.get_authorizations(
            mock_client.account.get_address()
        )
        assert len(authorizations) == 1
        assert authorizations[0].address == delegate_address
        assert "MY_APP" in authorizations[0].channels

        # Revoke
        await mock_client.revoke_all_authorizations(delegate_address)

        # Verify it's gone
        authorizations = await mock_client.get_authorizations(
            mock_client.account.get_address()
        )
        assert len(authorizations) == 0

    @pytest.mark.asyncio
    async def test_multiple_delegates_workflow(self, mock_client: MockAlephClient):
        """Test managing authorizations for multiple delegate addresses."""
        delegate1 = "0xDelegate1111111111111111111111111111111111"
        delegate2 = "0xDelegate2222222222222222222222222222222222"

        # Add two delegates
        await mock_client.add_authorization(
            Authorization(address=delegate1, channels=["channel_a"])
        )
        await mock_client.add_authorization(
            Authorization(address=delegate2, channels=["channel_b"])
        )

        authorizations = await mock_client.get_authorizations(
            mock_client.account.get_address()
        )
        assert len(authorizations) == 2

        # Revoke first delegate
        await mock_client.revoke_all_authorizations(delegate1)

        authorizations = await mock_client.get_authorizations(
            mock_client.account.get_address()
        )
        assert len(authorizations) == 1
        assert authorizations[0].address == delegate2

    @pytest.mark.asyncio
    async def test_replace_all_authorizations(self, mock_client: MockAlephClient):
        """Test replacing all authorizations at once."""
        # Add initial authorizations
        await mock_client.add_authorization(
            Authorization(address="0xOld111111111111111111111111111111111111111")
        )
        await mock_client.add_authorization(
            Authorization(address="0xOld222222222222222222222222222222222222222")
        )

        # Replace with new set
        new_auths = [
            Authorization(address="0xNew111111111111111111111111111111111111111"),
            Authorization(address="0xNew222222222222222222222222222222222222222"),
            Authorization(address="0xNew333333333333333333333333333333333333333"),
        ]
        await mock_client.update_all_authorizations(new_auths)

        authorizations = await mock_client.get_authorizations(
            mock_client.account.get_address()
        )
        assert len(authorizations) == 3
        addresses = {a.address for a in authorizations}
        assert "0xOld111111111111111111111111111111111111111" not in addresses
        assert "0xNew111111111111111111111111111111111111111" in addresses


# Model tests
class TestAuthorizationModel:
    def test_minimal_authorization(self):
        """Authorization can be created with just an address."""
        auth = Authorization(address="0x1234567890123456789012345678901234567890")
        assert auth.address == "0x1234567890123456789012345678901234567890"
        assert auth.chain is None
        assert auth.channels == []
        assert auth.types == []

    def test_full_authorization(self):
        """Authorization with all fields set."""
        auth = Authorization(
            address="0x1234567890123456789012345678901234567890",
            chain=Chain.ETH,
            channels=["ch1", "ch2"],
            types=[MessageType.post, MessageType.store],
            post_types=["blog"],
            aggregate_keys=["settings"],
        )
        assert auth.chain == Chain.ETH
        assert len(auth.channels) == 2
        assert len(auth.types) == 2

    def test_security_aggregate_serialization(self):
        """SecurityAggregateContent serializes correctly."""
        auth = Authorization(
            address="0x1234567890123456789012345678901234567890",
            channels=["test"],
        )
        content = SecurityAggregateContent(authorizations=[auth])
        dumped = content.model_dump()

        assert "authorizations" in dumped
        assert len(dumped["authorizations"]) == 1
        assert dumped["authorizations"][0]["address"] == auth.address


class TestAuthorizationBuilder:
    def test_authorization_builder_only_address(self):
        """Test the AuthorizationBuilder."""
        auth = AuthorizationBuilder(
            address="0x1234567890123456789012345678901234567890"
        ).build()
        assert auth.address == "0x1234567890123456789012345678901234567890"
        assert auth.chain is None
        assert auth.channels == []
        assert auth.types == []
        assert auth.post_types == []
        assert auth.aggregate_keys == []

    def test_authorization_builder(self):
        """Test the AuthorizationBuilder with a detailed configuration."""
        sample_authorization = Authorization(
            address="0xFullAuth111111111111111111111111111111111",
            chain=Chain.ETH,
            channels=["channel1", "channel2"],
            types=[MessageType.post, MessageType.aggregate],
            post_types=["blog", "comment"],
            aggregate_keys=["settings"],
        )

        auth = AuthorizationBuilder(address=sample_authorization.address).chain(
            sample_authorization.chain
        )
        for channel in sample_authorization.channels:
            auth = auth.channel(channel)
        for message_type in sample_authorization.types:
            auth = auth.message_type(message_type)
        for post_type in sample_authorization.post_types:
            auth = auth.post_type(post_type)
        for aggregate_key in sample_authorization.aggregate_keys:
            auth = auth.aggregate_key(aggregate_key)
        auth = auth.build()

        assert auth == sample_authorization
