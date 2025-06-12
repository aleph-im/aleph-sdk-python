from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aleph_message.models import Chain

from aleph.sdk.chains.ethereum import get_fallback_account as eth_fallback
from aleph.sdk.chains.solana import get_fallback_account as sol_fallback
from aleph.sdk.client.authenticated_http import AuthenticatedAlephHttpClient
from aleph.sdk.client.http import AlephHttpClient
from aleph.sdk.query.responses import Post, PostsResponse
from aleph.sdk.types import Voucher, VoucherAttribute, VoucherMetadata

# Test data
MOCK_ADDRESS = "0x1234567890123456789012345678901234567890"
MOCK_SOLANA_ADDRESS = "abcdefghijklmnopqrstuvwxyz123456789"

MOCK_METADATA_ID = "metadata123"
MOCK_VOUCHER_ID = "voucher123"

MOCK_METADATA = {
    "name": "Test Voucher",
    "description": "A test voucher",
    "external_url": "https://example.com",
    "image": "https://example.com/image.png",
    "icon": "https://example.com/icon.png",
    "attributes": [
        {"trait_type": "Test Trait", "value": "Test Value"},
        {"trait_type": "Numeric Trait", "value": "123", "display_type": "number"},
    ],
}

MOCK_EVM_VOUCHER_DATA = [
    (MOCK_VOUCHER_ID, {"claimer": MOCK_ADDRESS, "metadata_id": MOCK_METADATA_ID})
]

MOCK_SOLANA_REGISTRY = {
    "claimed_tickets": {
        "solticket123": {"claimer": MOCK_SOLANA_ADDRESS, "batch_id": "batch123"}
    },
    "batches": {"batch123": {"metadata_id": MOCK_METADATA_ID}},
}


@pytest.fixture
def mock_account():
    account = eth_fallback()
    with patch.object(account, "get_address", return_value=MOCK_ADDRESS):
        yield account


@pytest.fixture
def mock_solana_account():
    account = sol_fallback()
    with patch.object(account, "get_address", return_value=MOCK_SOLANA_ADDRESS):
        yield account


@pytest.fixture
def http_client():
    return AlephHttpClient()


@pytest.fixture
def authenticated_client(mock_account):
    return AuthenticatedAlephHttpClient(account=mock_account)


class TestVoucherModels:
    def test_voucher_attribute_creation(self):
        # Test with string value
        attr = VoucherAttribute(trait_type="Test Trait", value="Test Value")
        assert attr.trait_type == "Test Trait"
        assert attr.value == "Test Value"
        assert attr.display_type is None

        # Test with display_type
        attr = VoucherAttribute(
            trait_type="Test Trait", value="Test Value", display_type="number"
        )
        assert attr.trait_type == "Test Trait"
        assert attr.value == "Test Value"
        assert attr.display_type == "number"

        # Test with Decimal value
        attr = VoucherAttribute(trait_type="Test Trait", value=Decimal("123"))
        assert attr.trait_type == "Test Trait"
        assert attr.value == Decimal("123")

    def test_voucher_metadata_creation(self):
        metadata = VoucherMetadata(
            name="Test Voucher",
            description="A test voucher",
            external_url="https://example.com",
            image="https://example.com/image.png",
            icon="https://example.com/icon.png",
            attributes=[VoucherAttribute(trait_type="Test Trait", value="Test Value")],
        )

        assert metadata.name == "Test Voucher"
        assert metadata.description == "A test voucher"
        assert metadata.external_url == "https://example.com"
        assert metadata.image == "https://example.com/image.png"
        assert metadata.icon == "https://example.com/icon.png"
        assert len(metadata.attributes) == 1
        assert metadata.attributes[0].trait_type == "Test Trait"
        assert metadata.attributes[0].value == "Test Value"

    def test_voucher_creation(self):
        voucher = Voucher(
            id=MOCK_VOUCHER_ID,
            metadata_id=MOCK_METADATA_ID,
            name="Test Voucher",
            description="A test voucher",
            external_url="https://example.com",
            image="https://example.com/image.png",
            icon="https://example.com/icon.png",
            attributes=[VoucherAttribute(trait_type="Test Trait", value="Test Value")],
        )

        assert voucher.id == MOCK_VOUCHER_ID
        assert voucher.metadata_id == MOCK_METADATA_ID
        assert voucher.name == "Test Voucher"
        assert voucher.description == "A test voucher"
        assert voucher.external_url == "https://example.com"
        assert voucher.image == "https://example.com/image.png"
        assert voucher.icon == "https://example.com/icon.png"
        assert len(voucher.attributes) == 1
        assert voucher.attributes[0].trait_type == "Test Trait"
        assert voucher.attributes[0].value == "Test Value"


class TestAlephHttpClientVoucher:
    def test_resolve_address(self, http_client):
        # Test with provided address
        address = http_client._resolve_address("0xabcdef")
        assert address == "0xabcdef"

    @pytest.mark.asyncio
    async def test_fetch_voucher_update(self, http_client):
        mock_posts_response = AsyncMock()
        mock_post = MagicMock(spec=Post)
        mock_post.content = {
            "nft_vouchers": {
                MOCK_VOUCHER_ID: {
                    "claimer": MOCK_ADDRESS,
                    "metadata_id": MOCK_METADATA_ID,
                }
            }
        }
        mock_posts_response.posts = [mock_post]

        mock_client = AsyncMock()
        mock_client.get_posts = AsyncMock(return_value=mock_posts_response)

        with patch(
            "aleph.sdk.client.http.AlephHttpClient",
            return_value=AsyncMock(
                __aenter__=AsyncMock(return_value=mock_client), __aexit__=AsyncMock()
            ),
        ):
            result = await http_client._fetch_voucher_update()

        assert len(result) == 1
        assert result[0][0] == MOCK_VOUCHER_ID
        assert result[0][1]["claimer"] == MOCK_ADDRESS
        assert result[0][1]["metadata_id"] == MOCK_METADATA_ID

    @pytest.mark.asyncio
    async def test_fetch_voucher_update_empty(self, http_client):
        mock_posts_response = AsyncMock(spec=PostsResponse)
        mock_posts_response.posts = []

        mock_client = AsyncMock()
        mock_client.get_posts = AsyncMock(return_value=mock_posts_response)

        with patch(
            "aleph.sdk.client.http.AlephHttpClient",
            return_value=AsyncMock(
                __aenter__=AsyncMock(return_value=mock_client), __aexit__=AsyncMock()
            ),
        ):
            result = await http_client._fetch_voucher_update()

        assert result == []

    @pytest.mark.asyncio
    async def test_fetch_solana_voucher(self, http_client):
        with patch("aiohttp.ClientSession") as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value=MOCK_SOLANA_REGISTRY)

            mock_context_manager = AsyncMock()
            mock_context_manager.__aenter__.return_value = mock_response

            mock_session_instance = MagicMock()
            mock_session_instance.get.return_value = mock_context_manager

            mock_session.return_value.__aenter__.return_value = mock_session_instance

            result = await http_client._fetch_solana_voucher_list()

            assert result == MOCK_SOLANA_REGISTRY

    @pytest.mark.asyncio
    async def test_fetch_solana_voucher_error_status(self, http_client):
        with patch("aiohttp.ClientSession") as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 404

            mock_context_manager = AsyncMock()
            mock_context_manager.__aenter__.return_value = mock_response

            mock_session_instance = MagicMock()
            mock_session_instance.get.return_value = mock_context_manager

            mock_session.return_value.__aenter__.return_value = mock_session_instance

            result = await http_client._fetch_solana_voucher_list()

            assert result == {}

    @pytest.mark.asyncio
    async def test_fetch_solana_voucher_content_type_error(self, http_client):
        with patch("aiohttp.ClientSession") as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(side_effect=Exception("ContentTypeError"))
            mock_response.text = AsyncMock(
                return_value="""{"claimed_tickets": {}, "batches": {}}"""
            )

            mock_context_manager = AsyncMock()
            mock_context_manager.__aenter__.return_value = mock_response

            mock_session_instance = MagicMock()
            mock_session_instance.get.return_value = mock_context_manager

            mock_session.return_value.__aenter__.return_value = mock_session_instance

            result = await http_client._fetch_solana_voucher_list()

            assert "claimed_tickets" in result
            assert "batches" in result

    @pytest.mark.asyncio
    async def test_fetch_solana_voucher_json_decode_error(self, http_client):
        with patch("aiohttp.ClientSession") as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(side_effect=Exception("ContentTypeError"))
            mock_response.text = AsyncMock(return_value="Invalid JSON")

            mock_context_manager = AsyncMock()
            mock_context_manager.__aenter__.return_value = mock_response

            mock_session_instance = MagicMock()
            mock_session_instance.get.return_value = mock_context_manager

            mock_session.return_value.__aenter__.return_value = mock_session_instance

            result = await http_client._fetch_solana_voucher_list()

            assert result == {}

    @pytest.mark.asyncio
    async def test_fetch_voucher_metadata(self, http_client):
        with patch("aiohttp.ClientSession") as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value=MOCK_METADATA)

            mock_context_manager = AsyncMock()
            mock_context_manager.__aenter__.return_value = mock_response

            mock_session_instance = MagicMock()
            mock_session_instance.get.return_value = mock_context_manager

            mock_session.return_value.__aenter__.return_value = mock_session_instance

            result = await http_client.fetch_voucher_metadata(MOCK_METADATA_ID)

            assert isinstance(result, VoucherMetadata)
            assert result.name == "Test Voucher"
            assert result.description == "A test voucher"
            assert result.external_url == "https://example.com"
            assert result.image == "https://example.com/image.png"
            assert result.icon == "https://example.com/icon.png"
            assert len(result.attributes) == 2

    @pytest.mark.asyncio
    async def test_fetch_voucher_metadata_error(self, http_client):
        with patch("aiohttp.ClientSession") as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 404

            mock_context_manager = AsyncMock()
            mock_context_manager.__aenter__.return_value = mock_response

            mock_session_instance = MagicMock()
            mock_session_instance.get.return_value = mock_context_manager

            mock_session.return_value.__aenter__.return_value = mock_session_instance

            result = await http_client.fetch_voucher_metadata(MOCK_METADATA_ID)

            assert result is None

    @pytest.mark.asyncio
    async def test_get_evm_voucher(self, http_client):
        http_client._fetch_voucher_update = AsyncMock(
            return_value=MOCK_EVM_VOUCHER_DATA
        )

        mock_metadata = VoucherMetadata(
            name="Test Voucher",
            description="A test voucher",
            external_url="https://example.com",
            image="https://example.com/image.png",
            icon="https://example.com/icon.png",
            attributes=[VoucherAttribute(trait_type="Test Trait", value="Test Value")],
        )
        http_client.fetch_voucher_metadata = AsyncMock(return_value=mock_metadata)

        result = await http_client.get_evm_vouchers(MOCK_ADDRESS)

        assert len(result) == 1
        assert isinstance(result[0], Voucher)
        assert result[0].id == MOCK_VOUCHER_ID
        assert result[0].metadata_id == MOCK_METADATA_ID
        assert result[0].name == "Test Voucher"

    @pytest.mark.asyncio
    async def test_get_evm_voucher_no_match(self, http_client):
        http_client._fetch_voucher_update = AsyncMock(
            return_value=[
                (
                    MOCK_VOUCHER_ID,
                    {"claimer": "0xdifferent", "metadata_id": MOCK_METADATA_ID},
                )
            ]
        )

        result = await http_client.get_evm_vouchers(MOCK_ADDRESS)

        assert len(result) == 0

    @pytest.mark.asyncio
    async def test_get_evm_voucher_no_metadata(self, http_client):
        http_client._fetch_voucher_update = AsyncMock(
            return_value=MOCK_EVM_VOUCHER_DATA
        )
        http_client.fetch_voucher_metadata = AsyncMock(return_value=None)

        result = await http_client.get_evm_vouchers(MOCK_ADDRESS)

        assert len(result) == 0

    @pytest.mark.asyncio
    async def test_get_solana_vouchers(self, http_client):
        http_client._fetch_solana_voucher_list = AsyncMock(
            return_value=MOCK_SOLANA_REGISTRY
        )

        mock_metadata = VoucherMetadata(
            name="Test Voucher",
            description="A test voucher",
            external_url="https://example.com",
            image="https://example.com/image.png",
            icon="https://example.com/icon.png",
            attributes=[VoucherAttribute(trait_type="Test Trait", value="Test Value")],
        )
        http_client.fetch_voucher_metadata = AsyncMock(return_value=mock_metadata)

        result = await http_client.get_solana_vouchers(MOCK_SOLANA_ADDRESS)

        assert len(result) == 1
        assert isinstance(result[0], Voucher)
        assert result[0].id == "solticket123"
        assert result[0].metadata_id == MOCK_METADATA_ID
        assert result[0].name == "Test Voucher"

    @pytest.mark.asyncio
    async def test_get_solana_vouchers_no_match(self, http_client):
        mock_registry = {
            "claimed_tickets": {
                "solticket123": {"claimer": "differentsolana", "batch_id": "batch123"}
            },
            "batches": {"batch123": {"metadata_id": MOCK_METADATA_ID}},
        }
        http_client._fetch_solana_voucher_list = AsyncMock(return_value=mock_registry)

        result = await http_client.get_solana_vouchers(MOCK_SOLANA_ADDRESS)

        assert len(result) == 0

    @pytest.mark.asyncio
    async def test_get_solana_vouchers_no_batch(self, http_client):
        mock_registry = {
            "claimed_tickets": {
                "solticket123": {
                    "claimer": MOCK_SOLANA_ADDRESS,
                    "batch_id": "nonexistent",
                }
            },
            "batches": {},
        }
        http_client._fetch_solana_voucher_list = AsyncMock(return_value=mock_registry)

        result = await http_client.get_solana_vouchers(MOCK_SOLANA_ADDRESS)

        assert len(result) == 0

    @pytest.mark.asyncio
    async def test_get_solana_vouchers_no_metadata(self, http_client):
        http_client._fetch_solana_voucher_list = AsyncMock(
            return_value=MOCK_SOLANA_REGISTRY
        )
        http_client.fetch_voucher_metadata = AsyncMock(return_value=None)

        result = await http_client.get_solana_vouchers(MOCK_SOLANA_ADDRESS)

        assert len(result) == 0

    @pytest.mark.asyncio
    async def test_get_vouchers(self, http_client):
        evm_voucher = Voucher(
            id="evm123",
            metadata_id=MOCK_METADATA_ID,
            name="EVM Voucher",
            description="An EVM voucher",
            external_url="https://example.com",
            image="https://example.com/image.png",
            icon="https://example.com/icon.png",
            attributes=[VoucherAttribute(trait_type="Test Trait", value="Test Value")],
        )
        http_client.get_evm_vouchers = AsyncMock(return_value=[evm_voucher])

        solana_voucher = Voucher(
            id="solana123",
            metadata_id=MOCK_METADATA_ID,
            name="Solana Voucher",
            description="A Solana voucher",
            external_url="https://example.com",
            image="https://example.com/image.png",
            icon="https://example.com/icon.png",
            attributes=[VoucherAttribute(trait_type="Test Trait", value="Test Value")],
        )
        http_client.get_solana_vouchers = AsyncMock(return_value=[solana_voucher])

        result = await http_client.get_vouchers(MOCK_ADDRESS)

        assert len(result) == 2
        assert result[0] == evm_voucher
        assert result[1] == solana_voucher

    @pytest.mark.asyncio
    async def test_fetch_vouchers_by_chain_evm(self, http_client):
        evm_voucher = Voucher(
            id="evm123",
            metadata_id=MOCK_METADATA_ID,
            name="EVM Voucher",
            description="An EVM voucher",
            external_url="https://example.com",
            image="https://example.com/image.png",
            icon="https://example.com/icon.png",
            attributes=[VoucherAttribute(trait_type="Test Trait", value="Test Value")],
        )
        http_client.get_evm_vouchers = AsyncMock(return_value=[evm_voucher])

        result = await http_client.fetch_vouchers_by_chain(Chain.ETH, MOCK_ADDRESS)

        assert len(result) == 1
        assert result[0] == evm_voucher

    @pytest.mark.asyncio
    async def test_fetch_vouchers_by_chain_solana(self, http_client):
        solana_voucher = Voucher(
            id="solana123",
            metadata_id=MOCK_METADATA_ID,
            name="Solana Voucher",
            description="A Solana voucher",
            external_url="https://example.com",
            image="https://example.com/image.png",
            icon="https://example.com/icon.png",
            attributes=[VoucherAttribute(trait_type="Test Trait", value="Test Value")],
        )
        http_client.get_solana_vouchers = AsyncMock(return_value=[solana_voucher])

        result = await http_client.fetch_vouchers_by_chain(Chain.SOL, MOCK_ADDRESS)

        assert len(result) == 1
        assert result[0] == solana_voucher


class TestAuthenticatedAlephHttpClientVoucher:
    def test_resolve_address(self, authenticated_client):
        # Test with provided address
        address = authenticated_client._resolve_address("0xabcdef")
        assert address == "0xabcdef"

        # Test with account address
        address = authenticated_client._resolve_address()
        assert address == MOCK_ADDRESS

        # Test with no address and no account
        with patch.object(authenticated_client, "account", None):
            with pytest.raises(ValueError):
                authenticated_client._resolve_address()

    @pytest.mark.asyncio
    async def test_get_all(self, authenticated_client):
        evm_voucher = Voucher(
            id="evm123",
            metadata_id=MOCK_METADATA_ID,
            name="EVM Voucher",
            description="An EVM voucher",
            external_url="https://example.com",
            image="https://example.com/image.png",
            icon="https://example.com/icon.png",
            attributes=[VoucherAttribute(trait_type="Test Trait", value="Test Value")],
        )

        with patch.object(
            AlephHttpClient, "get_vouchers", new_callable=AsyncMock
        ) as mock_get_vouchers:
            mock_get_vouchers.return_value = [evm_voucher]
            result = await authenticated_client.get_vouchers()
            mock_get_vouchers.assert_called_once_with(address=MOCK_ADDRESS)
            assert len(result) == 1
            assert result[0] == evm_voucher

            # Test with specific address
            result = await authenticated_client.get_vouchers("0xspecific")
            mock_get_vouchers.assert_called_with(address="0xspecific")

    @pytest.mark.asyncio
    async def test_get_evm_voucher(self, authenticated_client):
        evm_voucher = Voucher(
            id="evm123",
            metadata_id=MOCK_METADATA_ID,
            name="EVM Voucher",
            description="An EVM voucher",
            external_url="https://example.com",
            image="https://example.com/image.png",
            icon="https://example.com/icon.png",
            attributes=[VoucherAttribute(trait_type="Test Trait", value="Test Value")],
        )

        with patch.object(
            AlephHttpClient, "get_evm_vouchers", new_callable=AsyncMock
        ) as mock_get_evm:
            mock_get_evm.return_value = [evm_voucher]
            result = await authenticated_client.get_evm_vouchers()
            mock_get_evm.assert_called_once_with(address=MOCK_ADDRESS)
            assert len(result) == 1
            assert result[0] == evm_voucher

            # Test with specific address
            result = await authenticated_client.get_evm_vouchers("0xspecific")
            mock_get_evm.assert_called_with(address="0xspecific")

    @pytest.mark.asyncio
    async def test_get_solana_vouchers(self, authenticated_client):
        solana_voucher = Voucher(
            id="solana123",
            metadata_id=MOCK_METADATA_ID,
            name="Solana Voucher",
            description="A Solana voucher",
            external_url="https://example.com",
            image="https://example.com/image.png",
            icon="https://example.com/icon.png",
            attributes=[VoucherAttribute(trait_type="Test Trait", value="Test Value")],
        )

        with patch.object(
            AlephHttpClient, "get_solana_vouchers", new_callable=AsyncMock
        ) as mock_fetch:
            mock_fetch.return_value = [solana_voucher]
            result = await authenticated_client.get_solana_vouchers()
            mock_fetch.assert_called_once_with(address=MOCK_ADDRESS)
            assert len(result) == 1
            assert result[0] == solana_voucher

            # Test with specific address
            result = await authenticated_client.get_solana_vouchers("0xspecific")
            mock_fetch.assert_called_with(address="0xspecific")
