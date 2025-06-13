from abc import ABC

from aleph_message.status import MessageStatus

from .types import TokenType
from .utils import displayable_amount


class QueryError(ABC, ValueError):
    """The result of an API query is inconsistent."""

    pass


class MessageNotFoundError(QueryError):
    """A message was expected but could not be found."""

    pass


class MultipleMessagesError(QueryError):
    """Multiple messages were found when a single message is expected."""

    pass


class MessageNotProcessed(Exception):
    """
    The resources that you arte trying to interact is not processed
    """

    item_hash: str
    status: MessageStatus

    def __init__(
        self,
        item_hash: str,
        status: MessageStatus,
    ):
        self.item_hash = item_hash
        self.status = status
        super().__init__(
            f"Resources {item_hash} is not processed : {self.status.value}"
        )


class NotAuthorize(Exception):
    """
    Request not authorize, this could happens for exemple in Ports Forwarding
    if u try to setup ports for a vm who is not yours
    """

    item_hash: str
    target_address: str
    current_address: str

    def __init__(self, item_hash: str, target_address, current_address):
        self.item_hash = item_hash
        self.target_address = target_address
        self.current_address = current_address
        super().__init__(
            f"Operations not authorize on resources {self.item_hash} \nTarget address : {self.target_address} \nCurrent address : {self.current_address}"
        )


class VmNotFoundOnHost(Exception):
    """
    The VM not found on the host,
    The Might might not be processed yet / wrong CRN_URL
    """

    item_hash: str
    crn_url: str

    def __init__(
        self,
        item_hash: str,
        crn_url,
    ):
        self.item_hash = item_hash
        self.crn_url = crn_url

        super().__init__(f"Vm : {self.item_hash} not found on crn : {self.crn_url}")


class MethodNotAvailableOnCRN(Exception):
    """
    If this error appears that means CRN you trying to interact is outdated and does
    not handle this feature
    """

    pass


class BroadcastError(Exception):
    """
    Data could not be broadcast to the aleph.im network.
    """

    def __init__(self, errors):
        self.errors = errors
        super().__init__(errors)


class InvalidMessageError(BroadcastError):
    """
    The message could not be broadcast because it does not follow the aleph.im
    message specification.
    """

    pass


class BadSignatureError(Exception):
    """
    The signature of a message is invalid.
    """

    pass


class FileTooLarge(Exception):
    """
    A file is too large
    """

    pass


class DomainConfigurationError(Exception):
    """Raised when the domain checks are not satisfied"""

    pass


class ForgottenMessageError(QueryError):
    """The requested message was forgotten"""

    pass


class RemovedMessageError(QueryError):
    """The requested message was removed"""

    pass


class ResourceNotFoundError(QueryError):
    """A message resource was expected but could not be found."""

    pass


class InsufficientFundsError(Exception):
    """Raised when the account does not have enough funds to perform an action"""

    token_type: TokenType
    required_funds: float
    available_funds: float

    def __init__(
        self, token_type: TokenType, required_funds: float, available_funds: float
    ):
        self.token_type = token_type
        self.required_funds = required_funds
        self.available_funds = available_funds
        super().__init__(
            f"Insufficient funds ({self.token_type.value}): required {displayable_amount(self.required_funds, decimals=8)}, available {displayable_amount(self.available_funds, decimals=8)}"
        )


class InvalidHashError(QueryError):
    """The Hash is not valid"""

    pass
