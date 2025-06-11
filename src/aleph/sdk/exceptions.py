from abc import ABC

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
