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


class InsufficientFundsError(Exception):
    """Raised when the account does not have enough funds to perform an action"""

    token_type: TokenType
    required_funds: float
    available_funds: float

    def __init__(
        self, token_type: TokenType, required_funds: float, available_funds: float
    ):
        self.token_type = token_type
        self.required_funds = displayable_amount(required_funds, decimals=8)
        self.available_funds = displayable_amount(available_funds, decimals=8)
        super().__init__(
            f"Insufficient funds ({self.token_type.value}): required {self.required_funds}, available {self.available_funds}"
        )


class InvalidHashError(QueryError):
    """The Hash is not valid"""

    pass
