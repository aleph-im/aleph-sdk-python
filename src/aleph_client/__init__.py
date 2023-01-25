from pkg_resources import DistributionNotFound, get_distribution

from .user_session import AuthenticatedUserSession, UserSession

try:
    # Change here if project is renamed and does not equal the package name
    dist_name = "aleph-sdk-python"
    __version__ = get_distribution(dist_name).version
except DistributionNotFound:
    __version__ = "unknown"
finally:
    del get_distribution, DistributionNotFound

__all__ = ["AuthenticatedUserSession", "UserSession"]
