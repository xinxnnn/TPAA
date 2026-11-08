"""Legacy import bridge for existing tests and demos.

New code should import UserCredentialHandler from user_credential_handler and must
not describe this server-side development component as a user-controlled wallet.
"""

from user_credential_handler import CredentialHandlerError, UserCredentialHandler

Wallet = UserCredentialHandler
WalletError = CredentialHandlerError

__all__ = ["Wallet", "WalletError", "UserCredentialHandler", "CredentialHandlerError"]
