"""Legacy module bridge. Import UserCredentialHandler from user_credential_handler."""

from user_credential_handler.handler import CredentialHandlerError, UserCredentialHandler

Wallet = UserCredentialHandler
WalletError = CredentialHandlerError

__all__ = ["Wallet", "WalletError", "UserCredentialHandler", "CredentialHandlerError"]
