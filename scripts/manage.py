'''Template for a management script.

Keep in mind that any raised exceptions might be forwarded to the user.

Under normal circumstances swmn should catch duplicate certificate creation requests or requests on non existent clients/certificates, however, the script should be able to handle these anyway.
'''
from typing import Optional, List


def make_cert(cn: str, passphrase: Optional[str], ca_passphrase: str,
              data) -> None:
    '''Make a certifacte
    
    Should follow these 3 steps:
    1. Generate a private key (using the passphrase if any)
    2. Use that to create a CSR
    3. Sign the CSR with the CA

    # Arguments
    * `cn` - Common name of the certifacte to generate
    * `passphrase` - [Optional] passphrase for the client certificate
    * `ca_passphrase` - CA passphrase to sign the CSR
    * `data` - [Optional] dictionary with additional options

    # Common-name not found
    If a client/certifcate with the common name already exists with the provided id exists a `LookupError` should be raised
    '''
    raise NotImplementedError


def revoke_cert(cn: str, ca_passphrase: str, data):
    '''Revoke a certificate by putting it on CRL, but keep any data such as the private key

    Throws an exception on failure!

    # Arguments
    * `cn` - Common name of the certifacte to revoke
    * `ca_passphrase` - CA passphrase to sign the CSR
    * `data` - [Optional] dictionary with additional options

    # Client not found
    If no client with the provided id exists a `LookupError` should be raised
    '''
    raise NotImplementedError


def revoke_and_remove_cert(cn: str, ca_passphrase: str, already_revoked,
                           data) -> None:
    '''Revoke a certificate by putting it on CRL, then delete all data

    # Note
    The certificate should be revoke before it is deleted from the server, to prevent unauthorized access.
    Keep in mind, that the client could already be revoked and may just need removal.

    # Arguments
    * `cn` - Common name of the certifacte to revoke
    * `ca_passphrase` - CA passphrase to sign the CSR
    * `already_revoked` - True if the client is already revoked, meaning only removal is necessary
    * `data` - [Optional] dictionary with additional options

    # Client not found
    If no client with the provided id exists a `LookupError` should be raised
    '''
    raise NotImplementedError


def list_certs(data) -> List[str]:
    '''Returns a list of all common-names/clients — possibly based on the provided extra options

    # Note
    Throws an exception on failure!

    # Arguments
    * `data` - [Optional] dictionary with additional options
    '''
    raise NotImplementedError


def get_config(cn: str, data) -> str:
    '''Returns the requested OpenVPN configuration/profile based on the certificate as a string if any

    # Arguments
    * `cn` - Common name of the client
    * `data` - [Optional] dictionary with additional options

    # Return value
    OpenVPN configuration file (from a file or dynamically generated) for the specified client.
    If no client with the provided id exists a `LookupError` should be raised
    '''
    raise NotImplementedError
