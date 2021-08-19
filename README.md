<h1 align="center"><i>
    swmn
</i></h1>

A basic but flexible certificate management solution intended for managing certificate based authentication from a webfrontend or REST api
<br/>

> :warning: If reliability or security is important, please don't use swmn — or at least consider its limitations carefully<sup>[1](#security_note)</sup>.

# Configuration and setup

## Requirements

- `cargo`
- Development libraries, among other:
    - SQLite (`libsqlite3`)
    - python3 (e.g. `python3-dev`)

## Installation

For the api-only version, install directly using
```bash
cargo install --git https://github.com/offdroid/swmn.git
```
For a version with the web interface, it is best to clone the repository as follows.
```bash
git clone https://github.com/offdroid/swmn.git
cd swmn
cargo b --features web-interface
```

## Managing users

Shut the server down if it is running, then create the first user with
```bash
swmn user set <username>
```
This creates a new user or overrides the password of an existing one.
On the other hand, to delete users use
```bash
swmn user remove <username>
```

<details>
<summary>
Note, that a removed but previously logged-in user will have access until the session cookie expires.
Alternatively, logout all users by changing the `secret_key`.
</summary>

For instance by changing `secret_key` in `Rocket.toml` (and restarting swmn afterwards):
```toml
[production] # Or a different environment
secret_key = "some_secure_key"
```
</details>

Please consult the CLI documentation with `swmn user --help` (or source code) for more details.

## CA passphrase

Any certificate authority (CA) should be secured with a passphrase.
This can be set globally: either as plaintext (not recommended), in the keyring or retrieved through a command at startup;
If neither option is set (or all fail) the passphrase has to be provided for each request, that requires it, such as certificate creation.

- **plaintext** set `swmn.ca.passphrase` in `Rocket.toml`
- **command** set `swmn.ca.passphrase_cmd` in `Rocket.toml`
    - Use a utility such as [pass](https://www.passwordstore.org/)
- **keyring** c.f. [Configuration section](#Configuration)

## Managing certificate creation and revocation

You can now start smwn and log in, but not yet manage any certificates.
To be as flexible as possible this process is controlled through a Python script, c.f. [manage.py](./scripts/manage.py).

It must provide the following functions:

```python
def make_cert(cn: str, passphrase: Optional[str], ca_passphrase: str, data):
    pass

def revoke_cert(cn: str, ca_passphrase: str, data):
    pass

def revoke_and_remove_cert(cn: str, ca_passphrase: str, already_revoked, data) -> None:
    pass

def list_certs(data) -> List[str]:
    pass

def get_config(cn: str, data) -> str:
    pass
```

The implementation is left to the user by design and may use Python libraries (such as pyOpenSSL) or the command-line with `os.system()` for instance.
In case of failure, the script functions should throw an exception, which might be propagated the user.

A non-default script location and module name can be defined in the `Rocket.toml` with the following keys:
- `swmn.script.module`
- `swmn.script.path`

# Configuration

Like any Rocket-based server swmn can be configured by a `Rocket.toml` in the working directory of swmn or at the path defined by `ROCKET_CONFIG`.
C.f. [Rocket Configuration](https://rocket.rs/v0.5-rc/guide/configuration/#configuration) for more details.

Apart from basic settings like IP, port and secret-key this includes smwn specific details, such as the location of the `manage.py` script.

Optionally, you can choose to store the CA passphrase in the keyring, which removes the need to explicitly specify it for creation and revokation operations. With the `secret-tool` utility run the following command:
```bash
secret-tool store --label="swmn Certificate Authority (CA)" application rust-keyring service swmn username "Certificate Authority"
```

<details>
<summary>Sample configuration</summary>

```toml
[default]
address = "0.0.0.0"
port = 8000
# Replace with a random value
secret_key = "00000000000000000000000000000000000000000000"

[global.databases]
swmn_db = { url = "db.sqlite" }

[global.swmn]
script.module = "manage"
script.path = "scripts/manage.py"
script.ca.passphrase = "Plaintext password" # Not recommended
# or
# script.ca.passphrase_cmd = "echo 'Do not use echo for this'"
```
</details>

# API

One way of interacting with swmn is through the REST interface.
See the [rest-module](./src/rest) for more details.

# CLI

User-accounts are managed through the CLI. Use `--help` for more details.

<details>
<summary>swmn user</summary>

```
swmn-user
Administrative user management, exists after completion

USAGE:
    swmn user <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    disable    Disable a user
    enable     Enable a user
    help       Prints this message or the help of the given subcommand(s)
    list       List all users
    remove     Remove an existing user; This does not revoke existing session cookies!
    set        Set an user's password or create a new one
```
</details>

# TLS

To ensure a secure connection, use of TLS is highly recommended.
The TLS support of Rocket, which swmn is built on, is not considered production ready.
Compile with the `tls` feature and see [Rocket: Configuring TLS](https://rocket.rs/v0.5-rc/guide/configuration/#tls).
Alternatively and the probably better option would be to use a reverse proxy, such as [NGINX](https://www.nginx.com/) to add TLS.

To enable secure cookies (recommended if using TLS) set the environment variable `SECURE_COOKIES` to `true`.

# Customizing the interface

The html web interface is very basic and works without JS — by design.
It can easily be replaced or extended through modification of the handlebars templates in [templates](./templates).

More ambitious extensions should replace the [`web`](./web/)-crate and/or make use of the REST-apis on the client-side.

`web-interface` and `no-rest-api` are crate features to include or exclude the web interface or REST api.

# Tests

The CLI tests require a swmn executable and are not run by default but can be with the following command
```bash
# Build beforehand, e.g.
# cargo build
cargo test -- --ignored
# or to run all test
cargo test -- --include-ignored
```
This means that you need to build the regular swmn and test binary to test any changes!

To also test all local dependencies use
```bash
cargo test -p api -p cert -p common -p database -p web -p swmn -- --include-ignored
```

# License

Licensed under MIT, see [LICENSE](./LICENSE).

---

<a name="security_note">1</a>: Especially, handling of the CA passphrase might not be sufficiently secure for real-world environments
