# distrust

---

Use discourse as an OIDC (oauth2) provider.

## Installation

To run distrust, copy the `distrust.example.yml` file to `distrust.yml` and customize it to your liking. Afterwards, run the binary or container image.

```sh
./distrust
```

## Installation
You can also use a container engine like podman or docker to run distrust

### Running using podman
```sh
podman run -d \
  --name distrust \
  -v $PWD/distrust.yml:/distrust.yml:Z \
  -p 3000:3000 \
  ghcr.io/parkour-vienna/distrust:$VERSION
```

### Running using docker-compose

Download a release 

```sh
export VERSION=0.0.5
curl https://github.com/Parkour-Vienna/distrust/releases/download/v$VERSION/distrust_$VERSION_Linux_x86_64.tar.gz
tar zxvf distrust_$VERSION_Linux_x86_64.tar.gz
```

Build the image: `docker-compose build`

Up and running: `docker-compose up`

Generate a new key: `docker-compose exec distrust ./distrust genkey`

## Configuration

### Configuring Discourse

To start using discourse as an OIDC provider, you need to configure your
discourse instance. The following site settings need to be set:

- `enable discourse connect provider`
- `discourse connect provider secrets` - Here you need to add the domain of the
  distrust server and choose a secure secret

This configuration must then be entered in the `distrust.yml` file

```yaml
discourse:
  server: https://your-discourse-installation.org
  secret: <your-chosen-secret>
```

### Configuring the oidc provider

The oidc provider is based on [ory/fosite](https://github.com/ory/fosite) and
needs two configuration values to work. The first one is a 32-byte secret. It
must be **exactly** 32 bytes long. The other parameter ist the private key used
for signing the tokens.

If you need a fresh rsa private key, you can run `distrust genkey` to generate
one.

> Both values can be left empty, however this will invalidate _all_ tokens on a
> server restart

```yaml
oidc:
  secret: 'some-exactly-32-byte-long-secret'
  privateKey: |
    -----BEGIN RSA PRIVATE KEY-----
    ....
    -----END RSA PRIVATE KEY-----
```

### Configuring Clients

The last step is the configuration of clients. Here you need to specify a name,
a client secret as well as the allowed redirect URIs.

> As of this point, the redirect URIs do _not_ support wildcards

The following example configures a client called `test` with the secret `foobar`
which is authorized to redirect to the [openid connect test
page](https://openidconnect.net)

```yaml
clients:
  test:
    secret: foobar
    redirectURIs:
      - 'https://openidconnect.net/callback'
```

If you do not want to provide a plaintext secret, you can also provide the
secret as an already hashed bcrypt2 value

#### Group ACLs

In case you want your client to be only available for members of a certain
group, you can populate the `allowGroups` or `denyGroups` fields in the client
config. This will either allow or deny access on a client basis.
