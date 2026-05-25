# Authentication

NeoFS RPCs expect requests signed with the container/object owner’s ECDSA key (Neo3-style, RFC 6979 deterministic SHA-256).

## WIF private key

Decode a Neo WIF string and derive the owner ID:

```zig
const secret = try sdk.crypto_wif.decodePrivateKey(wif);
const kp = try sdk.crypto_ecdsa.KeyPair.fromSecretBytes(&secret);
const owner = sdk.user.ID.fromKeyPair(kp);

var client = sdk.client.Client.init(allocator);
defer client.deinit();
client.setSignerKey(&secret);
try client.dial(endpoint, tls, 30_000);
```

After `setSignerKey`, convenience methods such as `putContainer`, `containerList`, and `prepareObjectPut` sign requests automatically.

## Signer API

For custom signing (hardware wallet, remote signer), use `*WithSigner` variants:

```zig
const signer = sdk.user_signer.Signer.fromKeyPair(kp);
const epoch = try client.networkInfoWithSigner(signer);
const cid = try client.putContainerWithSigner(signer, container);
```

## Container signatures

Container PUT requires a signature over the marshaled container body:

```zig
const sig = try sdk.container_init.signContainer(allocator, &secret, container);
// passed into putContainer / toPutRequestBody internally
```

Delete and some maintenance operations use `signContainerID` over the 32-byte container ID.

## Sessions

Object mutations in a container often need a **object session** (v2) bound to the current epoch:

```zig
const epoch = try client.networkInfo();
const session = try client.sessionCreate(owner, epoch + 10);
defer allocator.free(session.session_key);

const writer = try client.prepareObjectPut(
    cid, owner, payload, "file.txt",
    session, epoch, epoch + 10, epoch,
);
```

See [Objects](objects.md) for streaming put/get with sessions.

## WalletConnect

The SDK includes WalletConnect pairing helpers under `sdk.walletconnect` for delegated signing flows. Unit tests use a mock relay in `src/walletconnect/mock_relay.zig`.
