# Cloud KMS adapters

The adapters in [cloud-kms.mjs](cloud-kms.mjs) implement the trusted asynchronous port for [field envelope encryption](../../reference/field-encryption.README.md#trusted-asynchronous-kms-port). They call the official provider SDK interfaces through injected startup clients. The reference itself uses Node.js built-ins. Add and review the selected vendor SDK and its lockfile in the deploying application.

## Resource and context binding

Configure the port at startup with records in the following shape. The application must authorize the row and field first and select the configured key ID from the trusted tenant policy.

```javascript
const keys = [{
  keyId: 'tenant-a-fields',
  keyVersion: 'epoch-2026-11',
  resource: trustedVersionedResource,
  write: true,
}];
```

An application alias may have retained read versions and at most one write version. A record with `write: false` or omitted is read-only. Keep version labels immutable across deployments. A different alias, an unknown retained version, or a malformed provider result fails closed. Import aliases from the application configuration. The stored envelope supplies an alias and a version to check against that table. The adapter constructs provider calls exclusively from configured resources.

For each operation, the adapter binds the provider, configured resource, application alias, version and existing field-context digest into a domain-separated SHA-256 digest. AWS uses that digest in its encryption context, GCP and Azure use it as additional authenticated data. The digest is correlatable and should be treated as operational metadata. Keep raw tenant, row and field identifiers out of provider audit context and keep SDK request and response bodies out of logs.

The SDK trust boundary expects binary `Uint8Array` results. The adapter bounds sizes and clears the plaintext DEK views it owns where possible. Returned DEK buffers are handed to the trusted caller under the existing KMS port contract. Plan for additional copies in the JavaScript VM, vendor SDK and network layer. Use owned results from the provider client and keep identity, provider calls and plaintext in the protected process.

## AWS KMS in an EKS workload

With a configured IAM role for the service account, use the SDK v3 web identity credential provider and the actual AWS KMS client. Bind the role trust to the cluster issuer, token audience and assigned service-account subject. Configure the SDK region for the chosen key ARN and scope the key policy and IAM permission to the workload's symmetric key. The adapter uses `kms:GenerateDataKey` for writes and `kms:Decrypt` for reads. [AWS SDK credential providers](https://docs.aws.amazon.com/sdk-for-javascript/v3/developer-guide/migrate-credential-providers.html)

```javascript
import { KMSClient, GenerateDataKeyCommand, DecryptCommand } from '@aws-sdk/client-kms';
import { fromTokenFile } from '@aws-sdk/credential-providers';
import { createAwsKmsPort } from './cloud-kms.mjs';

const kms = createAwsKmsPort({
  keys,
  client: new KMSClient({ region: deploymentRegion, credentials: fromTokenFile(), maxAttempts: 1 }),
  GenerateDataKeyCommand,
  DecryptCommand,
});
```

Set each `resource` to the immutable symmetric key ARN. The adapter checks the returned ARN and passes the expected ARN on decrypt. The application's version label identifies its configured key generation. AWS controls automatic key-material rotation within an ARN and selects its retained material on decrypt. To remove a generation from the application's permitted key set, use a distinct ARN for the successor and retain the old mapping only through the migration and backup retention window. [AWS GenerateDataKey](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html) · [AWS Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html) · [AWS encryption context](https://docs.aws.amazon.com/kms/latest/developerguide/encrypt_context.html)

## Google Cloud KMS with workload identity

On GKE, configure Workload Identity Federation and authorize the workload principal for the exact CryptoKey. Use Application Default Credentials supplied by the workload. Preserve the approved identity configuration and exclude personal credentials and service account key files from the workload image. [GKE Workload Identity Federation](https://docs.cloud.google.com/kubernetes-engine/docs/concepts/workload-identity) · [Application Default Credentials](https://docs.cloud.google.com/docs/authentication/application-default-credentials)

```javascript
import { KeyManagementServiceClient } from '@google-cloud/kms';
import { createGcpKmsPort } from './cloud-kms.mjs';

const kms = createGcpKmsPort({ keys, client: new KeyManagementServiceClient() });
```

Use a fully qualified `projects/.../locations/.../keyRings/.../cryptoKeys/.../cryptoKeyVersions/...` resource per record. The adapter generates a local DEK, encrypts with the fixed CryptoKeyVersion and checks the returned version and checksum acknowledgments. On decrypt, the API accepts the parent CryptoKey and chooses the provider version from the ciphertext. The port enforces the configured application version via its allowlist and authenticated wrapping context. If you need the service to independently prevent use of a retired version, disable the retired provider version after migration and recovery validation. Grant only the appropriate encrypt and decrypt operations on the intended key. Use the SDK transport with binary responses and verify its deadline settings. [Cloud KMS RPC reference](https://docs.cloud.google.com/kms/docs/reference/rpc/google.cloud.kms.v1) · [Cloud KMS integrity guidelines](https://docs.cloud.google.com/kms/docs/data-integrity-guidelines)

## Azure Key Vault Managed HSM with Microsoft Entra Workload ID

The Azure adapter uses A256GCM on a symmetric 256-bit key in Azure Key Vault Managed HSM. Configure an Entra federated identity for the workload and minimum data-plane permissions to encrypt and decrypt the exact key. The application version maps to a full versioned public-cloud HSM key URL such as `https://example.managedhsm.azure.net/keys/fields/<version>`. The adapter checks the SDK's returned key ID and algorithm. It stores the server-generated 12-byte IV, 16-byte tag and 32-byte ciphertext in that order and supplies native AAD to both SDK calls. [Managed HSM key algorithms](https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/about-keys-details) · [JavaScript CryptographyClient](https://learn.microsoft.com/en-us/javascript/api/@azure/keyvault-keys/cryptographyclient) · [AKS Workload ID](https://learn.microsoft.com/en-us/azure/aks/workload-identity-overview)

```javascript
import { WorkloadIdentityCredential } from '@azure/identity';
import { CryptographyClient } from '@azure/keyvault-keys';
import { createAzureKmsPort } from './cloud-kms.mjs';

const kms = createAzureKmsPort({
  keys,
  CryptographyClient,
  credential: new WorkloadIdentityCredential(),
});
```

## Rollout, rotation and failure

1. Provision the key and workload identity through the approved deployment. Bind grants to the exact resources and separate writer, reader and administrator identities where operationally possible.
2. Confirm egress, TLS, authentication source, SDK retry and deadline behavior and access to a disposable key. The adapters use the supplied clients and provider-specific timeout options. Verify those options against the selected SDK transport. Treat provider rejection, timeout and unknown outcomes as failures and reconcile application writes before retrying.
3. Introduce the new write version, preserve approved old read entries, and verify round trips for the old and new revisions. Migrate with the existing authorized, conditional field replacement flow. Keep backups and old-key recovery aligned with the rotation plan.
4. After verifying migration and backup recovery, retire the old mapping and revoke provider access under the reviewed change. Envelopes under an inaccessible key require restoration of authorized key access.

Use `node --test enterprise/cloud-kms/cloud-kms.test.mjs` from the repository root. The tests use synthetic SDK responses and real local authenticated encryption to exercise request shape, scope, context mismatch, key rotation and fail-closed responses. Live SDK and cloud IAM configuration require separate deployment validation.
