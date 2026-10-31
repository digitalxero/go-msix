# MSIX audit fixes (#6–#16)

These fixes validate direct public-builder input before successful output and
preserve each reported failure as a separate regression. They do not change nFPM.

| Ticket | Regression evidence |
| --- | --- |
| #6 payload/footprint collisions | `TestAuditPayloadCollisions`: all four adders, both ancestor orders, footprint aliases; canonical CodeIntegrity catalog control |
| #7 Windows payload names | `TestAuditPayloadPaths`: traversal, UNC/drive forms, device names, trailing characters, controls; single-root-slash and Unicode controls |
| #8 core manifest and payload closure | `TestAuditCoreManifest`: direct identity/version/architecture/property/application failures, missing exe/image; qualified assets and activation-only controls |
| #9 registration identities | `TestAuditRegistrationIdentities`: Application IDs, protocols across extension versions, SCM service case, shortcut separators/constants; distinct controls |
| #10 signing consistency | `TestAuditSigningCredentials`, `TestAuditSigningPublisherFormatting`: RSA/ECDSA, explicit/PFX, exact publisher and RawSubject ordering/quoting |
| #11 protocol display name | `TestAuditManifestSerialization/protocol`: decoded UAP child and escaped value, logo retained |
| #12 shortcut fields | `TestAuditManifestSerialization/shortcut`: decoded arguments including legal whitespace and desktop10 display-name attribute |
| #13 execution property | `TestAuditManifestSerialization/allow_execution_*`: explicit true/false and omission |
| #14 resource namespace | `TestAuditManifestSerialization/resource_*`: Scale/DXFeatureLevel independently and in separate resource entries without apps |
| #15 XML characters | `TestAuditXMLCharacters`: invalid UTF-8 and forbidden controls in properties, publisher, extension; Unicode/markup controls |
| #16 source consistency | `TestAuditChangingSources`: empty/growing/shrinking/same-size/stable sources, unsigned/signed; full ZIP reads and one read per source |

Public API regressions produced meaningful failures before their implementation
fixes. The first-red logs are retained in `/tmp/go-msix-fix-evidence/first-red.txt`
and `signing-first-red.txt`. Original audit evidence remains untouched in
`/tmp/nfpm-1135-msix-deep-audit-vr9oh9wo`.

## Compatibility boundaries

Single leading payload slashes remain normalized; UNC/drive/traversal input is
rejected rather than renamed. Casing remains authored. Application IDs use schema
case-sensitive uniqueness, service/path ownership uses Windows uppercase identity,
and publisher matching is exact. `Programs` and `Common Programs` shortcuts remain
separate destinations; case/separator aliases of each constant conflict.

Core image references accept named/combined MRT qualifiers in filenames and folders;
bare language qualifiers are supported in folders. Resource strings in metadata
are preserved. An omitted application executable remains legal for activation-only
apps. This API does not expose sparse-package `AllowExternalContent` authoring;
validation does not introduce an unsupported external-location mode. CodeIntegrity
catalogs retain the explicit canonical `AppxMetadata/CodeIntegrity.cat` path.

Every Build snapshots its source read with bounded memory. Empty Store parts use
an immutable empty source; nonempty Store/Deflate parts use private spill files.
Catalog hashes, block maps, signature digest replays and output use those bytes.
The documented one-shot-reader cleanup contract remains separate.

`WithAllowExecution` requires Windows 10 1803+. Shortcut display names now use
`desktop10:DisplayName`; that label requires a Windows version supporting the
namespace. Callers targeting older systems should not depend on the label being
honored. Ordinary unset fields remain omitted.

The historical unsigned byte-equality test keeps its original hashes and payload
inventory. Its deliberately incomplete old manifest now exercises the private
container writer; public-builder fixtures include their referenced payloads.

## Native verification

`TestAuditPublisherWindows` compares the signed public API against native
`CertNameToStrW(CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG)`.
`TestAuditSDKWindows` runs MakeAppx positive controls and independently mutated
negative manifests for protocol, shortcut, execution, and resource attributes.
`TestAuditDeploymentWindows` uses a real executable and a throwaway trusted chain
to verify signature/deployment, protocol activation, shortcut launch arguments,
SCM service start/stop/removal, and non-executable asset behavior. It owns unique
package/service/shortcut names and cleans up its certificates and packages.

The dedicated Windows audit CI job requires the SDK and enables deployment tests;
missing tools and failed checks are blockers. Cross-compilation, XML checks and
skipped tests are not native trust/deployment acceptance. Local fleet capability
probing on this handoff timed out connecting to `dj-window.taild916a5.ts.net:22`.
Hosted Windows results are recorded in the PR before merge.

Native SDK controls established two additional core constraints: resource packages
omit ProcessorArchitecture, and Scale/DXFeatureLevel are mutually exclusive on a
single Resource element. Combined positive coverage uses separate entries. First-red
public receipts for both constraints are retained alongside the original regressions.
MakeAppx mapping authoring ignores supplied block-map/signature footprints; its
controls assert omission/regeneration. The library deliberately rejects ownership
conflicts instead of silently discarding caller input.

Native service validation also requires the enclosing windows.service extension
to declare Executable and EntryPoint explicitly. The renderer now forwards the
owning application's fields for desktop6/desktop7 services, and validates that
they exist. This prerequisite was found while establishing native #9 coverage;
`TestAuditServiceExecutableContext` retains its separate first-red receipt.
A resource package may use only one qualifier type; the combined namespace
positive uses a framework package with no applications and separate resource entries.
