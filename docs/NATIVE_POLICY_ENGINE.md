# Native policy engine migration

## Decision

Netspoc-Web will evolve from a viewer for exported Netspoc data into the system
of record for network security policy. The external Netspoc compiler is a legacy
input during migration and is not part of the target architecture.

This is a replacement of a policy compiler and deployment system, not a UI-only
change. Removing Netspoc before the native engine can prove equivalent policy
semantics could silently broaden firewall access. Migration therefore uses the
phases and acceptance gates below.

## Target architecture

1. **Policy API and database** own tenants, users, roles, owners, networks,
   address objects, services, rules, devices, VDOMs and ADOMs.
2. **Validator** rejects overlapping or invalid networks, dangling references,
   ambiguous ownership, invalid protocols/ports, cycles and unsupported vendor
   features before a revision can be published.
3. **Immutable revision store** records every published policy, author, review,
   timestamp and content hash. Drafts are mutable; published revisions are not.
4. **Authorization service** derives access from application roles rather than
   generated `email` files. At minimum it supports administrator, policy editor,
   reviewer, deployer and read-only viewer, scoped to responsibility areas.
5. **Vendor-neutral intermediate representation (IR)** expands groups and
   inherited networks, resolves rules and NAT, and produces deterministic input
   for device drivers.
6. **FortiOS driver** renders addresses, address groups, services, policies and
   NAT per VDOM and detects unsupported constructs.
7. **FortiManager driver** maps responsibility/device scope to ADOMs, creates a
   workspace transaction, installs a preview, retrieves task results and rolls
   back on failure.
8. **Reconciliation service** imports current FortiGate/FortiManager state,
   normalizes it into the IR and reports drift without treating imported state
   as an automatically approved policy.
9. **Deployment workflow** requires validation, rendered diff, approval,
   idempotent installation, post-deployment verification and an auditable
   rollback revision.

## Minimum data model

All records have a stable UUID, tenant ID, revision metadata and optimistic
locking version.

```text
ResponsibilityArea { id, name, description }
RoleBinding        { principal, role, responsibility_area_ids }
Network            { id, name, cidrs[], responsibility_area_id, parent_id? }
AddressObject      { id, name, addresses[], responsibility_area_id }
ServiceObject      { id, name, protocol, source_ports[], destination_ports[] }
Rule               { id, name, sources[], destinations[], services[], action,
                     schedule?, logging, nat?, responsibility_area_id }
Device             { id, name, kind, endpoint, credential_ref, vdoms[], adom? }
PolicyRevision     { id, state, author, reviewer?, created_at, content_hash }
Deployment         { id, revision_id, device_id, state, diff, task_id?, log }
```

Credentials are references to a secret manager or container secret and must
never be persisted in policy revisions.

## Delivery phases and exit criteria

### 1. Native authoring

- Database migrations and transactional repository.
- CRUD API and web forms for responsibility areas, role bindings, networks,
  objects, services and rules.
- Draft/publish workflow, schema validation and audit log.
- Importer for the existing exported Netspoc policy to seed the database once.

**Exit:** a user can reproduce an existing policy in the UI, publish an
immutable revision and retrieve identical content after restart.

### 2. Compilation and equivalence

- Vendor-neutral IR and deterministic FortiOS renderer.
- Golden tests for IPv4/IPv6, groups, TCP/UDP/ICMP, deny/permit, NAT, logging,
  VDOM boundaries, naming limits and object deduplication.
- Differential tests compare native output/semantics with representative
  production policies.

**Exit:** every supported construct has golden coverage; unsupported constructs
block publication; reviewed production samples show no unintended access.

### 3. Fortinet deployment

- FortiGate preview, install, verify, drift and rollback.
- FortiManager ADOM/workspace lock, policy package update, install preview,
  asynchronous task tracking, unlock and rollback.
- Least-privilege API profiles and encrypted secret integration.

**Exit:** repeat deployments are idempotent, failed installs roll back, and all
actions are attributable to a user and revision.

### 4. Cutover and Netspoc removal

- Run native compilation in shadow mode.
- Freeze Netspoc authoring, perform a final import and reconcile both systems.
- Deploy an approved native revision to a canary, then production.
- Remove `netspoc_data`, export readers, `current` symlink handling and Netspoc
  tooling only after rollback rehearsal and an agreed retention period.

**Exit:** no runtime, build, test or operational dependency on Netspoc remains.

## Non-goals for the first phase

- Directly installing a mutable draft.
- Silently ignoring unsupported FortiOS/FortiManager features.
- Storing API tokens or passwords in the policy database.
- Editing generated FortiGate CLI snippets as the source of truth.
- Removing the legacy reader before native equivalence and cutover gates pass.

## Required product decisions

Before implementing the database schema, agree on:

- PostgreSQL versus another transactional database (PostgreSQL is recommended).
- Required FortiOS and FortiManager versions and whether FortiManager is the
  mandatory deployment path when a device is managed by it.
- Approval rule (for example four-eyes), emergency change process and retention.
- Supported initial semantics: IPv4/IPv6, NAT variants, schedules, identity,
  Internet services, security profiles, zones, SD-WAN and dynamic addresses.
- Tenant isolation and identity provider/LDAP/OIDC requirements.

Until those decisions and phases are complete, the existing Netspoc export path
is legacy compatibility—not the target design.
