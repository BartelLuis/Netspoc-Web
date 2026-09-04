# FortiGate policy naming

Policy names are entered manually in the rule editor. The backend trims and
validates `policy_name` when saving a draft, staging a revision and publishing
it; it does not replace a submitted name with a generated one.

A name is required, must be unique within the policy and may contain at most 35
ASCII letters, digits, underscores or hyphens. Server-owned stable rule IDs are
still preserved across edits. Copying a rule creates a new stable ID, while
moving it keeps the existing ID.

Legacy policy documents may still contain tenants, target contexts, naming
catalog data, lifecycle fields, comments and naming versions. These fields are
kept unchanged for compatibility but are intentionally hidden from the normal
administration UI and are not required for new rules.

`POST /backend6/admin/policy-name-preview` remains as a compatibility endpoint
for older clients. It validates manual names and returns preserved server-owned
identity metadata; it no longer derives names.
