# Security-Group-to-Security-Group (SG-to-SG) References

Owner: Member 2 (Detection & Attack-Path Analysis)

AWS security group rules frequently allow traffic *from another security group* instead of a
CIDR block. This document describes how the detection engine handles those rules and where it stops.

## Supported input shapes

| Source | Shape | Notes |
|---|---|---|
| CloudTrail `AuthorizeSecurityGroupIngress` | `ip_permissions[].userIdGroupPairs[].groupId` | Also `UserIdGroupPairs`, `user_id_group_pairs`, and `GroupId` / `group_id` inside each pair |
| Flat normalized event | `details.source_security_group_id` | Also `details.sourceSecurityGroupId` |
| `RevokeSecurityGroupIngress` | Same shapes as above | Revokes only the matching reference |

`ipRanges` and `userIdGroupPairs` in the same permission produce one rule per CIDR and one rule per
referenced group. `SecurityGroupRule.referenced_security_group_id` carries the reference; for
such rules `cidr_ipv4` is `None`.

## Correlation behavior (`CrossLayerCorrelator`)

A reference rule enables an accepted flow only when **all** existing checks pass (API success,
time window, protocol, port, target ENI and attached SG, not revoked) **and**:

1. `configuration_history` is provided.
2. The flow's `source_ip` maps to **exactly one** ENI/resource.
3. That ENI had the referenced SG attached **at flow time** (`attached_at <= t < detached_at`).

If any of these cannot be established, no alert is produced (conservative: no assumption of
membership). In particular:

- A reference is **never** treated as a `0.0.0.0/0` wildcard.
- Malformed references (empty, non-string, or missing group ID) yield **no rule**, not a wildcard.
- A reference to an SG that no known ENI carries yields no alert.
- Revocation is reference-aware: revoking `sg-a` does not revoke a rule for `sg-b`, and revoking a
  CIDR rule does not revoke an SG-reference rule (and vice versa).

### Alert additions

`DetectionAlert.details` gains (existing keys unchanged):

- `sg_references`: list of `{referenced_security_group_id, security_group_id, protocol, from_port, to_port, source_resource_ids}` (sorted, deterministic). Empty for CIDR-only alerts.
- `referenced_security_group_ids`: sorted list of referenced SG IDs.

`related_resource_ids` still lists only the affected (target) ENIs; source ENIs are in
`sg_references[].source_resource_ids`.

## Graph representation (`GraphBuilder`)

For each verified reference on an alert:

```
referenced SG  --permitted_reachability (permitted)-->  protected SG
```

- Direction is referenced (source) SG → protected SG.
- `evidence_event_ids` = the CloudTrail authorization event; `valid_time` = its timestamp.
- `protocol` is set; `port` is set only for a single-port rule, otherwise `None` with
  `details.from_port` / `details.to_port` preserved.
- `details.source_resource_ids` lists the ENIs that justified the reference.

Together with existing edges this makes the chain traversable:

```
eni-app --(attachment)--> sg-app --(sg reference)--> sg-db --(inferred_sequence)--> eni-db
```

Path results containing the inferred edge are flagged `contains_inferred_relationships`.
Alerts with missing or malformed `sg_references` add no SG-to-SG edge and no placeholder nodes.

## Limitations

- **Alert-driven graph edges.** SG-to-SG edges are created only for references that were validated
  by a correlated flow. A reference that was authorized but never exercised in the window does not
  appear in the graph.
- **Requires configuration history.** Membership of the referenced SG comes from
  `ConfigurationHistory` (Member 1). Missing or stale snapshots mean no detection, not a guess.
- **Source IP must map to one ENI.** Flow logs record IPs; shared/ambiguous IPs (NAT, secondary
  IPs not in `eni_to_ip_map`) are skipped.
- **Same-VPC / same-account assumptions.** `userId` and `vpcId` in a group pair are not
  evaluated; peered-VPC and cross-account references are matched on group ID only.
- **Group IDs only.** References by group *name* (EC2-Classic / default-VPC style) are not
  resolved.
- **Transitive nesting is not expanded.** The referenced SG is matched against SGs directly
  attached to the source ENI; SGs referencing SGs referencing SGs are not walked.
- **IPv6 and prefix-list sources** are out of scope for this change.
- **Revocation matching** keeps the existing coarse behavior for ports (a `None` port in the
  revoke matches any), now additionally scoped by reference identity.
- As before, a correlated finding establishes enabled reachability, **not** compromise or the
  IAM actor's responsibility for the traffic.
