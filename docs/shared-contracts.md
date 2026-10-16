# Cross-Layer Correlation Specification & Contracts

## 1. Overview
The Cross-Layer Correlation Engine correlates AWS CloudTrail administrative security group ingress rule modifications with subsequent accepted VPC Flow Logs traffic.

## 2. Shared Contracts & Inputs

### Member 1 (Inputs)
Member 1 provides:
1. **CloudTrail Events**: Normalized as `BaseTelemetryEvent` with:
   - `source = "cloudtrail"`
   - `action = "AuthorizeSecurityGroupIngress"` or `"RevokeSecurityGroupIngress"`
   - `actor`: IAM User / Role ARN
   - `details`: Security group rule permissions (`ipPermissions` list with `ipRanges` and/or `userIdGroupPairs`, or flat `protocol`, `from_port`, `to_port`, `cidr_ipv4` / `source_security_group_id`), error status (`errorCode`, `errorMessage`).
2. **VPC Flow Log Events**: Normalized as `BaseTelemetryEvent` with:
   - `source = "vpc_flow"`
   - `action = "ACCEPT"`
   - `resource_id`: Target ENI ID (`eni-xxxx`)
   - `source_ip`, `destination_ip`, `destination_port`, and `details["protocol"]`
3. **Configuration History**: `ConfigurationHistory` with:
   - `attachments`: List of `SecurityGroupAttachment(resource_id, security_group_id, attached_at, detached_at)`
   - `eni_to_ip_map`: IP-to-ENI mapping snapshots.

### Member 3 (Output Consumption)
Member 3 consumes:
- `List[DetectionAlert]` with:
  - `alert_id`: Unique identifier
  - `rule_id`: `"CORR-CROSS-001"`
  - `rule_version`: `"1.0.0"`
  - `priority`: `"high"`
  - `explanation`: Human-readable summary detailing administrative actor, matching flow, time delta, and explicit uncertainty disclaimers.
  - `evidence_event_ids`: Both CloudTrail and VPC Flow Log IDs.
  - `related_resource_ids`: Affected ENIs and security group targets.
  - `details`: Metadata dictionary for UI timelines and graph building. For SG-to-SG rules it also carries `sg_references` and `referenced_security_group_ids` (see `docs/sg-to-sg-references.md`).

## 3. Assumptions & Limitations
- **Preservation of Uncertainty**: Correlated flows indicate enabled reachability. They do NOT confirm application-layer compromise or malicious intent.
- **Actor Disassociation**: The IAM principal who authorized the rule is explicitly kept distinct from the network entity generating the network traffic.
- **Offline / Batch Processing**: Batch processing sorts deterministically by UTC timestamp and deduplicates by `event_id`.
