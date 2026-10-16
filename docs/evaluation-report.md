# Comparative Evaluation Research Report: Network Baseline vs. Cross-Layer Detection

## 1. Executive Summary
This report documents the empirical comparison between two cybersecurity detection architectures for AWS cloud infrastructures:
- **Detector A (Network Baseline)**: Analyzes VPC Flow Logs against approved communication policies (`NET-BL-001`).
- **Detector B (Cross-Layer Correlator)**: Evaluates AWS CloudTrail administrative security group ingress rule changes in temporal and topological conjunction with subsequent accepted VPC flows (`CORR-CROSS-001`).

Evaluation artifacts and machine-readable metrics are persisted in [`results/evaluation_report.json`](file:///c:/Users/bitup/OneDrive/Desktop/cloud-attack-path-detection/results/evaluation_report.json).

---

## 2. Evaluation Methodology & Metric Definitions

### Positive Class & Denominator Definitions
1. **Policy-Violation Detection**:
   - **Positive Class**: Any accepted network flow violating the approved communication policy ($N_{pos} = 6$).
   - **Negative Class**: Normal approved traffic, maintenance exceptions, and non-violating administrative actions ($N_{neg} = 6$).
   - **Precision**: $\frac{\text{TP}}{\text{TP} + \text{FP}}$ (proportion of flagged alerts that represent genuine policy violations).
   - **Recall**: $\frac{\text{TP}}{\text{TP} + \text{FN}}$ (proportion of genuine policy violations detected).
   - **False Positive Rate (FPR)**: $\frac{\text{FP}}{\text{FP} + \text{TN}}$.
2. **Cross-Layer Relationship Attribution**:
   - **Positive Class**: A causal triplet $(\text{CloudTrail Event ID}, \, \text{VPC Flow Event ID}, \, \text{Resource ID})$ where an administrative ingress authorization directly enabled the observed flow ($N_{expected} = 2$).
   - **Precision**: $\frac{\text{TP}_{\text{rel}}}{\text{Predicted}_{\text{rel}}}$ if $\text{Predicted}_{\text{rel}} > 0$; otherwise `None` (undefined).
   - **Recall**: $\frac{\text{TP}_{\text{rel}}}{\text{Expected}_{\text{rel}}}$ if $\text{Expected}_{\text{rel}} > 0$; otherwise `None` (undefined).
   - **F1 Score**: $\frac{2 \cdot P \cdot R}{P + R}$ if $P, R \neq \text{None}$; otherwise `None`.
   - **Convention for Unsupported Detectors**: When a detector does not predict relationships (such as the Network Baseline detector), relationship precision and F1 are documented as `not_supported` (JSON `null`), rather than setting precision to $0.0$.
3. **Monotonic Timing Protocol**:
   - Monotonic high-resolution clock (`time.perf_counter()`) isolating algorithmic detection latency from disk I/O and telemetry ingestion.

---

## 3. Benchmark Dataset Composition

Standard benchmark consisting of 12 controlled scenarios (19 events total):
- **Development Subset** (8 scenarios: `sc-01` to `sc-08`): Core positive and negative functional test scenarios (normal traffic, maintenance windows, matching ingress changes, non-traffic changes, unrelated events, failed API calls, pre-existing unapproved flows, window expiry).
- **Held-Out Subset** (4 scenarios: `sc-09` to `sc-12`): Edge cases (ambiguous IP-to-resource mappings, out-of-order event arrivals, missing event attributes, and rules revoked prior to flow).

Ground-truth labels and detector input payloads are decoupled into separate files:
- `fixtures/evaluation/development/telemetry_and_config.json`
- `fixtures/evaluation/development/ground_truth.json`
- `fixtures/evaluation/held_out/telemetry_and_config.json`
- `fixtures/evaluation/held_out/ground_truth.json`

---

## 4. Empirical Evaluation Results

### A. Case-Level Policy Violation Detection
| Metric | Detector A: Network Baseline | Detector B: Cross-Layer Correlator | Absolute Delta ($B - A$) |
| :--- | :--- | :--- | :--- |
| **Total Scenarios** | 12 | 12 | 0 |
| **Ground Truth Positive** | 6 | 6 | 0 |
| **Ground Truth Negative** | 6 | 6 | 0 |
| **True Positives (TP)** | 6 | 2 | -4 |
| **False Positives (FP)** | 0 | 0 | 0 |
| **True Negatives (TN)** | 6 | 6 | 0 |
| **False Negatives (FN)** | 0 | 4 | +4 |
| **Policy Violation Precision** | **1.0000** | **1.0000** | **0.0000** |
| **Policy Violation Recall** | **1.0000** | **0.3333** | **-0.6667** |
| **False Positive Rate (FPR)** | **0.0000** | **0.0000** | **0.0000** |

### B. Relationship Attribution & Reconstruction
| Metric | Detector A: Network Baseline | Detector B: Cross-Layer Correlator | Comparative Status |
| :--- | :--- | :--- | :--- |
| **Expected Relationships** | 2 | 2 | Identical ground truth |
| **Predicted Relationships** | 0 | 2 | Baseline predicts 0 links |
| **True Positive Links** | 0 | 2 | Cross-layer matches both |
| **Relationship Precision** | **N/A (`null`)** | **1.0000** | Baseline: `not_supported` |
| **Relationship Recall** | **0.0000** | **1.0000** | Cross-layer: +1.0000 |
| **Relationship F1 Score** | **N/A (`null`)** | **1.0000** | Cross-layer achieves full recovery |
| **Processing Latency** | **0.39 ms** | **0.25 ms** | -0.14 ms |

---

## 5. Research Analysis & Separate Objectives

1. **Why Cross-Layer Recall is 0.3333 on Generic Policy Violations**:
   - The Network Baseline detector monitors all traffic against static rules; any accepted flow without an approval rule triggers an alert (yielding 1.0000 recall on unapproved flows).
   - In contrast, the Cross-Layer Correlator is **not** a general policy scanner; it is a causal correlator that specifically fires when a security group change enabled subsequent traffic.
   - For scenarios where unapproved traffic occurred without any CloudTrail event (e.g. pre-existing rules or external scans), the Cross-Layer correlator deliberately remains silent. This demonstrates that cross-layer correlation is a specialized investigative multiplier, not a replacement for network baselining.
2. **Relationship Reconstruction Value**:
   - The Network Baseline detector cannot reconstruct attack paths or identify the responsible IAM administrative action (Relationship Recall = 0.0000, Precision = N/A).
   - The Cross-Layer Correlator successfully reconstructed 100% of causal triplets without any false-positive linkages ($F_1 = 1.0000$).

---

## 6. Threats to Validity & Operational Limitations

1. **Synthetic Telemetry vs. Production AWS Environments**:
   - Telemetry in this benchmark was synthetically generated to test edge cases deterministically. While logical correctness is verified, real-world networks experience packet loss, flow log truncation, and high background noise.
2. **CloudTrail Delivery Latency & Out-of-Order Telemetry**:
   - Real AWS CloudTrail logs typically deliver with a **5 to 15 minute delay**, whereas VPC Flow Logs deliver within 1 to 10 minutes. In production, network flows may arrive *before* the CloudTrail event is delivered to the SIEM. While the offline correlator sorts out-of-order batches deterministically, online real-time stream processing would require sliding buffer windows.
3. **VPC Flow Log Aggregation Windows**:
   - VPC Flow Logs aggregate connection records over 1-minute or 10-minute intervals. The exact packet arrival time within that window is inexact.
4. **Security Group to Security Group (SG-ID) References**:
   - **Update:** SG-to-SG references (AWS `UserIdGroupPairs` and `source_security_group_id`) are now handled in cross-layer correlation and graph construction, validated against timestamped ENI/SG attachments in `ConfigurationHistory`. Remaining limitations (alert-driven edges, reliance on configuration history from Member 1, no transitive expansion, group IDs only) are documented in `docs/sg-to-sg-references.md`. Benchmark scenarios in this report predate this change and remain CIDR-based.
5. **Permitted Reachability vs. Observed Communication**:
   - Graph edges distinguish `permitted_reachability` from `observed_communication`. A configuration change establishing reachability proves that a path was opened, but does not prove that application-layer authentication or compromise occurred.
6. **No Proof of Causation or Exploitation**:
   - A configuration change preceding a flow does not, by itself, prove malicious intent or that the IAM actor was the network adversary.
