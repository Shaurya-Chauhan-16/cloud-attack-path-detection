# Cloud-Network Attack Path and Lateral Movement Detection

Final-year cybersecurity research project evaluating network-only baseline detection versus cross-layer telemetry correlation (AWS CloudTrail administrative events, VPC Flow Logs, and configuration snapshots).

## Team Member Responsibilities
- **Amaanali Motiwala**: AWS telemetry collectors, normalization, resource mapping, configuration snapshots, and storage.
- **Vedant Patel**: Policy engine, network detection, cross-layer correlation, temporal graph engine (NetworkX), priority scoring, and evaluation metrics.
- **Shaurya Chauhan**: FastAPI backend service, React dashboard, timelines, evidence views, and reports.

---

## Configuration (`data/local/lab_config.json`)

Ensure `data/local/lab_config.json` exists with the required AWS settings:

```json
{
  "profile": "attackpath-collector",
  "region": "ap-south-1",
  "log_group": "/attackpath/vpc-flow",
  "trail_bucket": "cloud-bucket-sav",
  "vpc_id": "vpc-01016869033a18a15",
  "sqs_queue_url": "https://sqs.ap-south-1.amazonaws.com/123456789012/attackpath-telemetry-queue"
}
```

### Config Keys:
- `profile`: AWS CLI credentials profile name (configured in `~/.aws/credentials`).
- `region`: AWS region (e.g., `ap-south-1`).
- `log_group`: CloudWatch Log Group name where VPC Flow Logs are delivered.
- `trail_bucket`: S3 bucket name storing AWS CloudTrail `.json.gz` log archives.
- `vpc_id`: Target VPC identifier.
- `sqs_queue_url`: Amazon SQS queue receiving S3 `s3:ObjectCreated:*` event notifications for new CloudTrail log files.

### Environment Variables (Optional):
- `MAX_ANALYSIS_EVENTS`: Maximum events per telemetry source loaded for analysis (default: `100000`).
- `ALERT_REFRESH_INTERVAL_SECONDS`: Minimum interval between automatic background re-analyses when new events are ingested (default: `60`).

---

## How to Run the Project

### 1. Activate Python Virtual Environment
Open PowerShell from the project root:
```powershell
.\.venv\Scripts\Activate.ps1
```

### 2. Telemetry Collection

#### Option A: One-Shot Ingestion
Pull historical CloudTrail objects and VPC Flow Logs into SQLite (`data/local/events.db`):
```powershell
python src/ingestion/collectors/run_collect.py
```

#### Option B: Real-Time Telemetry Streaming Worker
Run the decoupled live consumer (long-polls SQS for S3 CloudTrail events and tails CloudWatch VPC Flow Logs with overlap & cursor persistence):
```powershell
python -m src.ingestion.collectors.stream_worker
```

### 3. Run FastAPI Backend
Start the REST API service (port 8000):
```powershell
uvicorn src.api.main:app --reload --port 8000
```
- Interactive Swagger docs: [http://localhost:8000/docs](http://localhost:8000/docs)
- Health check: [http://localhost:8000/health](http://localhost:8000/health)
- Alerts: [http://localhost:8000/alerts](http://localhost:8000/alerts)

### 4. Run React Dashboard (Frontend)
In a separate terminal:
```powershell
cd src/frontend
npm install
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) (or the Vite dev URL shown in the terminal).

### 5. Run Verification & Tests
- **Diagnostic Helper**:
  ```powershell
  python debug_alerts.py
  ```
- **Run Pytest Suite**:
  ```powershell
  python -m pytest -q
  ```
- **Build Frontend**:
  ```powershell
  cd src/frontend
  npm run build
  ```

---

## Telemetry Delivery Limitations (Near Real-Time)

Because this research system correlates real AWS cloud telemetry:
- **CloudTrail Latency**: AWS CloudTrail flushes log files to Amazon S3 approximately every **5 to 15 minutes**. Events will only arrive at the SQS queue and collector once AWS delivers the log archive to S3.
- **VPC Flow Logs Latency**: AWS VPC Flow Logs are aggregated in CloudWatch in **1 to 10 minute windows** (depending on the configured aggregation interval).
- **Dashboard Synchronization**: The dashboard and detection pipeline operate in **near real-time** rather than zero-latency real-time, bound by AWS's native log publication intervals.
