# Anomaly Detection Engine

This project is a real-time network anomaly detection system that monitors incoming HTTP traffic to a Nginx reverse proxy, detects abnormal request patterns from individual IP addresses, and automatically blocks offending IPs using iptables firewall rules. It runs entirely in Docker, requires no external database, and exposes a live dashboard showing traffic metrics, banned IPs, and system resource usage. When an anomaly is detected, a Slack alert is sent with full details about the offending IP, the trigger condition, and the applied ban duration.

---

## Language Choice

Python was chosen for this project for several reasons. Python ships with a rich standard library that covers most of what this daemon needs: `collections.deque` for sliding windows, `statistics` for mean and standard deviation, `threading` for background workers, and `http.server` for the dashboard. The only third-party dependencies are `pyyaml` for config parsing, `requests` for Slack notifications, and `psutil` for system metrics. Python is also easy to read and audit, which matters for a security-adjacent tool where the logic must be transparent and verifiable. Performance is not a bottleneck here because the detection loop processes one log line at a time at the speed Nginx writes them, which is far below Python's throughput ceiling for this kind of I/O-bound work.

---

## Architecture

The system is composed of three Docker services connected on a shared bridge network:

1. **Nginx** receives all incoming HTTP requests on port 80 and proxies them to the Nextcloud container. It writes every request as a JSON object to a shared Docker volume at `/var/log/nginx/hng-access.log`. Each log entry contains the source IP, timestamp, HTTP method, path, response status, and response size.

2. **Nextcloud** is the protected application. It sits behind Nginx and never receives direct external traffic.

3. **Detector** mounts the Nginx log volume in read-only mode and tails the log file as a stream. For every new log entry it maintains sliding windows per IP, computes anomaly scores against a rolling baseline, and takes action when thresholds are exceeded. The detector container is given the `NET_ADMIN` capability so it can issue iptables commands that affect the host network.

The full flow for a single request is:

```
Client request
  -> Nginx (logs JSON entry to shared volume)
  -> Detector reads new log line
  -> Updates sliding windows and baseline
  -> Runs anomaly checks
  -> If anomaly: iptables DROP rule added, Slack alert sent, audit log written
  -> Dashboard reflects updated state within 3 seconds
```

---

## How the Sliding Window Works

Each IP address gets its own `collections.deque` that stores the Unix timestamps of every request that IP has made. A single global deque stores timestamps for all requests regardless of source. Neither deque has a fixed size limit; instead, stale entries are evicted on every log entry processed.

When a new log entry arrives, the current time (`time.time()`) is appended to both the IP-specific deque and the global deque. A cutoff value is then calculated as `now - 60`, representing the start of the 60-second window. Any timestamp at the left of the deque that is older than the cutoff is removed with `popleft()` until the oldest remaining entry is within the window. Because timestamps are always appended in chronological order, this eviction is always O(k) where k is the number of expired entries, not O(n) over the whole deque.

The length of the deque after eviction is the IP's request rate for the current 60-second window. This value is what gets compared against the baseline.

The same structure is used to track 4xx and 5xx error responses per IP, using a separate error deque per IP and one global error deque.

---

## How the Baseline Works

The baseline answers the question: what is the normal request rate on this system right now? It maintains two data structures simultaneously.

The first is a `collections.deque` with `maxlen=1800`. Each slot holds the total request count for one second. Because the deque is capped at 1800 entries, it automatically evicts counts older than 30 minutes when new ones are appended. This is the rolling window.

The second is a dictionary keyed by hour (0 through 23), where each value is a list of per-second counts recorded during that hour. This captures the natural traffic rhythm of the day: traffic at 2am behaves differently from traffic at 2pm. Each hourly list is trimmed to a maximum of 3600 entries (one hour of per-second samples) to bound memory usage.

Every time a new count is added via `add_count()`, the baseline checks whether 60 seconds have elapsed since the last recalculation. If so, it recomputes the mean and standard deviation using Python's `statistics.mean` and `statistics.stdev`. The data source for recalculation is chosen as follows: if the current hour's slot has more than 60 data points, it uses that slot because it reflects the traffic pattern for this specific time of day. Otherwise it falls back to the full 30-minute rolling window.

To prevent division by zero in the z-score formula, both mean and stddev are floored at 1.0 regardless of what the calculation produces.

---

## How Detection Works

For every log entry processed, the detector computes a z-score for the source IP:

```
z_score = (ip_rate - mean) / stddev
```

Where `ip_rate` is the number of requests from that IP in the last 60 seconds, and `mean` and `stddev` come from the baseline.

An IP is flagged as anomalous if either of two conditions is true:

- The z-score exceeds 3.0. This means the IP's request rate is more than three standard deviations above the baseline mean, which is statistically unusual under normal traffic distributions.
- The raw rate exceeds 5 times the baseline mean. This catches burst attackers who ramp up so fast that the standard deviation has not had time to widen to reflect the change.

A third condition modifies the z-score threshold rather than triggering a ban directly. If the proportion of 4xx and 5xx responses from an IP exceeds three times the global error proportion across all traffic, the z-score threshold for that IP is tightened from 3.0 to 2.0. This makes the detector more sensitive to IPs that are not just sending many requests but are also generating a high error rate, which is a common pattern in credential-stuffing and path-scanning attacks.

---

## How iptables Blocking Works

iptables is the Linux kernel's built-in packet filtering firewall. When the detector decides to block an IP, it runs the following command inside the container:

```
iptables -I DOCKER-USER -s <ip> -j DROP
```

The `-I DOCKER-USER` flag inserts the rule at the top of the `DOCKER-USER` chain, which Docker processes before its own forwarding rules, ensuring traffic from a blocked IP is dropped even for containerised services. The `-s <ip>` flag matches packets from the specified source address. The `-j DROP` target silently discards the packet without sending any response to the sender.

The system applies escalating ban durations based on how many times an IP has been banned before:

| Offence number | Ban duration |
|----------------|--------------|
| 1st            | 10 minutes   |
| 2nd            | 30 minutes   |
| 3rd            | 2 hours      |
| 4th and beyond | Permanent    |

A background thread checks every 30 seconds whether any active ban has expired. When a ban expires, the rule is removed with:

```
iptables -D DOCKER-USER -s <ip> -j DROP
```

The IP is then removed from the in-memory ban registry. A Slack alert is sent noting the next ban duration that will apply if the IP re-offends. Permanent bans are never automatically lifted.

---

## Prerequisites

The following must be installed and available on the host machine before deployment:

- **Docker** (version 20.10 or later recommended)
- **Docker Compose** (version 2.x, included with Docker Desktop and recent Docker Engine installs)
- **Python 3.11** (only needed if running the detector outside Docker for development)
- **iptables** (available by default on most Linux distributions; required on the Docker host for `NET_ADMIN` capability to work)

---

## Setup Instructions

Follow these steps on a fresh Ubuntu or Debian VPS:

**1. Install Docker**

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker
```

**2. Clone the repository**

```bash
git clone https://github.com/PrincewillDev/anomaly_detection_engine.git
cd anomaly_detection_engine
```

**3. Configure the Slack webhook**

Open `detector/config.yaml` and replace the placeholder webhook URL with your real Slack incoming webhook URL:

```yaml
slack:
  webhook_url: "https://hooks.slack.com/services/YOUR/REAL/WEBHOOK"
```

If you do not have a Slack webhook, the system will still run; the notifier will print errors to stdout but will not crash.

**4. Build and start all services**

```bash
docker compose up --build -d
```

This command builds the detector image, pulls the Nginx and Nextcloud images if they are not already cached, creates the shared log volume, and starts all three containers in the background.

**5. Verify all containers are running**

```bash
docker compose ps
```

All three services (nginx, nextcloud, detector) should show a status of `Up`.

**6. Tail the detector logs to confirm it is monitoring**

```bash
docker compose logs -f detector
```

You should see the startup message and, once Nginx receives its first request, log lines reflecting traffic processing.

---

## What a Successful Startup Looks Like

After running `docker compose up --build -d`, the expected output from `docker compose ps` is:

```
NAME                          STATUS          PORTS
anomaly_detection_engine-nginx-1       Up              0.0.0.0:80->80/tcp
anomaly_detection_engine-nextcloud-1   Up
anomaly_detection_engine-detector-1    Up
```

Running `docker compose logs detector` should show:

```
Anomaly detection engine started. Monitoring: /var/log/nginx/hng-access.log
Dashboard running on http://0.0.0.0:8080
```

To confirm the dashboard is accessible, open a browser and navigate to `http://monitor.servehttp.com`. You should see a plain HTML page showing uptime, global request rate, baseline mean and stddev, the top 10 source IPs, any currently banned IPs, and CPU and memory usage. The page refreshes automatically every 3 seconds.

To generate test traffic and confirm the detector is processing entries, run:

```bash
curl http://178.105.31.108/
```

The global request count on the dashboard should increment with each request.

---

## Live URLs

- **Application (Nginx / Nextcloud):** `http://178.105.31.108/`
- **Detector Dashboard:** `http://monitor.servehttp.com`

---

## GitHub Repository

Repository: `https://github.com/PrincewillDev/anomaly_detection_engine`

---

## Blog Post

A detailed write-up covering the design decisions, anomaly detection theory, and lessons learned during this project is available at:

`https://dev.to/princewilldev/how-i-built-a-real-time-ddos-detection-engine-from-scratch-and-what-i-learned-g9h`
