# Docker Hardening Guide (Debian/Ubuntu)

### 📋 Overview
Docker simplifies containerization but introduces host‑level and container‑level security risks.  
Hardening Docker ensures minimal attack surface and controlled privilege boundaries.

---

## 🧩 Common Weak Points
- Containers run as root by default  
- Daemon (`dockerd`) exposed on TCP without TLS  
- Unrestricted container capabilities  
- Unconfined network traffic between containers  
- Unused images left unscanned  
- Missing AppArmor or Seccomp profiles  

---

## 🔒 Hardening Steps

| # | Action | File/Command | Recommended Setting | Purpose |
|---|---------|---------------|--------------------|----------|
| 1 | Limit Docker socket exposure | `/lib/systemd/system/docker.service` | Remove `-H tcp://0.0.0.0:2375` | Prevent remote daemon access |
| 2 | Enforce user namespace remapping | `/etc/docker/daemon.json` | `"userns-remap": "default"` | Map container users to unprivileged host users |
| 3 | Disable containers running as root | Dockerfile/Runtime | `USER appuser` inside Dockerfile | Drop root privileges |
| 4 | Enable default seccomp & AppArmor profiles | `/etc/docker/daemon.json` | `"seccomp-profile": "/etc/docker/seccomp.json"` | Kernel syscall filtering |
| 5 | Restrict capabilities | Container run options | `--cap-drop=ALL --cap-add=NET_BIND_SERVICE` | Principle of least privilege |
| 6 | Disable inter-container communication | `/etc/docker/daemon.json` | `"icc": false` | Isolate containers |
| 7 | Restrict networking exposure | Docker run options | `--network bridge` or specific subnet | Minimize broadcast domain |
| 8 | Enable audit logging | `/etc/docker/daemon.json` | `"log-driver": "json-file"`, set rotation | Track container activity |
| 9 | Limit image provenance | Docker CLI | `FROM signed/base:image` | Use trusted repositories |
| 10 | Regular cleanup | Periodic cron | `docker system prune --all --force` | Remove stale/unpatched layers |

---

### ⚙️ Example Secure Configuration (`/etc/docker/daemon.json`)
```json
{
  "icc": false,
  "userns-remap": "default",
  "no-new-privileges": true,
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "5" },
  "live-restore": true
}


### ⚙️ Example Container Runtime

```bash
# run container with least privilege:
docker run -d \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid \
  --cap-drop=ALL \
  --cap-add=NET_BIND_SERVICE \
  --security-opt=no-new-privileges:true \
  --security-opt=seccomp=/path/to/seccomp.json \
  --user 1000:1000 \
  --pids-limit 100 \
  --memory="512m" \
  --cpus="0.5" \
  myapp:latest
```

| Author | Repository | License | Last Update |
|---------|-------------|----------|--------------|
| [**yasinabedini**](https://github.com/yasinabedini) | Harden‑Self / playbooks / linux | 2025‑11‑13 |
