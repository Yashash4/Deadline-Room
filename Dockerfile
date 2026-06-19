# Container images for Deadline Room: one shared base, one clean image per role.
#
# The deployment is container-per-agent (AGENTS.md hard convention 5: one Band
# WebSocket connection per agent id, last connection wins, so each Band agent runs
# in its own container). This Dockerfile builds a single base layer with the code
# and pinned deps, then a small final stage per role that sets only the entrypoint.
# Every stage shares the cached base layer, so the three role images differ only in
# their CMD, never in their contents.
#
# Build the base (default target) and run the offline suite:
#   docker build -t deadline-room .
#   docker run --rm deadline-room
#
# Build a role image:
#   docker build --target warden  -t deadline-room-warden  .
#   docker build --target service -t deadline-room-service .
#   docker build --target drafter -t deadline-room-drafter .
#
# The deterministic core needs only the standard library plus pytest; the standing
# service (service/) additionally needs fastapi + uvicorn. A live floor run needs
# BAND_API_KEY + FEATHERLESS_API_KEY passed in at runtime; the service and the
# offline suite need no keys and no network.

# --- base: code + pinned runtime/test deps, shared by every role image --------
FROM python:3.11-slim AS base

WORKDIR /app

# Install pinned dependencies first so the layer caches across code changes.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# The standing governance service and its ASGI server (service/ optional extra).
RUN pip install --no-cache-dir "fastapi>=0.110" "uvicorn>=0.27"

# Copy the rest of the repository.
COPY . .

# A non-root runtime user: the container never needs root, and the signing key
# custody seam (warden/custody.py) is happier without it.
RUN useradd --create-home --uid 10001 appuser && chown -R appuser:appuser /app
USER appuser

# Default to the offline, no-key verification path so the base image is useful out
# of the box: a clean clone proves the deterministic core on first run.
CMD ["python", "-m", "pytest", "tests/", "-q"]

# --- service: the standing governance API + product UI ------------------------
# Serves the read spine (/portfolio, /queue, /sla, /insights), the offline seal
# write path (/incidents), the Prometheus /metrics surface, the product UI, and the
# approval screen fronting the real two-key release gate. Liveness /healthz and
# readiness /readyz are the k8s probe targets.
FROM base AS service
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "web.app_server:app", \
     "--host", "0.0.0.0", "--port", "8000"]

# --- warden: the deterministic gate process -----------------------------------
# The no-LLM Warden runs its own container so its Band agent id owns a single
# WebSocket connection. The shell binds it to a live room; offline it audits the
# sealed corpus, the deterministic verdict the rest of the system trusts.
FROM base AS warden
ENV DEADLINE_ROOM_ROLE=warden
CMD ["python", "scripts/audit_run.py"]

# --- drafter: one LLM drafter agent per regime --------------------------------
# Each regulatory drafter runs in its own container (container-per-agent). The
# regime is selected at run time by DEADLINE_ROOM_REGIME so the same image serves
# every drafter Deployment; the live shell connects it to the room.
FROM base AS drafter
ENV DEADLINE_ROOM_ROLE=drafter
ENV DEADLINE_ROOM_REGIME=nis2
CMD ["python", "-c", "import os; print('drafter role for regime', os.environ.get('DEADLINE_ROOM_REGIME')); import floor.run_floor"]
