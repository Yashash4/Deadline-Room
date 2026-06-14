# Reproducible one-command bring-up for Deadline Room.
# Build:  docker build -t deadline-room .
# Test:   docker run --rm deadline-room            (default: runs the suite)
# Demo:   docker run --rm deadline-room python floor/run_floor.py   (needs keys)
#
# The deterministic core needs only the standard library plus pytest, so the
# default command exercises the whole 188-test suite with no API keys and no
# network. The live floor run needs BAND_API_KEY + FEATHERLESS_API_KEY passed
# in at runtime.
FROM python:3.11-slim

WORKDIR /app

# Install pinned dependencies first so the layer caches across code changes.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the repository.
COPY . .

# Default to the offline, no-key verification path so the image is useful out
# of the box: a clean clone proves the deterministic core on first run.
CMD ["python", "-m", "pytest", "tests/", "-q"]
