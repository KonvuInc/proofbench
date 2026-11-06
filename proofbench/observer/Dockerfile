# Victim browser + readiness prober. Owned by the controller, never by the attacker.
FROM mcr.microsoft.com/playwright/python:v1.49.1-noble
RUN pip install --no-cache-dir --break-system-packages playwright==1.49.1
COPY probe.py victim.py /obs/
WORKDIR /obs
