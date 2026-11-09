# Intentionally insecure container image for the demo pipeline.
# Findings Trivy should report:
#   - outdated, end-of-life base image (OS package CVEs)
#   - container runs as root (no USER instruction)
#   - no HEALTHCHECK
FROM python:3.9-slim-bullseye

WORKDIR /app

COPY app/requirements.txt .
RUN pip install -r requirements.txt

COPY app/ .

EXPOSE 5000
CMD ["python", "app.py"]
