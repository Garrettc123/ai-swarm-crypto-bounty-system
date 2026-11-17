FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORT=8080
WORKDIR /app
COPY bounty_discovery_service.py bounty_intelligence.py bounty_work_queue.py blockscout_evidence.py immunefi_review.py rhns_governance.py bounty_queue_persistence.py bounty_queue_oidc.py dashboard.html dashboard.css dashboard.js /app/
RUN python -m pip install --no-cache-dir 'redis>=5,<7' 'PyJWT[crypto]>=2.8,<3'
RUN useradd --uid 10001 --create-home --no-log-init scout
USER scout
EXPOSE 8080
CMD ["python", "-u", "bounty_discovery_service.py"]
