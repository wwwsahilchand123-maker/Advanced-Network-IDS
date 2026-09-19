# Security Checklist

Use this checklist before running the IDS outside a local lab.

- [ ] Set a unique `SECRET_KEY` in the environment.
- [ ] Set a strong unique admin password.
- [ ] Keep `DEBUG=False`.
- [ ] Restrict CORS origins to trusted clients.
- [ ] Keep `.env`, databases, logs and packet captures out of Git.
- [ ] Run packet capture only on authorized networks.
- [ ] Review detection alerts before taking response actions.
- [ ] Rotate API keys if they are exposed.
- [ ] Use HTTPS when exposing the API beyond localhost.
- [ ] Use PostgreSQL for multi-user deployments.
