# Security Policy

Advanced Network IDS is an educational and portfolio project. Please use it only in environments where you have explicit authorization.

## Reporting a vulnerability

Do not publish credentials, private packet captures, personal data, or exploit details in a public issue. For a suspected security issue, provide a minimal description of the affected component, impact, reproduction context, and a safe remediation suggestion through a private channel when available.

## Safe handling

- Keep secrets in environment variables and never commit `.env` files.
- Treat captured packets, uploaded PCAPs, and generated reports as sensitive data.
- Review CORS, authentication, and authorization settings before exposing the API beyond a local lab.
- Validate and sanitize untrusted network input before processing or storing it.
