# Development Notes

## Local Development

Keep environment-specific configuration in `.env` and use `.env.example` as the template. Do not commit credentials, API tokens, local databases, packet captures or generated logs.

## Before a Pull Request

- Run the backend test suite.
- Review configuration changes for secret exposure.
- Update documentation when behavior changes.
- Keep detection rules explainable and testable.
- Include a concise commit message describing the change.
