# Contributing to Advanced Network IDS

Thanks for contributing. This project is intended for defensive security research and authorized lab environments.

## Development workflow

1. Create a focused branch for your change.
2. Keep detection logic, API changes, and UI changes isolated where practical.
3. Add or update tests for behavior you change.
4. Run the backend test suite before opening a pull request:

```bash
cd backend
pytest -q
```

## Detection changes

When changing a detector, document the signal it uses, expected false positives, and any tunable threshold. Avoid hard-coding credentials, API keys, captured traffic, or private network data.

## Pull requests

Please include a short summary, testing performed, and any security or compatibility considerations. Only test packet capture and detection against systems or traffic you are authorized to monitor.
