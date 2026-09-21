# Contributing

Thank you for helping improve Manticore Sentinel. This repository is public for transparency and evaluation. It is still a host-security-sensitive tool.

## Before you start

- Read [README.md](README.md) and [SECURITY.md](SECURITY.md).
- Do not include secrets, production host dumps, or exploit proofs in issues or pull requests.
- Security defects go through private advisory reporting, not the public issue tracker.

## Development

Requirements: Linux, current stable Rust.

```bash
cargo test
cargo run -- --benchmark
```

Optional: `cargo fmt` and `cargo clippy --all-targets -- -D warnings` before a pull request.

## Pull requests

- Keep changes focused. Prefer a small patch with tests over a wide refactor.
- Update docs when you change configuration, auth, HTTP listeners, or Compose publishes.
- Example profiles under `config/profiles/` must not gain real or placeholder secrets.
- Protocol-only ecosystem rule: talk to PeerWeave and EVRUS over HTTP/GraphQL/OIDC/JSON-RPC. Do not add shared crates or in-process coupling.

## Code of collaboration

Be specific and professional. Harassment or malicious use of this codebase (unauthorized access against systems you do not operate) is not welcome.

## License

Contributions are accepted under the same terms as [LICENSE](LICENSE).
