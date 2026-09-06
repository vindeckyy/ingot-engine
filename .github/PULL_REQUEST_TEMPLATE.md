## Summary

What does this PR change, and why?

## Verification

- [ ] `./scripts/check.sh --strict` passes
- [ ] New logic has a runnable check (unit test or assert-based self-check)
- [ ] No new mandatory runtime dependency
- [ ] No silently ignored API options
- [ ] Error bodies are Docker-shaped (`{"message": "..."}`)
- [ ] Tier 1 tests stay rootless-safe (no namespaces, mounts, cgroups, netlink, daemon socket)

## Test plan

- [ ] Tier 1: `cargo test --workspace` passes locally
- [ ] Tier 2 (if applicable): `./scripts/test_interop.sh` and/or `./scripts/test_network.sh` pass on a disposable root host

## Notes

Any context reviewers need: migration concerns, firewall/cgroup teardown changes, or follow-up work.
