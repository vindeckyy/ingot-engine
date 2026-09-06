---
name: Bug report
about: Report a defect in Ingot
title: "[bug] "
labels: bug
body:
  - type: textarea
    id: summary
    attributes:
      label: Summary
      description: What happened, and what did you expect?
    validations:
      required: true
  - type: textarea
    id: reproduce
    attributes:
      label: Reproduction steps
      description: Minimal sequence to trigger the bug.
    validations:
      required: true
  - type: input
    id: version
    attributes:
      label: Ingot version
      description: Output of `ingot version` or the commit hash.
    validations:
      required: true
  - type: input
    id: env
    attributes:
      label: Environment
      description: OS, kernel version, Docker CLI version if interop.
    validations:
      required: true
  - type: textarea
    id: logs
    attributes:
      label: Logs
      description: Relevant daemon or CLI output. Redact secrets.
      render: shell
  - type: dropdown
    id: tier
    attributes:
      label: Test tier
      options:
        - Tier 1 (rootless unit)
        - Tier 2 (root integration)
        - Not sure
    validations:
      required: true
---

## Summary

What happened, and what did you expect?

## Reproduction steps

1.
2.
3.

## Ingot version

## Environment

OS, kernel, Docker CLI version if interop.

## Logs

```
(paste relevant output, redact secrets)
```

## Test tier

Tier 1 (rootless unit), Tier 2 (root integration), or not sure.
