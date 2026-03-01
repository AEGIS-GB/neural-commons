# Centaur — vLLM Deployment Configs (Phase 4)

On-demand vLLM deployment for the Centaur reasoning service.

## Prerequisites (HIL)

- vLLM/ROCm benchmark must complete in Phase 0
- Benchmark report determines: VRAM usage, tokens/sec, quantization needed

## Configuration

- Cold start target: <30s
- Hot-pin threshold: >50 daily queries → pin to 2 GPU nodes (D27)
- Podman rootless sandbox (§22)

## Files (to be created)

- `vllm-config.yml` — vLLM server configuration
- `Containerfile` — Podman container definition
- `deploy.sh` — Deployment script
