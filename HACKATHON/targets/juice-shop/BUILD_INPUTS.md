# Juice Shop build inputs

This document records the exact build inputs for the Juice Shop target used in Phase 1.7.

## Source revision

- Repository: `https://github.com/juice-shop/juice-shop.git`
- Pinned revision: `f189f521266f42c6bd05884468292000cee852ed`
- Version tag: `v20.3.0`

## Container image

- Image: `bkimminich/juice-shop:v20.3.0@sha256:cea5a4af4aacee498c491491af0408934ec81d004035c0a02ef3e54395e3bf27`

## Build contract

The source checkout mounted by the profile must remain aligned with the pinned revision above. The route adapter and static-analysis pipeline should reference this same exact target revision so that findings are tied to a reproducible app version.
