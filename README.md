# eos-userutils

**E-OS fork of [`redox-os/userutils`](https://gitlab.redox-os.org/redox-os/userutils).** Part of the [**E-OS**](https://github.com/Gh0s777tt/E-OS) ecosystem — a hardened, Crimson-branded downstream of [Redox OS](https://www.redox-os.org).

This repository is Redox **login / getty / passwd** user utilities.

## E-OS changes vs upstream

- **First-boot OOBE (R-602)** — `login` forces a password change before spawning a shell for the shipped passwordless `user` **and** any account still on the default `password`, on the text/getty and serial paths.

## How it's pinned

The E-OS build pins this fork in [`recipes/core/userutils/recipe.toml`](https://github.com/Gh0s777tt/E-OS/blob/main/recipes/core/userutils/recipe.toml):

- branch **`eos-july`** · rev **`799088a107e8`**
- up to date with upstream

## Build standalone

This fork is normally built by the E-OS cookbook (`make CI=1 …` in the [main repo](https://github.com/Gh0s777tt/E-OS)). To build it on its own you need the Redox toolchain; see the main repo's [build guide](https://github.com/Gh0s777tt/E-OS/blob/main/docs/building.md).

## Hosting

**GitLab (source of truth):** https://gitlab.com/e-os/eos-userutils  
**GitHub (read-only mirror):** https://github.com/Gh0s777tt/eos-userutils

## License

MIT (inherited from upstream Redox). The E-OS project as a whole is AGPL-3.0; see the [main repo](https://github.com/Gh0s777tt/E-OS/blob/main/LICENSE).

---
[E-OS main repo](https://github.com/Gh0s777tt/E-OS) · [Docs](https://github.com/Gh0s777tt/E-OS/tree/main/docs) · [Upstream](https://gitlab.redox-os.org/redox-os/userutils)
