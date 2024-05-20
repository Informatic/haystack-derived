# haystack-derived

This is a minimal plain-C reimplementation of key derivation carried out by certain offline tracking tags.

Uses [micro-ecc](https://github.com/kmackay/micro-ecc) library for elliptic curve and general large integer operations, and [sha-2](https://github.com/amosnier/sha-2) library for SHA-256.

See `main.c` for a simple usage example.

**Note:** This repository uses submodules, use `git submodule update --init` (or `git clone --recursive`) in order to properly fetch dependencies.

Based on and tested against [FindMy.py project](https://github.com/malmeloo/FindMy.py).