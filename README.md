# libghc-acme

Native Haskell client library for ACME (Automatic Certificate Management
Environment)

[![build status](https://git.hemio.de/hemio/libghc-acme/badges/master/build.svg)](https://git.hemio.de/hemio/libghc-acme/commits/master)

## Interation Tests

Running the integration tests, requires a running *boulder* server. To setup and
start *boulder* inside a *docker* container you can use

    ./boulder-install.bash
    ./boulder-start.bash

If the boulder server is running you can

    cabal sandbox init
    cabal install
    cabal test

## About ACME

The ACME draft is currently in version 5 and in "WG Last Call". The ACME server
implementation *boulder* substentially deviates from the current draft.

This library has workarounds for compatibility with *boulder*. They will be
dropped, once *boulder* follows the upcomming RFC.

- [ACME draft at IETF](https://datatracker.ietf.org/doc/draft-ietf-acme-acme)
- [Boulder (Let's Encrypt's ACME-Server)](https://github.com/letsencrypt/boulder)
- [Boulder divergences from ACME](https://github.com/letsencrypt/boulder/blob/release/docs/acme-divergences.md)

