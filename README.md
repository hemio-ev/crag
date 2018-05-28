# crag

Native Haskell client library for ACME (Automatic Certificate Management
Environment)

[![build status](https://git.hemio.de/hemio/crag/badges/master/build.svg)](https://git.hemio.de/hemio/crag/commits/master)
[![coverage report](https://git.hemio.de/hemio/crag/badges/master/coverage.svg)](https://git.hemio.de/hemio/crag/commits/master)

**This library is WORK IN PROGRESS**

## Interation Tests

The integration tests are performed against [letsencrypt/pebble](https://github.com/letsencrypt/pebble). You can setup pebble by running

    make pebble

The tests can be beformed via

    cabal update
    cabal sandbox init
    cabal install --enable-tests --enable-coverage
    make pebble
    cabal test

All required servers are started automatically by the tests.

## About ACME

The ACME draft is currently in version 9 and in "WG Last Call". The ACME server
implementation *boulder* currently substentially deviates from the current ACME
draft and is NOT supported by this library.

This library has workarounds for compatibility with *boulder*. They will be
dropped, once *boulder* follows the upcomming RFC.

- [ACME draft at IETF](https://datatracker.ietf.org/doc/draft-ietf-acme-acme)
- [Pebble (Let's Encrypt's ACME test server)](https://github.com/letsencrypt/pebble)
- [Boulder (Let's Encrypt's ACME server)](https://github.com/letsencrypt/boulder)
- [Boulder divergences from ACME](https://github.com/letsencrypt/boulder/blob/master/docs/acme-divergences.md)
