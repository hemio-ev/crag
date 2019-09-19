# crag

Native Haskell client library and CLI for ACME (Automatic Certificate Management Environment, RFC 8555)

[![build status](https://git.hemio.de/hemio/crag/badges/master/build.svg)](https://git.hemio.de/hemio/crag/commits/master)
[![coverage report](https://git.hemio.de/hemio/crag/badges/master/coverage.svg)](https://git.hemio.de/hemio/crag/commits/master)

## Integration Tests

The integration tests are performed against [letsencrypt/pebble](https://github.com/letsencrypt/pebble). These tests can be run by executing

```sh
sudo curl -sSL https://get.haskellstack.org/ | sh
make pebble
stack test
```

All required servers are started and stopped automatically.

## About ACME

- [RFC 8555: Automatic Certificate Management Environment (ACME)](https://tools.ietf.org/html/rfc8555)
- [Pebble (Let's Encrypt's ACME test server)](https://github.com/letsencrypt/pebble)
- [Boulder (Let's Encrypt's ACME server)](https://github.com/letsencrypt/boulder)
- [Boulder divergences from ACME](https://github.com/letsencrypt/boulder/blob/master/docs/acme-divergences.md)
