multus
======

[![Build Status](https://github.com/companyzero/multus/workflows/Build%20and%20Test/badge.svg)](https://github.com/companyzero/multus/actions)
[![ISC License](https://img.shields.io/badge/license-ISC-blue.svg)](http://copyfree.org)

## Overview

multus is a backup and restore tool that supports encryption and incrementals.

**multus is currently a Proof-Of-Concept tool!  We will happily take PRs that
move multus into a more mature project.**

### Setup

 1. Create the .multus directory: `$ mkdir -m 0700 ~/.multus`  
 1. Install [Super Sekrit](https://github.com/jrick/ss)
    1. Generate a keypair with `ss keygen`
    1. Copy the public key to `~/.multus`
 1. Copy `backup.conf.sample` to `~/.multus`
 1. Edit `~/.multus/backup.conf`

### Run

#### Backup

`$ multus backup`

#### Restore

`$ multus restore [file] [level]`

## License

multus is licensed under the [copyfree](http://copyfree.org) ISC License.
