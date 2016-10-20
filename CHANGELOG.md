# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## [Unreleased]

## [v0.1.1] - 2016-10-20

### Changed

- `itmdump` no longer depends on the `mkfifo` command.
- `itmdump`, which normally uses named pipes, now fallbacks to regular files to
  be work on Windows. 
- `itmdump` now is restrictive with about the arguments it receives. Before, a
  second argument would simply be ignored, but, now, that has become a hard
  error.
- `itmdump` version output (`-V`) now includes the git commit hash and date.

## v0.1.0 - 2016-10-03

### Added

- `itmdump` tool that parses instrumentation packets from the stimulus port 0
  and dumps the payload to `stdout`. 

[Unreleased]: https://github.com/japaric/itm/compare/v0.1.1...HEAD
[v0.1.1]: https://github.com/japaric/itm/compare/v0.1.0...v0.1.1
