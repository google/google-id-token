# Change Log

## [1.4.1] - 2017-09-06
### Added
- Add compatibility with `jwt` gem `v2.0`.


## [1.4.0] - 2017-09-01
### Added
- Add `expiry` option to the `Validator` which defines the time after which the certificates cache should be renewed. This prevents continuously fetching them in case of constant decoding errors.

### Changed
- Make `Validator` thread-safe by not maintaining error state. Errors in `#check` are not saved to the instance variable `problem`. Added specific error classes which are raised upon validation errors instead.
- Caching certificates in the `Validator` instead of always fetching them from Google servers.
