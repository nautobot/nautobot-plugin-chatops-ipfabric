## v3.0.0 - 2023-01-23

## Added

- #122 - Updated to support `python-ipfabric` v6 and Nautobot 1.5.
- #123 - New command `get-loaded-snapshots` for greater snapshot details.

## Changed

- New codeowner added - @alhogan.

## v2.0.0 - 2022-09-22

## Added

- #109 - Migration to use `python-ipfabric` library as the API client to IP Fabric.
- #103 - New command `get-loaded-snapshots` for greater snapshot details.

## Changed

- Version 2.0.0 of `nautobot-plugin-chatops-ipfabric` only supports IP Fabric version v5.0 and above.

## v1.2.0 - 2022-07-07

## Added

- #100 - Migration to use `python-ipfabric` library as the API client to IP Fabric.
- #103 - New command `get-loaded-snapshots` for greater snapshot details.

## Changed

- Removed the deprecated `end-to-end-path` command.


## v1.1.4 - 2022-06-08

## Added

- #96 - Slack CI notification for build pipeline.

### Fixed

- #97 - Fix for pathlookup argument selection error when using dialog box.

## v1.1.3 - 2022-05-25

### Fixed

- #93 - Bump pyjwt dependency.
- #92 - Update plugin description.
- #91 - Fix for null WLAN SSIDs.

## v1.1.2 - 2022-05-11

### Added

- #87 - Migrate `ipfabric pathlookup` to use the ipfabric-diagrams library. PNG output for IP Fabric 4.3+ only.
- #85 - Update plugin description to Nautobot Plugin Chatops IPFabric.
- #84 - Added Hugo as codeowner.
- #83 - Request permission to send files to Microsoft Teams.


## v1.1.1 - 2022-02-10

### Added

- #67 - Improved snapshot handling and added lock representation in snapshot select menu.
- #76 - Added case-insensitive search capability for hostnames.

## v1.1.0 - 2022-01-18

### Deprecated

- The `end-to-end-path` command is being deprecated and will be available for users of IP Fabric v3.8. Future path simulation capability will be developed in the `pathlookup` command for IP Fabric v4.

### Added

- #60 - Added `find-host` command.
- #61 - Added `pathlookup` command to get PNG for path lookups. Supported in IP Fabric v4. 


## v1.0.0 - 2021-12-06

Initial release