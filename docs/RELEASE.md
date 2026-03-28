# Open OSCAR Server Release Process

This document explains how the Open OSCAR Server release process works.

## Overview

Open OSCAR Server is built and released to Github using [GoReleaser](https://goreleaser.com/). The release process, which
runs from a local computer (and not a CI/CD process) creates pre-built binaries for several platforms (Windows, macOS,
Linux).

GoReleaser runs in a Docker container, which provides a hermetic environment that prevents build contamination from the
host environment.

### Code Signing Policy

This project offers signed Windows binaries and does not currently offer signed macOS binaries. This means that macOS
distrusts Open OSCAR Server by default and quarantines the application when you open it.
> If you don't want to bypass this security mechanism, you can [build the project yourself](./building) instead.

## Release Procedure

The following is the procedure that builds Open OSCAR Server and uploads the build artifacts to a Github release.

1. **Export Github Personal Access Token (PAT)**

   Export a Github Personal Access Token that has `write:packages` permissions for the Open OSCAR Server repo.

    ```sh
    export GITHUB_TOKEN=...
    ```

2. **Tag The Build**

   Tag the build using [semantic versioning](https://semver.org/).
    ```shell
    git tag v0.1.0
    git push --tags
    ```

3. **Dry-Run Release**

   Execute a dry-run build to make sure all the moving parts work together. Fix any problems that crop up before
   continuing.

    ```shell
   make release-dry-run
    ```

4. **Release It!**

   Now run the release process. Once its complete, a private draft [release](https://github.com/mk6i/open-oscar-server/releases)
   should appear with attached build artifacts.

   Run the following two commands in separate terminals.

   ```shell
   make sign-server    # terminal 1, with SIGN_* env for your token
   make release-sign-docker   # terminal 2
   ```

5. **Publish It**
   Publish the draft release.
