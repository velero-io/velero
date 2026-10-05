# Running in Docker

To run this site in a Docker container, you can use `make serve-docs` from the root directory.

# Dependencies for MacOS

Install the following for an easy to use dev environment:

* `brew install hugo`

# Dependencies for Linux
If you are running a build on Ubuntu you will need the following packages:
* hugo


# Local Development
1. Clone down your own fork, or clone the main repo `git clone https://github.com/velero-io/velero` and add your own remote.
1. `cd velero/site`
1. Serve the site and watch for markup/sass changes `hugo serve`.
1. View your website at http://127.0.0.1:1313/
1. Commit any changes and push everything to your fork.
1. Once you're ready, submit a PR of your changes. Netlify will automatically generate a preview of your changes.

# Jetbrains IDE setup (IntelliJ, Goland, etc)
1. Install the `Hugo Integration` plugin: https://plugins.jetbrains.com/plugin/13215-hugo-integration
    - Under `Preferences...` -> `Plugins`
1. Create a new configuration:
    - Click `Edit Configurations...`
    - Click the `+` button to create a new configuration and select `Hugo`
    - Select `hugo serve` and make sure it is running under the `site` directory
    - Save and run the new Configuration
    - View your website at http://127.0.0.1:1313/
    - Any changes in `site` will reload the website automatically

# Adding a New Docs Version

To add a new set of versioned docs to go with a new Velero release:

1. In the root of the repository, run:

   ```bash
   # set to the appropriate version numbers
   NEW_DOCS_VERSION=vX.Y VELERO_VERSION=vX.Y.Z make gen-docs
   ```

1. [Pre-release only] In `site/config.yaml`, revert the change to the `latest` field, so the pre-release docs do not become the default.
