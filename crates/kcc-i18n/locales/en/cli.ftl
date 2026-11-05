# Command-line output.

cli-about = Manage Keenetic and Netcraze routers from the command line, the Web UI and MCP.
cli-router-added = Router { $name } added.
cli-router-removed = Router { $name } removed.
cli-no-routers = No routers are configured.
cli-connecting = Connecting to { $url }...
cli-connected = Connected to { $model } running firmware { $version }.
cli-config-written = Configuration written to { $path }.
cli-dry-run = Dry run: no changes were sent to the router.
cli-changes-applied =
    { $count ->
        [one] { $count } change applied.
       *[other] { $count } changes applied.
    }
