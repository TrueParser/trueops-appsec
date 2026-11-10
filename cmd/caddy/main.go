// Command caddy runs the TrueOps AppSec distribution using Caddy's native CLI.
package main

import (
	_ "github.com/TrueParser/trueops-appsec/modules/appsec"
	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
)

func main() {
	caddycmd.Main()
}
