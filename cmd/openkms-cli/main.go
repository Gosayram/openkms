// Copyright 2025 Gosayram Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"os"

	"github.com/alecthomas/kong"
)

func main() {
	var cli CLI
	ctx := kong.Parse(&cli,
		kong.Name("openkms-cli"),
		kong.Description("OpenKMS Key Management Service CLI"),
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact: true,
		}),
	)

	// Bind CLI to all commands
	bindCLI(&cli)

	if err := ctx.Run(); err != nil {
		os.Exit(1)
	}
}

// bindCLI binds the CLI instance to all commands
func bindCLI(cli *CLI) {
	cli.Key.Create.CLI = cli
	cli.Key.Get.CLI = cli
	cli.Encrypt.CLI = cli
	cli.Decrypt.CLI = cli
	cli.Sign.CLI = cli
	cli.Verify.CLI = cli
	cli.HMAC.CLI = cli
	cli.Rotate.CLI = cli
	cli.Rewrap.CLI = cli
	cli.Health.CLI = cli
	cli.Migrate.Up.CLI = cli
	cli.Migrate.Down.CLI = cli
	cli.Audit.CLI = cli
}
