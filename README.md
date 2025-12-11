# Instagram profile asset downloader :rocket:

**_Instagram Profile Asset Downloader_**, or `igassdown` for short, is a FREE and open-source command‑line tool that logs into Instagram and downloads all posts (photos and videos) and basic post metadata for a given profile. It is designed to work well for both public and private profiles (when you authenticate), and to be scriptable for batch runs or cron jobs.

All downloaded data is written into an output directory (default: `./output`) in a per‑profile subdirectory. For each profile you get:

- JSON metadata for every post
- A text file containing one URL per line for all media assets
- The downloaded media files themselves, named with a timestamp and shortcode

## Quick start :surfer:

> [!NOTE]
> Make sure you [install dependencies](#install-dependencies) first.

Log in once and store a reusable session file (no posts are downloaded):

```sh
python -m igassdown -l <login-user> --login-only
```

Log in and download all posts for a target profile into the default `output` directory:

```sh
python -m igassdown -l <login-user> -t <target-profile>
```

Run non‑interactively (suitable for cron) and write to a custom directory:

```sh
python -m igassdown -l <login-user> -t <target-profile> -o /path/to/output --quiet
```

## Install Dependencies

It’s recommended to work inside a Python virtual environment so that `igassdown` and its dependencies stay isolated from your system.

**From the project root:**

*On macOS / Linux*

```sh
python -m venv .venv
. .venv/bin/activate

pip install -r src/requirements/requirements.txt
```

*On Windows (PowerShell)*

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1

pip install --upgrade pip
pip install -r src\requirements\requirements.txt
```

After activating the virtual environment and installing dependencies, you can run the CLI as:

```sh
python -m igassdown --help
```

## Command‑line usage :gear:

The module exposes a CLI via `python -m igassdown`.

```text
igassdown [--login YOUR-USERNAME]
igassdown [OPTIONS]
igassdown --help
```

### What to download

- `-t, --target TARGET-PROFILE`  
	Instagram profile whose posts should be downloaded. If omitted, the logged‑in user’s profile is used.

### How to download

- `-S, --no-sleep`  
	Disable internal sleeps between requests. By default the downloader sleeps briefly to be polite to Instagram; use this option at your own risk.

- `--max-connection-attempts N`  
	Maximum number of times a failed HTTP request is retried before being aborted.  
	Default: `3`. Set to `0` to retry indefinitely until the request succeeds or is manually interrupted (e.g. with `CTRL+C`).

- `--request-timeout N`  
	Timeout (in seconds) for each HTTP request.  
	Default: `300.0` seconds.

- `--abort-on STATUS_CODES`  
	Comma‑separated list of HTTP status codes that cause igassdown to abort immediately, bypassing all retry logic.  
	Example: `--abort-on 400,401,403,404,429,500`.

- `--user-agent UA-STRING`  
	Override the default HTTP User‑Agent string used for requests.

### Login (download private profiles)

To download from private profiles you control, or to access content only visible when logged in, you must authenticate. igassdown stores a session file (containing cookies, not your password) so later runs can reuse the same login.

- `-l, --login YOUR-USERNAME`  
	Instagram username to log in with. When used, igassdown will try to load an existing session file; if none exists or it is invalid, it will log in (interactively or using `--password`) and then save a fresh session file.

- `-p, --password YOUR-PASSWORD`  
	Password for the Instagram account. If omitted, igassdown will prompt for your password interactively when needed.

- `--login-only`  
	Perform login (creating/updating the session file) and exit without downloading any posts.

- `-f, --sessionfile PATH`  
	Path to load and store the session key file.  
	Default: a file under your OS‑specific config directory, similar to `~/.config/igassdown/session-<login_name>`.

- `-b, --load-cookies BROWSER-NAME`  
	Import an existing Instagram session directly from a supported browser using the optional `browser_cookie3` library. Supported values include `brave`, `chrome`, `chromium`, `edge`, `firefox`, `librewolf`, `opera`, `opera_gx`, `safari`, and `vivaldi`.

- `-B, --cookiefile COOKIE-FILE`  
	Optional cookie file path to use together with `--load-cookies` when the browser supports custom cookie locations.

> Note: `--login` and `--load-cookies` cannot be used together in the same invocation.

### Miscellaneous options

- `-o, --output OUTPUT-DIR`  
	Base directory where profile subdirectories and downloaded assets will be stored.  
	Default: value from `Config.output_dir` (typically `./output`).

- `-q, --quiet`  
	Quiet mode. Suppresses non‑error output and disables interactive prompts. If credentials or input are required but not provided, the program will fail instead of asking. Intended for unattended / cron usage.

- `-h, --help`  
	Show built‑in help and exit.

## Examples :robot:

Download your own posts after logging in interactively:

```sh
python -m igassdown -l myuser
```

Download from a private profile you follow, reusing an existing session file:

```sh
python -m igassdown -l myuser -t friend_profile
```

Use cookies from Firefox instead of typing a password:

```sh
python -m igassdown --load-cookies firefox -t target_profile
```

Run as a nightly cron job, aborting on 4xx/5xx errors, with minimal logging:

```sh
python -m igassdown -l myuser -t target_profile \
	--abort-on 400,401,403,404,429,500 \
	--max-connection-attempts 5 \
	--request-timeout 120 \
	--quiet
```

## Notes :pencil:

- The tool respects your existing Instagram permissions; it cannot access content you cannot see in the browser.
- Be mindful of Instagram’s terms of service and rate limits when using automated tools.

---

# Contributing :sparkles:

See [CONTRIBUTING.md](CONTRIBUTING.md) for information on contributing to this project.

---

# License :card_index:

This project © 2025 by [Andrew Haller](https://github.com/andrewhaller) is licensed under the [MIT License](https://opensource.org/license/mit). See the [LICENSE](LICENSE) file for details.
