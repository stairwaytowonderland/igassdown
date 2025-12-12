"""Download pictures (or videos) along with post metadata from Instagram."""

import os
import re
import sys
from argparse import SUPPRESS, ArgumentParser, ArgumentTypeError
from enum import IntEnum
from typing import List, Optional

from . import (
    OUTPUT_DIR,
    PACKAGE_NAME,
    BadCredentialsException,
    Igdownloader,
    IgdownloaderException,
    InvalidArgumentException,
    LoginException,
    TwoFactorAuthRequiredException,
)
from .client import get_default_session_filename
from .config import AppConfig

try:
    import browser_cookie3

    bc3_library = True
except ImportError:
    bc3_library = False


class ExitCode(IntEnum):
    SUCCESS = 0
    NON_FATAL_ERROR = 1
    INIT_FAILURE = 2
    LOGIN_FAILURE = 3
    DOWNLOAD_ABORTED = 4
    USER_ABORTED = 5
    SAVE_FAILURE = 6
    UNEXPECTED_ERROR = 99


def usage_string():
    argv0 = os.path.basename(sys.argv[0])
    argv0 = "igdownloader" if argv0 == "__main__.py" else argv0
    return """
{0} [--login YOUR-USERNAME]
{2:{1}} [OPTIONS]
{0} --help""".format(
        argv0, len(argv0), ""
    )


def http_status_code_list(code_list_str: str) -> List[int]:
    codes = [int(s) for s in code_list_str.split(",")]
    for code in codes:
        if not 100 <= code <= 599:
            raise ArgumentTypeError("Invalid HTTP status code: {}".format(code))
    return codes


def get_cookies_from_instagram(domain, browser, cookie_file="", cookie_name=""):
    supported_browsers = {
        "brave": browser_cookie3.brave,
        "chrome": browser_cookie3.chrome,
        "chromium": browser_cookie3.chromium,
        "edge": browser_cookie3.edge,
        "firefox": browser_cookie3.firefox,
        "librewolf": browser_cookie3.librewolf,
        "opera": browser_cookie3.opera,
        "opera_gx": browser_cookie3.opera_gx,
        "safari": browser_cookie3.safari,
        "vivaldi": browser_cookie3.vivaldi,
    }

    if browser not in supported_browsers:
        raise InvalidArgumentException(
            "Loading cookies from the specified browser failed\n"
            "Supported browsers are Brave, Chrome, Chromium, Edge, Firefox, LibreWolf, "
            "Opera, Opera_GX, Safari and Vivaldi"
        )

    cookies = {}
    browser_cookies = list(supported_browsers[browser](cookie_file=cookie_file))

    for cookie in browser_cookies:
        if domain in cookie.domain:
            cookies[cookie.name] = cookie.value

    if cookies:
        print(f"Cookies loaded successfully from {browser}")
    else:
        raise LoginException(
            f"No cookies found for Instagram in {browser}, "
            f"Are you logged in successfully in {browser}?"
        )

    if cookie_name:
        return cookies.get(cookie_name, {})
    else:
        return cookies


def import_session(browser, igdownloader, cookiefile):
    cookie = get_cookies_from_instagram("instagram", browser, cookiefile)
    if cookie is not None:
        igdownloader.context.update_cookies(cookie)
        username = igdownloader.test_login()
        if not username:
            raise LoginException(
                f"Not logged in. Are you logged in successfully in {browser}?"
            )
        igdownloader.context.username = username
        print(f"{username} has been successfully logged in.")
        print(f"Next time use --login={username} to reuse the same session.")


def _main(
    igdownloader: Igdownloader,
    username: Optional[str] = None,
    password: Optional[str] = None,
    login_only: bool = False,
    target_profile: Optional[str] = None,
    output_dir: Optional[str] = None,
    sessionfile: Optional[str] = None,
    browser: Optional[str] = None,
    cookiefile: Optional[str] = None,
) -> ExitCode:
    """Download set of profiles, hashtags etc. and handle logging in and session files if desired."""
    # Parse and generate filter function
    # load cookies if browser is not None
    if browser and bc3_library:
        import_session(browser.lower(), igdownloader, cookiefile)
    elif browser and not bc3_library:
        raise InvalidArgumentException(
            "browser_cookie3 library is needed to load cookies from browsers"
        )
    output_dir = output_dir or igdownloader.context.config.output_dir
    # Login, if desired
    if username is not None:
        if not re.match(r"^[A-Za-z0-9._]+$", username):
            igdownloader.context.error(
                'Warning: Parameter "{}" for --login is not a valid username.'.format(
                    username
                )
            )
        try:
            igdownloader.load_session_from_file(username, sessionfile)
        except FileNotFoundError as err:
            if sessionfile is not None:
                print(err, file=sys.stderr)
            igdownloader.context.log("Session file does not exist yet - Logging in.")
        if (
            not igdownloader.context.is_logged_in
            or username != igdownloader.test_login()
        ):
            if password is not None:
                try:
                    igdownloader.login(username, password)
                except TwoFactorAuthRequiredException:
                    igdownloader.context.error(
                        "Warning: There have been reports of 2FA currently not working. "
                        "Consider importing session cookies from your browser with "
                        "--load-cookies."
                    )
                    while True:
                        try:
                            code = input("Enter 2FA verification code: ")
                            igdownloader.two_factor_login(code)
                            # igdownloader.save_session_to_file(sessionfile)
                            break
                        except BadCredentialsException as err:
                            print(err, file=sys.stderr)
            else:
                try:
                    igdownloader.interactive_login(username)
                except KeyboardInterrupt:
                    print("\nInterrupted by user.", file=sys.stderr)
                    return ExitCode.USER_ABORTED
        igdownloader.context.log("Logged in as '%s'." % username)

    exit_code = ExitCode.SUCCESS

    # Save session
    # Save before downloading posts to avoid session loss if download fails (or is cancelled)
    if igdownloader.context.is_logged_in:
        igdownloader.save_session_to_file(sessionfile)

    # Extract all posts
    if not login_only:
        try:
            download_count, _ = igdownloader.get_posts(
                username=target_profile, output_dir=output_dir
            )
            igdownloader.context.log(f"Assets downloaded: {download_count}")
        except Exception as e:
            exit_code = ExitCode.UNEXPECTED_ERROR
            print(
                f"Error fetching posts ({ExitCode.UNEXPECTED_ERROR.name}: {exit_code}):\n\t{e}",
                file=sys.stderr,
            )

    return exit_code


def main(
    config: AppConfig = AppConfig(OUTPUT_DIR, PACKAGE_NAME, LOG_STACKLEVEL=4)
) -> None:
    parser = ArgumentParser(
        description=__doc__,
        add_help=False,
        usage=usage_string(),
        epilog="The complete documentation can be found at "
        "https://github.com/stairwaytowonderland/igassdown.",
        fromfile_prefix_chars="+",
    )

    g_what = parser.add_argument_group("What to Download")
    g_what.add_argument(
        "-t",
        "--target",
        metavar="TARGET-PROFILE",
        help="Profile to download. Defaults to the logged-in user.",
    )

    g_how = parser.add_argument_group("How to Download")
    g_how.add_argument("-S", "--no-sleep", action="store_true", help=SUPPRESS)
    g_how.add_argument(
        "--max-connection-attempts",
        metavar="N",
        type=int,
        default=3,
        help="Maximum number of connection attempts until a request is aborted. Defaults to 3. If a "
        "connection fails, it can be manually skipped by hitting CTRL+C. Set this to 0 to retry "
        "infinitely.",
    )
    g_how.add_argument(
        "--request-timeout",
        metavar="N",
        type=float,
        default=300.0,
        help="Seconds to wait before timing out a connection request. Defaults to 300.",
    )
    g_how.add_argument(
        "--abort-on",
        type=http_status_code_list,
        metavar="STATUS_CODES",
        help="Comma-separated list of HTTP status codes that cause Igdownloader to abort, bypassing all retry logic.",
    )
    g_how.add_argument(
        "--user-agent",
        help="User Agent to use for HTTP requests. Defaults to '{}'.".format(
            config.default_user_agent()
        ),
    )

    g_login = parser.add_argument_group(
        "Login (Download Private Profiles)",
        "Igdownloader can login to Instagram. This allows downloading private profiles. "
        "To login, pass the --login option. Your session cookie (not your password!) "
        "will be saved to a local file to be reused next time you want Igdownloader "
        "to login. Instead of --login, the --load-cookies option can be used to "
        "import a session from a browser.",
    )
    g_login.add_argument(
        "-l",
        "--login",
        metavar="YOUR-USERNAME",
        help="Login name (profile name) for your Instagram account.",
    )
    g_login.add_argument(
        "-b",
        "--load-cookies",
        metavar="BROWSER-NAME",
        help="Browser name to load cookies from Instagram",
    )
    g_login.add_argument(
        "--login-only",
        action="store_true",
        help="Only perform login and then exit.",
    )
    g_login.add_argument(
        "-B",
        "--cookiefile",
        metavar="COOKIE-FILE",
        help="Cookie file of a profile to load cookies",
    )
    g_login.add_argument(
        "-f",
        "--sessionfile",
        help="Path for loading and storing session key file. "
        "Defaults to " + get_default_session_filename("<login_name>"),
    )
    g_login.add_argument(
        "-p",
        "--password",
        metavar="YOUR-PASSWORD",
        help="Password for your Instagram account. Without this option, "
        "you'll be prompted for your password interactively if "
        "there is not yet a valid session file.",
    )

    g_misc = parser.add_argument_group("Miscellaneous Options")
    g_misc.add_argument(
        "-o",
        "--output",
        metavar="OUTPUT-DIR",
        default=config.output_dir,
        help="Directory to save downloaded files to. Defaults to '{}'.".format(
            config.output_dir
        ),
    )
    g_misc.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Disable user interaction, i.e. do not print messages (except errors) and fail "
        "if login credentials are needed but not given. This makes Igdownloader suitable as a "
        "cron job.",
    )
    g_misc.add_argument(
        "-h", "--help", action="help", help="Show this help message and exit."
    )

    args = parser.parse_args()
    try:
        if args.login and args.load_cookies:
            raise InvalidArgumentException(
                "--load-cookies and --login cannot be used together."
            )

        loader = Igdownloader(
            config=config,
            sleep=not args.no_sleep,
            quiet=args.quiet,
            user_agent=args.user_agent,
            max_connection_attempts=args.max_connection_attempts,
            request_timeout=args.request_timeout,
            fatal_status_codes=args.abort_on,
        )
        exit_code = _main(
            loader,
            username=args.login.lower() if args.login is not None else None,
            password=args.password,
            login_only=args.login_only,
            output_dir=args.output,
            target_profile=(args.target or args.login),
            sessionfile=args.sessionfile,
            browser=args.load_cookies,
            cookiefile=args.cookiefile,
        )
        loader.close()
        if loader.has_stored_errors:
            exit_code = ExitCode.NON_FATAL_ERROR
    except InvalidArgumentException as err:
        print(err, file=sys.stderr)
        exit_code = ExitCode.INIT_FAILURE
    except LoginException as err:
        print(err, file=sys.stderr)
        exit_code = ExitCode.LOGIN_FAILURE
    except IgdownloaderException as err:
        print("Fatal error: %s" % err)
        exit_code = ExitCode.UNEXPECTED_ERROR
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
