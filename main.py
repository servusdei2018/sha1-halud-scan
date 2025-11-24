#!/usr/bin/env python3
"""
CLI tool for scanning GitHub users' public repos for indicators of shai-hulud compromise.

Usage:
    python main.py scan-file users.txt --token <GITHUB_TOKEN> --workers 10
    python main.py scan-org <orgname> --token <GITHUB_TOKEN> --workers 10
"""

from __future__ import annotations

import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Tuple

import click
import requests
from colorama import Fore, Style, init

init(autoreset=True)

DEFAULT_WORKERS = 5
REQUEST_TIMEOUT = 10  # seconds


def _get_headers(token: Optional[str]) -> dict:
    """Build headers used for GitHub API requests."""
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "shai-hulud-scan/0.1",
    }
    if token:
        headers["Authorization"] = f"token {token.strip()}"
    return headers


def load_usernames(file_path: str) -> List[str]:
    """
    Load a list of usernames from a file (one username per line).

    Ignores blank lines and strips whitespace.
    """
    with open(file_path, "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip()]


def load_org_members(org_name: str, token: Optional[str] = None) -> List[str]:
    """
    Load a list of organization members (by login) for the given GitHub organization.

    This uses the org members endpoint and returns the `login` value for each
    member found. It handles pagination and raises ValueError on API or permission
    errors (including rate limits).
    """
    headers = _get_headers(token)
    url = f"https://api.github.com/orgs/{org_name}/members"
    params = {"per_page": 100, "page": 1}
    members: List[str] = []

    try:
        while True:
            response = requests.get(
                url, headers=headers, params=params, timeout=REQUEST_TIMEOUT
            )

            if response.status_code == 404:
                raise ValueError("Organization not found")
            if response.status_code == 401:
                raise ValueError("Unauthorized (invalid token?)")
            if response.status_code == 403:
                msg = None
                try:
                    msg = response.json().get("message")
                except Exception:
                    msg = response.text or "Forbidden (403)"

                if msg and "rate limit" in msg.lower():
                    reset_ts = response.headers.get("X-RateLimit-Reset")
                    reset_at = _format_rate_limit_reset(reset_ts)
                    raise ValueError(f"API Rate Limit Exceeded; resets at {reset_at}")
                else:
                    raise ValueError(msg or "Forbidden (403)")

            if response.status_code != 200:
                raise ValueError(f"HTTP {response.status_code}")

            page_members = response.json()
            for member in page_members:
                login = member.get("login")
                if login:
                    members.append(login)

            if "next" in response.links:
                params["page"] += 1
                continue

            break

    except requests.RequestException as e:
        raise ValueError(str(e))

    return members


def _format_rate_limit_reset(reset_ts: Optional[str]) -> str:
    """
    Convert the X-RateLimit-Reset value into a human-readable time string.
    """
    if not reset_ts:
        return "unknown"
    try:
        reset_ts_int = int(reset_ts)  # epoch seconds
        readable = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(reset_ts_int))
        return f"{readable}"
    except Exception:
        return reset_ts


def check_user(username: str, token: Optional[str] = None) -> Tuple[str, Optional[str]]:
    """
    Scans a user's public repositories for compromise indicators.

    Args:
        username (str): GitHub username to scan.
        token (Optional[str]): GitHub personal access token to increase rate limits.

    Returns:
        tuple: (status, data)
            status: "FLAG" if found, "OKAY" if not found, "ERROR" for errors.
            data: For "FLAG", the repo URL; for "ERROR", an error message.
    """
    username = username.strip()
    if not username:
        return "ERROR", "Empty username"

    headers = _get_headers(token)
    url = f"https://api.github.com/users/{username}/repos"
    params = {"per_page": 100, "page": 1}

    try:
        while True:
            response = requests.get(
                url, headers=headers, params=params, timeout=REQUEST_TIMEOUT
            )

            if response.status_code == 404:
                return "ERROR", "User not found"
            if response.status_code == 401:
                return "ERROR", "Unauthorized (invalid token?)"
            if response.status_code == 403:
                msg = None
                try:
                    msg = response.json().get("message")
                except Exception:
                    msg = response.text or "Forbidden (403)"

                if msg and "rate limit" in msg.lower():
                    reset_ts = response.headers.get("X-RateLimit-Reset")
                    reset_at = _format_rate_limit_reset(reset_ts)
                    return "ERROR", f"API Rate Limit Exceeded; resets at {reset_at}"
                else:
                    return "ERROR", msg

            if response.status_code != 200:
                return "ERROR", f"HTTP {response.status_code}"

            repos = response.json()
            for repo in repos:
                description = repo.get("description") or ""
                if "Sha1-Hulud: The Second Coming." in description:
                    return "FLAG", repo.get("html_url")

            if "next" in response.links:
                params["page"] += 1
                continue

            return "OKAY", None

    except requests.RequestException as e:
        return "ERROR", str(e)


def _print_status(username: str, status: str, data: Optional[str]) -> None:
    if status == "FLAG":
        click.echo(f"{Fore.RED}[FLAG] {username} compromised: {data}")
    elif status == "OKAY":
        click.echo(f"{Fore.GREEN}[OKAY] {username}")
    elif status == "ERROR":
        click.echo(f"{Fore.YELLOW}[ERROR] {username}: {data}")
    else:
        click.echo(f"{Fore.YELLOW}[UNKNOWN] {username}: {data}")


@click.group(help="shai-hulud scanner CLI")
def cli() -> None:
    pass


@cli.command(name="scan-file")
@click.argument(
    "users_file", type=click.Path(exists=True, dir_okay=False, readable=True)
)
@click.option(
    "--token",
    "-t",
    default=None,
    help="GitHub personal access token. Optional. Can also be provided through the GITHUB_TOKEN env var.",
    show_default=False,
)
@click.option(
    "--workers",
    "-w",
    default=DEFAULT_WORKERS,
    show_default=True,
    help="Number of concurrent workers to use when scanning.",
)
def scan_file(users_file: str, token: Optional[str], workers: int) -> None:
    """
    Scan users for shai-hulud compromise indicators.

    Args:
        users_file (str): Path to a file containing GitHub usernames (one per line).
        token (Optional[str]): GitHub personal access token.
        workers (int): Number of concurrent workers to use.
    """
    token = token or os.environ.get("GITHUB_TOKEN")
    try:
        usernames = load_usernames(users_file)
    except FileNotFoundError:
        click.echo(
            f"{Fore.RED}[ERROR] Could not find '{users_file}'. Please provide a valid file.",
            err=True,
        )
        sys.exit(1)
    except Exception as e:
        click.echo(f"{Fore.RED}[ERROR] Could not read '{users_file}': {e}", err=True)
        sys.exit(1)

    num_users = len(usernames)
    click.echo(
        f"{Style.BRIGHT}Starting scan for shai-hulud on {num_users} users...{Style.RESET_ALL}\n"
    )

    if num_users == 0:
        click.echo(f"{Fore.YELLOW}[INFO] No users to scan. Exiting.")
        sys.exit(0)

    workers = max(1, min(workers, num_users))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_user = {
            executor.submit(check_user, user, token): user for user in usernames
        }
        for future in as_completed(future_to_user):
            user = future_to_user[future]
            try:
                status, data = future.result()
            except Exception as e:
                status, data = "ERROR", str(e)
            _print_status(user, status, data)


@cli.command(name="scan-org")
@click.argument("org", type=str)
@click.option(
    "--token",
    "-t",
    default=None,
    help="GitHub personal access token. Optional. Can also be provided through the GITHUB_TOKEN env var.",
    show_default=False,
)
@click.option(
    "--workers",
    "-w",
    default=DEFAULT_WORKERS,
    show_default=True,
    help="Number of concurrent workers to use when scanning.",
)
def scan_org(org: str, token: Optional[str], workers: int) -> None:
    """
    Scan every member in a GitHub organization for shai-hulud compromise indicators.

    Args:
        org (str): Organization name.
        token (Optional[str]): GitHub personal access token.
        workers (int): Number of concurrent workers to use.
    """
    token = token or os.environ.get("GITHUB_TOKEN")
    try:
        members = load_org_members(org, token)
    except ValueError as e:
        click.echo(
            f"{Fore.RED}[ERROR] Could not load members for org '{org}': {e}", err=True
        )
        sys.exit(1)
    except Exception as e:
        click.echo(
            f"{Fore.RED}[ERROR] Could not load members for org '{org}': {e}", err=True
        )
        sys.exit(1)

    num_users = len(members)
    click.echo(
        f"{Style.BRIGHT}Starting scan for shai-hulud on {num_users} users from org '{org}'...{Style.RESET_ALL}\n"
    )

    if num_users == 0:
        click.echo(f"{Fore.YELLOW}[INFO] No users to scan. Exiting.")
        sys.exit(0)

    workers = max(1, min(workers, num_users))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_user = {
            executor.submit(check_user, user, token): user for user in members
        }
        for future in as_completed(future_to_user):
            user = future_to_user[future]
            try:
                status, data = future.result()
            except Exception as e:
                status, data = "ERROR", str(e)
            _print_status(user, status, data)


if __name__ == "__main__":
    cli()
