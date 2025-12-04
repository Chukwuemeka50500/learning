#!/usr/bin/env python3
"""
Fetch your top N GitHub repositories sorted by stargazers count.

Usage:
  - Set an environment variable GITHUB_TOKEN (recommended) containing a personal access token
    with "repo" scope if you want private repos included, or no scope for public repos only.
  - Or pass a token via --token (less secure).

Examples:
  GITHUB_TOKEN=ghp_xxx python top_repos_by_stars.py
  python top_repos_by_stars.py --username octocat --top 5
  python top_repos_by_stars.py --top 10 --json

What it does:
  - If no --username is provided, it authenticates and fetches the authenticated user's repos
    (using /user/repos) which includes private repos if token allows.
  - If --username is provided it fetches that user's public repos (using /users/:username/repos).
  - Handles pagination, sorts by stargazers_count descending, and prints the top N repos.
"""

import os
import sys
import argparse
import requests
import time
import json
from typing import List, Dict, Optional

GITHUB_API = "https://api.github.com"


def get_auth_headers(token: Optional[str]) -> Dict[str, str]:
    headers = {"Accept": "application/vnd.github.v3+json", "User-Agent": "top-repos-script/1.0"}
    if token:
        headers["Authorization"] = f"token {token}"
    return headers


def get_authenticated_username(token: str) -> Optional[str]:
    """Return the authenticated user's login, or None on failure."""
    resp = requests.get(f"{GITHUB_API}/user", headers=get_auth_headers(token))
    if resp.status_code == 200:
        return resp.json().get("login")
    return None


def fetch_repos_for_authenticated_user(token: Optional[str]) -> List[Dict]:
    """
    Fetch all repositories for the authenticated user (owner repos).
    This endpoint will include private repos if token has access.
    """
    headers = get_auth_headers(token)
    repos = []
    params = {"per_page": 100, "page": 1, "type": "owner", "sort": "full_name"}
    while True:
        resp = requests.get(f"{GITHUB_API}/user/repos", headers=headers, params=params)
        if resp.status_code == 401:
            raise RuntimeError("Unauthorized: invalid or missing token for authenticated user endpoint.")
        if resp.status_code != 200:
            raise RuntimeError(f"Failed to fetch repos: {resp.status_code} {resp.text}")
        page_items = resp.json()
        if not page_items:
            break
        repos.extend(page_items)
        if "next" not in resp.links:
            break
        params["page"] += 1
        # be friendly to the API
        time.sleep(0.1)
    return repos


def fetch_repos_for_user(username: str, token: Optional[str]) -> List[Dict]:
    """
    Fetch public repositories for a given username.
    (Authenticated requests get a higher rate limit.)
    """
    headers = get_auth_headers(token)
    repos = []
    params = {"per_page": 100, "page": 1, "type": "owner", "sort": "full_name"}
    while True:
        resp = requests.get(f"{GITHUB_API}/users/{username}/repos", headers=headers, params=params)
        if resp.status_code == 404:
            raise RuntimeError(f"User '{username}' not found (404).")
        if resp.status_code != 200:
            raise RuntimeError(f"Failed to fetch repos for {username}: {resp.status_code} {resp.text}")
        page_items = resp.json()
        if not page_items:
            break
        repos.extend(page_items)
        if "next" not in resp.links:
            break
        params["page"] += 1
        time.sleep(0.1)
    return repos


def top_repos_by_stars(repos: List[Dict], top_n: int) -> List[Dict]:
    sorted_repos = sorted(repos, key=lambda r: r.get("stargazers_count", 0), reverse=True)
    return sorted_repos[:top_n]


def short_repo_info(repo: Dict) -> Dict:
    return {
        "name": repo.get("full_name") or repo.get("name"),
        "html_url": repo.get("html_url"),
        "stars": repo.get("stargazers_count", 0),
        "forks": repo.get("forks_count", 0),
        "description": repo.get("description") or "",
        "private": repo.get("private", False),
    }


def main(argv):
    parser = argparse.ArgumentParser(description="Fetch top N GitHub repos by star count.")
    parser.add_argument("--token", "-t", help="GitHub personal access token (optional). If not provided, uses GITHUB_TOKEN env var.")
    parser.add_argument("--username", "-u", help="GitHub username to fetch repos for. If omitted, the authenticated user is used.")
    parser.add_argument("--top", "-n", type=int, default=5, help="How many top repos to show (default 5).")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON of the top repos.")
    args = parser.parse_args(argv)

    token = args.token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    # If username not provided, prefer the authenticated user's repos (so private repos can be included)
    try:
        if args.username:
            username = args.username
            repos = fetch_repos_for_user(username, token)
        else:
            if not token:
                print("No token provided and no username specified; fetching public repos for an unauthenticated user is rate-limited.")
            # attempt to get authenticated username if token present
            if token:
                auth_username = get_authenticated_username(token)
                if auth_username:
                    username = auth_username
                    repos = fetch_repos_for_authenticated_user(token)
                else:
                    # fallback: fetch public repos for the username you supplied (none)
                    raise RuntimeError("Failed to determine authenticated user from token.")
            else:
                raise RuntimeError("No username specified and no GITHUB_TOKEN available. Provide one or pass --username <user>.")
    except RuntimeError as exc:
        print("Error:", exc, file=sys.stderr)
        sys.exit(2)

    if not repos:
        print("No repositories found.")
        return

    top = top_repos_by_stars(repos, args.top)
    output = [short_repo_info(r) for r in top]

    if args.json:
        print(json.dumps(output, indent=2))
        return

    # Human readable output
    print(f"Top {len(output)} repositories by stars for " +
          (f"'{args.username}'" if args.username else f"authenticated user '{username}'") + ":")
    for idx, repo in enumerate(output, start=1):
        private_flag = " (private)" if repo["private"] else ""
        print(f"{idx}. {repo['name']}{private_flag}")
        print(f"   stars: {repo['stars']}  forks: {repo['forks']}")
        if repo["description"]:
            print(f"   {repo['description']}")
        print(f"   {repo['html_url']}")
        print()

if __name__ == "__main__":
    main(sys.argv[1:])
