# shai-hulud scanner

Scans GitHub profiles/organizations for indicators of [shai-hulud](https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains) compromise.

## Usage

This tool supports scanning either a newline-separated file of GitHub usernames or scanning all the members of a GitHub organization.

### Scan usernames from a file

1. Create a text file and populate it with GitHub usernames you want to scan, one username per line. For example, create a file named `users.txt`:
```
user1
user2
user3
```

2. Run the `scan-file` command with the path to your text file:
```bash
uv run main.py scan-file users.txt
```

- To use a [GitHub token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#creating-a-fine-grained-personal-access-token) (recommended to avoid rate limiting):
```bash
uv run main.py scan-file users.txt --token YOUR_GITHUB_TOKEN
```

- To change the number of concurrent workers (defaults to 5):
```bash
uv run main.py scan-file users.txt --workers 10
```

### Scan an organization

To scan every member of an organization, use the `scan-org` command and specify the organization name. The scanner will fetch public members for the organization and then scan each user's public repositories:

```bash
uv run main.py scan-org my-org
```

- To use a token and control workers:
```bash
uv run main.py scan-org my-org --token YOUR_GITHUB_TOKEN --workers 10
```

> [!NOTE]
> Only public organization members are returned by the public organization members API. If you need private membership visibility, [supply a token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#creating-a-fine-grained-personal-access-token) with appropriate permissions.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
