"""Finite public diagnostics; provider bodies and credentials never become events."""
GITHUB_FAILURES = {
    'github_signing_unavailable': 'GitHub App signing failed. Check the complete private key and matching App ID on the backend.',
    'github_configuration_unavailable': 'GitHub App configuration is unavailable on the backend.',
    'github_authorization_unavailable': 'GitHub authorization is unavailable. Reconnect GitHub and check repository access.',
    'github_permissions_invalid': 'Approve read-only Contents and Metadata permissions for the GitHub App installation.',
    'github_access_restricted': 'GitHub access is restricted or rate limited. Check installation access and retry later.',
    'github_access_unavailable': 'Temporary repository access could not be obtained. Check backend and GitHub connectivity.',
    'github_response_invalid': 'The backend returned invalid temporary repository access. Check backend and agent versions.',
    'github_scope_changed': 'Repository authorization changed. Configure the repository again before scanning.',
}


class GitHubScanError(RuntimeError):
    def __init__(self, reason):
        self.reason = reason if reason in GITHUB_FAILURES else 'github_access_unavailable'
        super().__init__(GITHUB_FAILURES[self.reason])


# Match only application-owned messages, never interpolate a response body.
ACCESS_ERRORS = {
    'GitHub App signing configuration is unavailable': 'github_signing_unavailable',
    'GitHub App connection is not configured in this environment': 'github_configuration_unavailable',
    'GitHub authorization or repository access is unavailable; reconnect GitHub': 'github_authorization_unavailable',
    'Connect GitHub in Settings before selecting a repository': 'github_authorization_unavailable',
    'Reconnect GitHub to restore authorization': 'github_authorization_unavailable',
    'GitHub authorization expired or was declined. Connect again.': 'github_authorization_unavailable',
    'GitHub App requires only read-only Contents and Metadata permissions': 'github_permissions_invalid',
    'GitHub access is restricted or rate limited. Retry later or review authorization.': 'github_access_restricted',
    'Repository authorization changed': 'github_scope_changed',
    'Repository installation authorization changed': 'github_scope_changed',
    'Repository identity changed. Configure a new target.': 'github_scope_changed',
    'GitHub returned invalid temporary authorization': 'github_response_invalid',
}


def access_failure(response):
    reason = response.headers.get('X-LHX-GitHub-Error')
    if reason in GITHUB_FAILURES:
        return GitHubScanError(reason)
    if len(response.content) <= 12000:
        try:
            value = response.json()
            detail = value.get('detail') if isinstance(value, dict) else None
            if isinstance(detail, str) and detail in ACCESS_ERRORS:
                return GitHubScanError(ACCESS_ERRORS[detail])
        except ValueError:
            pass
    reason = ('github_authorization_unavailable' if response.status_code in (401, 403, 404, 409)
              else 'github_access_unavailable')
    return GitHubScanError(reason)
