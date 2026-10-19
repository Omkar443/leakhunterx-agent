"""Finite archive failure messages; never display provider bodies or source text."""

HISTORICAL_FAILURES = {
    'archive_unavailable': 'The archive provider could not supply the requested archive content. Historical coverage is incomplete.',
    'archive_timeout': 'The archive provider did not respond before the archive request timed out. Retry later or select a shorter period.',
    'archive_service_unavailable': 'The archive provider returned a server error. Historical coverage is incomplete; retry later.',
    'archive_network_error': 'The agent could not reach the archive provider. Check agent connectivity and retry.',
    'archive_rate_limited': 'The archive provider rate limited archive requests. Wait before starting another historical scan.',
    'archive_access_denied': 'The archive provider refused access to the requested archive content.',
    'archive_invalid_response': 'The archive provider returned an unsupported or invalid archive response.',
    'archive_response_limit': 'An archive response exceeded the safe response size limit.',
    'archive_scope_refused': 'An archive redirect was refused by the authorized scope checks.',
    'archive_discovery_incomplete': 'Archive discovery reached its safe request or time budget. Historical coverage is incomplete.',
    'archive_no_captures': 'No supported archive captures were returned for this target and period. Historical coverage was not established.',
    'historical_budget_exhausted': 'Historical assessment reached its authorized resource budget. Historical coverage is incomplete.',
    'historical_analysis_unavailable': 'Historical analysis could not complete. Incomplete results are excluded.',
}

CONTENT_FAILURES = {
    'budget_limit': 'historical_budget_exhausted',
    'rate_limited': 'archive_rate_limited',
    'invalid_content': 'archive_invalid_response',
    'response_limit': 'archive_response_limit',
    'scope_refused': 'archive_scope_refused',
}
