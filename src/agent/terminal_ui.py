"""Local-only terminal workspace. No transport, evidence payloads or AI status.

Rendering is optional: a broken/redirected terminal must never break scanning.
Only measured counters and allowlisted lifecycle fields enter this view.
"""
from __future__ import annotations

import atexit
from collections import deque
import datetime
import os
import platform
import re
import shutil
import sys
import threading
import time
import unicodedata
from urllib.parse import urlsplit, urlunsplit


ESCAPES = re.compile(r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b\[[0-?]*[ -/]*[@-~]')
PHASES = ('discovery', 'crawling', 'analysis', 'finalizing')
LABELS = {'discovery': 'Discovery', 'crawling': 'Crawl & render',
          'analysis': 'Analysis', 'finalizing': 'Evidence delivery'}


def clean(value, limit=512):
    text = ESCAPES.sub('', str(value))[:limit]
    return ''.join(c for c in text if not unicodedata.category(c).startswith('C'))


def safe_url(value):
    try:
        parsed = urlsplit(clean(value))
        host = parsed.hostname or ''
        if ':' in host:
            host = '[' + host + ']'
        if parsed.port:
            host += ':' + str(parsed.port)
        return urlunsplit((parsed.scheme, host, parsed.path, '', ''))
    except ValueError:
        return 'URL unavailable'


def cells(text):
    return sum(0 if unicodedata.combining(c) else 2 if unicodedata.east_asian_width(c) in 'WF' else 1 for c in text)


def fit(text, width):
    text = clean(text)
    if cells(text) > width:
        result = ''
        for c in text:
            if cells(result + c) > max(0, width - 1):
                break
            result += c
        text = result + ('…' if width else '')
    return text + ' ' * max(0, width - cells(text))


def number(value):
    return value if type(value) is int and 0 <= value <= 10_000_000 else None


class AgentWorkspace:
    def __init__(self, stream=None, size=None, clock=time.monotonic):
        self.stream = stream or sys.stdout
        self.size = size or (lambda: shutil.get_terminal_size((100, 30)))
        self.clock = clock
        self.lock = threading.RLock()
        self.stop = threading.Event()
        self.thread = None
        self.active = False
        self.muted = False
        self._windows_console = None
        self.color = 'NO_COLOR' not in os.environ
        self.unicode = True
        try:
            '─│┌┐└┘…'.encode(getattr(self.stream, 'encoding', None) or 'utf-8')
        except UnicodeEncodeError:
            self.unicode = False
        self.agent_id = '—'
        self.backend = '—'
        self.version = '—'
        self.browser = 'Not started'
        self.connection = 'Starting'
        self.events = deque(maxlen=4)
        self.reset_scan()

    def reset_scan(self):
        if self.browser in ('Render complete', 'Rendering'):
            self.browser = 'Installed · starts during crawl'
        self.scan_id = ''
        self.target = 'Waiting for a scan assignment'
        self.started = None
        self.finished = None
        self.started_label = '—'
        self.state = 'Waiting'
        self.phase = None
        self.stages = {key: 'Waiting' for key in PHASES}
        self.counts = {}
        self.partial = False
        self.delivery = 'Not started'
        self.batch_index = 0

    def open(self, agent_id, backend, version):
        if self.active:
            return True
        if self.muted:
            return False
        self.agent_id, self.backend, self.version = clean(agent_id), safe_url(backend), clean(version)
        if not self.stream.isatty() or os.environ.get('TERM') == 'dumb':
            return False
        # Windows terminals need virtual-terminal processing enabled.
        if os.name == 'nt':
            try:
                import ctypes
                handle = ctypes.windll.kernel32.GetStdHandle(-11)
                mode = ctypes.c_uint()
                if not ctypes.windll.kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                    return False
                if not ctypes.windll.kernel32.SetConsoleMode(handle, mode.value | 4):
                    return False
                self._windows_console = (handle, mode.value)
            except (AttributeError, OSError):
                return False
        with self.lock:
            if self.active:
                return True
            self.stop = threading.Event()
            self.active = True
            try:
                self.stream.write('\x1b[?1049h\x1b[?25l')
                self.draw()
                self.thread = threading.Thread(target=self._refresh, args=(self.stop,), name='lhx-terminal', daemon=True)
                self.thread.start()
                return True
            except (OSError, ValueError):
                self.muted = True
                self.close()
                return False

    def _refresh(self, stop):
        previous = None
        while not stop.wait(.25):
            try:
                with self.lock:
                    if stop.is_set():
                        return
                    frame = self.render(*self.size())
                # A slow terminal write must not hold the scan snapshot lock.
                if frame != previous and not stop.is_set():
                    self.draw(frame)
                    previous = frame
            except Exception:
                with self.lock:
                    # Presentation failures do not propagate into the scanner.
                    self.muted = True
                    self.close()
                return

    def close(self):
        with self.lock:
            self.stop.set()
            if self.active:
                self.active = False
                try:
                    self.stream.write('\x1b[0m\x1b[?25h\x1b[?1049l')
                    self.stream.flush()
                except (OSError, ValueError):
                    pass
            if self._windows_console is not None:
                try:
                    import ctypes
                    handle, mode = self._windows_console
                    ctypes.windll.kernel32.SetConsoleMode(handle, mode)
                except (AttributeError, OSError):
                    pass
                self._windows_console = None

    def begin(self, scan_id, target):
        with self.lock:
            self.reset_scan()
            self.events.clear()
            self.scan_id, self.target = clean(scan_id), safe_url(target)
            self.started = self.clock()
            self.started_label = datetime.datetime.now().strftime('%H:%M:%S')
            self.state = 'Starting'
            self.connection = 'Assigned'
            self.note('scan', 'Scan received')

    def note(self, level, message):
        with self.lock:
            item = (datetime.datetime.now().strftime('%H:%M:%S'), clean(level, 16), clean(message, 256))
            if not self.events or self.events[-1][1:] != item[1:]:
                self.events.append(item)
            if level == 'waiting':
                self.connection = 'Retrying'
            elif level == 'ready':
                self.connection = 'Polling'
            elif level == 'idle':
                self.connection = 'Waiting'

    def terminal(self, status):
        with self.lock:
            if self.state in ('Completed', 'Failed', 'Cancelled'):
                return
            self.state = {'completed': 'Completed', 'cancelled': 'Cancelled'}.get(status, 'Failed')
            if self.phase and self.stages[self.phase] == 'Running':
                self.stages[self.phase] = self.state
            if self.state == 'Completed':
                self.delivery = 'Assignment ended'
            elif self.delivery == 'Sending':
                self.delivery = 'Pending recovery'
            self.finished = self.clock()

    def observe(self, event):
        if not isinstance(event, dict):
            return
        with self.lock:
            scan_id = event.get('scan_id')
            if scan_id and self.scan_id and scan_id != self.scan_id:
                return
            if self.state in ('Completed', 'Failed', 'Cancelled'):
                return
            data = event.get('data')
            if not isinstance(data, dict):
                return
            kind, phase = event.get('event_type'), data.get('phase')
            if phase == 'analyzing':
                phase = 'analysis'
            if kind in ('phase_started', 'scan_progress') and phase in PHASES:
                # Analysis summaries may arrive while evidence is being finalized.
                if self.phase is None or PHASES.index(phase) >= PHASES.index(self.phase):
                    self.phase = phase
                    self.state = 'Running'
                    if self.stages[phase] != 'Complete':
                        self.stages[phase] = 'Running'
                    if self.delivery == 'Not started':
                        self.delivery = 'Collecting'
                    if phase == 'finalizing':
                        self.delivery = 'Sending'
            if kind == 'phase_completed' and phase in PHASES:
                self.stages[phase] = 'Complete'
            if kind == 'crawling_completed':
                self.stages['crawling'] = 'Complete'
            if kind == 'discovery_completed':
                self.stages['discovery'] = 'Complete'
            if data.get('discovery_limited') is True or data.get('analysis_limited') is True or data.get('rendering_limited') is True:
                self.partial = True
            if data.get('substage') == 'rendering':
                status = data.get('rendering_status')
                if status in ('running', 'completed', 'unavailable', 'disabled'):
                    self.browser = {'running': 'Rendering', 'completed': 'Render complete',
                                    'unavailable': 'Unavailable · HTTP active', 'disabled': 'Disabled'}[status]
                    if status == 'unavailable':
                        self.partial = True
            # Only metrics from existing events. No raw finding/context is retained.
            aliases = {'processed_files': 'processed', 'current': 'processed', 'processed_js_files': 'processed',
                       'total_files': 'total', 'total': 'total', 'total_js_files': 'total',
                       'routes_discovered': 'routes', 'discovered_urls': 'routes', 'pages_fetched': 'pages',
                       'rendered_pages': 'rendered', 'browser_requests': 'requests',
                       'successful_analyses': 'successful', 'failed_analyses': 'failed',
                       'timed_out_analyses': 'timeouts', 'potential_secrets': 'secrets',
                       'total_secrets_found': 'secrets', 'discovered_endpoints': 'endpoints',
                       'total_endpoints_found': 'endpoints'}
            metrics = data.get('metrics')
            for source in (data, metrics if isinstance(metrics, dict) else {}):
                for field, name in aliases.items():
                    count = number(source.get(field))
                    if count is not None:
                        # Crawling total_files means discovered assets, not processed.
                        self.counts[name] = max(self.counts.get(name, 0), count)
            if kind == 'artifact_batch_ready':
                index = number(data.get('batch_index'))
                if index and index > self.batch_index:
                    self.batch_index = index
                    artifacts = data.get('artifacts')
                    if isinstance(artifacts, list):
                        for name, artifact_type in (('secrets', 'potential_secret'), ('endpoints', 'endpoint')):
                            count = sum(isinstance(a, dict) and a.get('type') == artifact_type for a in artifacts)
                            if count:
                                self.counts[name] = self.counts.get(name, 0) + count
            if kind == 'scan_completed':
                # Completion is displayed only after the existing transport flush.
                self.phase = 'finalizing'
                self.state = 'Running'
                self.stages['finalizing'] = 'Running'
                self.delivery = 'Sending'

    def delivered(self):
        self.terminal('completed')
        with self.lock:
            self.stages['finalizing'] = 'Complete'
            self.delivery = 'Acknowledged'
        self.note('completed', 'Local scan complete · evidence acknowledged')

    def render(self, columns, rows):
        with self.lock:
            width = max(1, min(180, columns - 1))
            available = max(1, rows - 1)
            count = lambda name: str(self.counts[name]) if name in self.counts else '—'
            elapsed = int((self.finished if self.finished is not None else self.clock()) - self.started) if self.started is not None else 0
            elapsed = f'{elapsed // 60:02d}:{elapsed % 60:02d}' if self.started is not None else '—'
            processed, total = self.counts.get('processed'), self.counts.get('total')
            percentage = min(100, int(processed * 100 / total)) if processed is not None and total else None
            measured = f'{count("processed")} / {count("total")} resources'
            bar_width = max(4, min(42, width - 38))
            filled = int(bar_width * percentage / 100) if percentage is not None else 0
            bar = '[' + '█' * filled + '░' * (bar_width - filled) + ']'
            progress = (f'{bar}  {percentage}%' if percentage is not None
                        else 'No JavaScript resources reported' if total == 0
                        else 'Resource counts not reported' if self.finished is not None
                        else 'Waiting for measured resource progress')
            stage = LABELS.get(self.phase, self.state)
            assessment = [f'Target   {self.target}', f'Scan ID  {self.scan_id or "—"}',
                          f'Started  {self.started_label}    Elapsed {elapsed}', '',
                          f'{stage} · {self.state}', progress, measured, '',
                          f'{count("routes")} routes  ·  {count("pages")} pages fetched',
                          f'{count("total")} JS resources  ·  {count("endpoints")} endpoint candidates',
                          f'{count("secrets")} secret candidates  ·  {count("successful")} analyzed successfully',
                          f'{count("failed")} unavailable/failed  ·  {count("timeouts")} timed out']
            environment = [f'Agent ID  {self.agent_id}', f'Assignments {self.connection}',
                           f'Browser   {self.browser}', f'Version   {self.version}',
                           f'Platform  {platform.system()} / {platform.machine()}',
                           f'Backend   {self.backend}', '',
                           'Evidence delivery', f'Status    {self.delivery}',
                           'Detection counts are candidates.', '',
                           f'Coverage  {"Partial" if self.partial else "Not yet assessed" if self.state != "Completed" else "No limitation reported"}',
                           f'{count("rendered")} pages rendered · {count("requests")} browser requests']
            lines = ['LeakHunterX  /  Local Agent Terminal', '']
            coverage = 'Partial' if self.partial else 'No limitation reported' if self.state == 'Completed' else 'Not yet assessed'
            if width >= 110 and available >= 28:
                left_width = int((width - 1) * .61)
                right_width = width - 1 - left_width
                height = max(len(assessment), len(environment))
                left = self.panel('Assessment', assessment + [''] * (height - len(assessment)), left_width)
                right = self.panel('Agent & Environment', environment + [''] * (height - len(environment)), right_width)
                lines += [l + ' ' + r for l, r in zip(left, right)]
            elif width >= 60 and available >= 25:
                lines += self.panel('Assessment', assessment[:7] + assessment[8:12], width)
                lines += self.panel('Agent & Environment', environment[1:4] + [f'Evidence: {self.delivery} · Coverage: {coverage}'], width)
            else:
                lines += [f'{self.state} · {stage}', f'Target  {self.target}',
                          f'Scan    {self.scan_id or "—"}', progress, measured,
                          f'Elapsed {elapsed} · Delivery {self.delivery}',
                          f'Browser {self.browser}',
                          f'{count("secrets")} secrets · {count("endpoints")} endpoints (candidates)',
                          f'OK {count("successful")} · Failed {count("failed")} · Timeout {count("timeouts")}',
                          f'Coverage: {coverage}']
            if available >= 28:
                lines += ['']
                stage_line = '  '.join(f'{LABELS[p]}: {self.stages[p]}' for p in PHASES)
                if cells(stage_line) <= width:
                    lines.append(stage_line)
                else:
                    # Keep every stage visible in the stacked layout.
                    for first, second in ((PHASES[0], PHASES[1]), (PHASES[2], PHASES[3])):
                        pair = f'{LABELS[first]}: {self.stages[first]}  {LABELS[second]}: {self.stages[second]}'
                        lines += [pair] if cells(pair) <= width else [f'{LABELS[first]}: {self.stages[first]}', f'{LABELS[second]}: {self.stages[second]}']
            event_rows = max(0, min(4, available - len(lines) - 4))
            if event_rows:
                activity = [f'{t}  {level.upper():<10} {message}' for t, level, message in list(self.events)[-event_rows:]]
                lines += self.panel('Recent activity', activity or ['Waiting for agent activity'], width)
            lines += ['Ctrl+C to stop · Detailed findings and reports are in your dashboard']
            lines = [fit(line, width).rstrip() for line in lines[:available]]
            if not self.unicode:
                mapping = str.maketrans({'─': '-', '█': '#', '░': '-', '│': '|', '┌': '+', '┐': '+', '└': '+', '┘': '+', '·': '|', '…': '.', '—': '-'})
                lines = [line.translate(mapping) for line in lines]
            if self.color:
                colored = []
                for i, line in enumerate(lines):
                    code = ('1;97' if i == 0 else '91' if 'Failed' in line or 'Cancelled' in line
                            else '92' if 'Acknowledged' in line or 'Local scan complete' in line
                            else '96' if line.startswith(('┌', '+', '[')) else '97')
                    colored.append(f'\x1b[{code}m{line}\x1b[0m')
                lines = colored
            return '\n'.join(lines)

    @staticmethod
    def panel(title, content, width):
        inner = max(0, width - 4)
        top = '┌' + (' ' + title + ' ').ljust(max(0, width - 2), '─')[:max(0, width - 2)] + '┐'
        return [top] + ['│ ' + fit(line, inner) + ' │' for line in content] + ['└' + '─' * max(0, width - 2) + '┘']

    def draw(self, frame=None):
        if self.active:
            # Erase each line's old tail when a metric or terminal width shrinks.
            self.stream.write('\x1b[H' + (frame if frame is not None else self.render(*self.size())).replace('\n', '\x1b[K\r\n') + '\x1b[J')
            self.stream.flush()


workspace = AgentWorkspace()
atexit.register(workspace.close)
