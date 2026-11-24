"""Helpers for one explicitly authorized paid staging request. No secrets in reports."""
import json
import re


def verify_stage(status, version, commit):
    if (not re.fullmatch(r'[a-f0-9]{40}', commit)
            or status.get('version') != version or status.get('sourceCommit') != commit
            or status.get('status') != 'ok'):
        raise ValueError('Staging Backend does not match the exact release source')


def validate_stream(raw):
    if len(raw) > 8 * 1024 * 1024:
        raise ValueError('AI stream exceeds smoke-test limit')
    started = None
    done = None
    saw_text = False
    for frame in raw.replace('\r\n', '\n').split('\n\n'):
        if not frame.strip():
            continue
        name, data = None, []
        for line in frame.splitlines():
            if line.startswith('event: '):
                if name is not None:
                    raise ValueError('Duplicate event')
                name = line[7:]
            elif line.startswith('data: '):
                data.append(line[6:])
            elif not line.startswith(':'):
                raise ValueError('Invalid SSE frame')
        if name is None and not data:
            continue
        if done is not None:
            raise ValueError('Unexpected frame after completion')
        try:
            payload = json.loads('\n'.join(data))
        except (ValueError, TypeError):
            raise ValueError('Invalid SSE data') from None
        if not isinstance(payload, dict):
            raise ValueError('Invalid SSE object')
        if name == 'start' and started is None:
            started = payload.get('requestId')
            if not isinstance(started, str) or not re.fullmatch(r'[a-f0-9]{32}', started):
                raise ValueError('Invalid request ID')
        elif name == 'delta' and started and isinstance(payload.get('delta'), str):
            saw_text |= bool(payload['delta'])
        elif name == 'done' and started and payload.get('requestId') == started and payload.get('state') == 'completed':
            done = payload
        else:
            raise ValueError('AI stream did not complete successfully')
    if not started or not saw_text or done is None:
        raise ValueError('Incomplete AI stream')
    charge = done.get('chargedMicroUsd', 0)
    if type(charge) is not int or charge < 0:
        raise ValueError('Invalid AI charge')
    return charge


def verify_usage(before, after, charge):
    for row in (before, after):
        for key in ('requests', 'chargedMicroUsd', 'uncertainRequests'):
            if type(row.get(key)) is not int or row[key] < 0:
                raise ValueError('Invalid AI usage')
    if (after['requests'] != before['requests'] + 1
            or after['chargedMicroUsd'] != before['chargedMicroUsd'] + charge
            or after['uncertainRequests'] != before['uncertainRequests']):
        raise ValueError('AI budget did not settle exactly one request')


def paid_smoke(request, backend, access):
    # Dedicated idle staging account. Do not auto-retry a potentially billed POST.
    headers = {'Authorization': 'Bearer ' + access, 'Cache-Control': 'no-store'}
    def usage():
        response = request.get(backend + '/api/v1/ai/usage', headers=headers, max_redirects=0, timeout=15000)
        if response.status != 200:
            raise ValueError('AI usage unavailable')
        data = response.json()
        return data.get('data', data)['usage']
    before = usage()
    response = request.post(backend + '/api/v1/ai/responses', headers={**headers, 'Accept': 'text/event-stream'}, data={'prompt': 'Reply with the word OK.'}, max_redirects=0, timeout=110000)
    if response.status != 200 or not response.headers.get('content-type', '').startswith('text/event-stream'):
        raise ValueError('AI generation unavailable')
    charge = validate_stream(response.text())
    verify_usage(before, usage(), charge)
