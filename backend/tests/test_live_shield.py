import urllib.request
import urllib.error
import json

def fetch(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, resp.read().decode('utf-8', errors='ignore')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', errors='ignore')

def main():
    print('--- Test 1: Clean Traffic Forwarding ---')
    status, body = fetch('http://127.0.0.1:8000/gateway/')
    print(f'Clean Request: Status={status}, Body Length={len(body)}')
    assert status == 200, f"Expected 200, got {status}"

    print('\n--- Test 2: SQL Injection Interception ---')
    sqli_url = 'http://127.0.0.1:8000/gateway/api/products?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--'
    status, body = fetch(sqli_url)
    print(f'SQLi Probe: Status={status}, Has Intrusion Header={"Security Intrusion Intercepted" in body}')
    assert status == 403, f"Expected 403, got {status}"

    print('\n--- Test 3: Active IP Quarantine Jail Enforcement ---')
    # The subsequent request (even clean) must be dropped at perimeter because 127.0.0.1 is quarantined
    status, body = fetch('http://127.0.0.1:8000/gateway/')
    print(f'Subsequent Probe: Status={status}, In Jail={"Perimeter IP Quarantine Active" in body}')
    assert status == 403, f"Expected 403, got {status}"
    assert 'Perimeter IP Quarantine Active' in body

    print('\n--- Test 4: Quarantine Status API ---')
    status, body = fetch('http://127.0.0.1:8000/api/monitoring/quarantine')
    q_data = json.loads(body)
    print(f'Quarantined count: {q_data["count"]}')
    assert q_data['count'] > 0

    print('\n--- Test 5: Unban IP via API ---')
    unban_data = json.dumps({'client_ip': '127.0.0.1'}).encode('utf-8')
    unban_req = urllib.request.Request(
        'http://127.0.0.1:8000/api/monitoring/quarantine/unban',
        data=unban_data,
        headers={'Content-Type': 'application/json'},
        method='POST'
    )
    with urllib.request.urlopen(unban_req) as resp:
        res = json.loads(resp.read().decode())
        print('Unban result:', res)

    print('\n--- Test 6: Verify Traffic Allowed after Unban ---')
    status, body = fetch('http://127.0.0.1:8000/gateway/')
    print(f'Post-Unban Clean Request: Status={status}')
    assert status == 200

    print('\n--- Test 7: Sensitive File Probing (.env) ---')
    status, body = fetch('http://127.0.0.1:8000/gateway/.env')
    print(f'.env Probe: Status={status}, Blocked={status == 403}')
    assert status == 403

    # Unban again for subsequent tests
    unban_req2 = urllib.request.Request(
        'http://127.0.0.1:8000/api/monitoring/quarantine/unban',
        data=unban_data,
        headers={'Content-Type': 'application/json'},
        method='POST'
    )
    urllib.request.urlopen(unban_req2)

    print('\n--- Test 8: Scanner Bot Detection (User-Agent: sqlmap) ---')
    status, body = fetch('http://127.0.0.1:8000/gateway/products', headers={'User-Agent': 'sqlmap/1.7#stable'})
    print(f'Scanner Probe: Status={status}, Blocked={status == 403}')
    assert status == 403

    # Unban again
    urllib.request.urlopen(unban_req2)

    print('\n🎉 ALL 8 SECURITY VERIFICATION TESTS PASSED PERFECTLY!')

if __name__ == '__main__':
    main()
