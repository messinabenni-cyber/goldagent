# Scope of Work — VoIP Penetration Test

> Fill in, sign, store. Provide to `voip_scan.py --scope-file`. Its SHA-256
> is logged in every report as proof of authorisation.

## 1. Parties

| Field           | Value                              |
|-----------------|------------------------------------|
| Client name     |                                    |
| Client contact  | (name, role, email, phone)         |
| Operator        |                                    |
| Operator org    |                                    |
| Engagement date | (start) – (end)                    |

## 2. Authorised Targets

List every IP, CIDR, hostname, and port range in scope. Targets NOT listed
are out of scope and must not be probed.

```
10.0.0.0/24
pbx.client.example.com
```

## 3. Authorised Actions

Tick the actions explicitly authorised. Unticked actions must not be performed.

- [ ] Network/port discovery
- [ ] SIP extension enumeration
- [ ] Credential spray against discovered extensions (with lockout guard)
- [ ] AMI default-credential testing (TCP/5038)
- [ ] Toll-fraud proof-of-concept call (DRY-RUN — provisional only)
- [ ] Toll-fraud proof-of-concept call (FULL — reaches 200 OK)
- [ ] SRTP downgrade testing
- [ ] Other (specify): _________________________

## 4. Out of Scope

- Emergency services (911 / 999 / 112 / etc.)
- Production data exfiltration
- Persistent backdoor installation
- Denial of service
- Pivoting to non-listed networks

## 5. Test Call Destinations

Numbers the operator may dial during PoC calls. **The operator must own
or control every number listed.**

```
+447900900900
```

## 6. Engagement Window

| Field          | Value                              |
|----------------|------------------------------------|
| Start          | YYYY-MM-DD HH:MM (timezone)        |
| End            | YYYY-MM-DD HH:MM (timezone)        |
| Quiet hours    | (when NOT to scan)                 |
| Notify on hit  | (email/phone — for critical finds) |

## 7. Sign-off

| Client (asset owner) | Operator |
|----------------------|----------|
|                      |          |
| Name + signature     | Name + signature |
| Date:                | Date:    |
