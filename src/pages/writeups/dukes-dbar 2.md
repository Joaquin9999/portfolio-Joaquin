---
layout: ../../layouts/WriteupLayout.astro
title: "Duke's DBAR Writeup"
pageTitle: "Duke's DBAR Writeup"
description: "Forensics writeup: Grafana log + SQLite correlation, CVE-2024-9264."
---

# Duke's DBAR Writeup

## Summary

This challenge can be solved by correlating the Grafana application log with the Grafana SQLite database:

1. The log shows the malicious query activity and source IP.
2. The database maps the user ID to the Grafana login.
3. The vulnerable feature is identifiable from the query pattern and Grafana version.

Artifacts:

- `/Users/neji21/Documents/forense/retos/dukes_dbar/grafana.log`
- `/Users/neji21/Documents/forense/retos/dukes_dbar/grafana.db`

## Initial Triage

List the SQLite tables and inspect the users:

```sh
sqlite3 /Users/neji21/Documents/forense/retos/dukes_dbar/grafana.db '.tables'
sqlite3 -header -column /Users/neji21/Documents/forense/retos/dukes_dbar/grafana.db \
  'select id,login,email,is_admin,created,updated from user;'
```

Relevant users include:

- `admin`
- `viewer1`
- `editor1`
- `sa-1-checkup`
- `editor2`

## Find The Malicious Query

Search the log for file-read primitives and auth activity:

```sh
rg -n "read_blob|User auth token created|clientIP|python-requests" \
  /Users/neji21/Documents/forense/retos/dukes_dbar/grafana.log
```

The key lines show two SQL Expressions queries:

```text
SELECT content FROM read_blob('/etc/passwd')
SELECT content FROM read_blob('/var/lib/grafana/ctf/secret.csv')
```

The same log region shows:

- `userID=5`
- `clientIP=85.215.144.254`
- `userAgent=python-requests/2.31.0`

This establishes:

- the attacker probed with `/etc/passwd`
- the real exfiltration target was `/var/lib/grafana/ctf/secret.csv`
- the source IP was `85.215.144.254`

## Resolve The Username

Map `userID=5` back to the Grafana login:

```sh
sqlite3 -header -column /Users/neji21/Documents/forense/retos/dukes_dbar/grafana.db \
  'select id,login,email,name,is_admin from user where id=5;'
```

Output:

```text
5   editor2   editor2@ctf.local   editor2   0
```

So the Grafana login used for the malicious actions was `editor2`.

## Identify The CVE

Check the Grafana version in the log:

```sh
rg -n "Starting Grafana" /Users/neji21/Documents/forense/retos/dukes_dbar/grafana.log
```

The instance reports `version=11.0.0`.

The observed exploit path is SQL Expressions using DuckDB-style `read_blob()` to read local files. This matches `CVE-2024-9264`.

## Flag

```text
MCTF{CVE-2024-9264:/var/lib/grafana/ctf/secret.csv:85.215.144.254:editor2}
```
