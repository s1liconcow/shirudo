# app-sandbox

The `app-sandbox` package installs the `app-sandbox` upatch, which puts
applications in sandboxes. A sandbox restricts every task that executed
one of its files, and the tasks those start, in three things:

- what it executes: its own files and those of the policies it names;
- where it connects and sends: the networks it names;
- which files it creates, renames and opens for writing or truncates:
  none whose name matches a pattern it denies.

The package ships sandboxes for Apache httpd and PHP-FPM that keep a web
application from writing the PHP files it serves, from starting other
programs and from reaching beyond private networks: what an attacker
who found a hole in the application does first. Replace them with
sandboxes for your own applications.

Its tree entry names the PHP2Shell advisories, CVE-2026-109618 and
CVE-2026-109619, as `fixes`, so that a backend that reads the tree
counts a node that loaded the upatch as shielded against them. The
sandboxes do not close the hole in PHP: a request can still run the
attacker's code in the application. They keep that code from leaving a
PHP file behind, from running another program and from connecting out.
Upgrade PHP as well.

A sandbox restricts and never grants: a task in it keeps every limit it
had. It is not a boundary against root outside the sandbox, and a file
replaced after the load is a new file without the label, see "Limits".

## Define a sandbox

A sandbox has two parts. The `Beefile` gives it a name, a policy bit and
the executables that put a task in it, as a `[[upatches.policy]]` table
(see `Documentation/reference/formats/beefile.rst`):

```toml
[[upatches.policy]]
id = "apache"
bit = 0x1
paths = ["/usr/sbin/apache2", "/usr/sbin/httpd"]
```

The last component of a path may be a pattern, as in
`/usr/sbin/php-fpm*` for the PHP-FPM of any version: the target labels
every regular file of the directory that matches it.

`sandbox.toml` gives the rules of the sandbox of that name:

```toml
[networks]
localnet = ["127.0.0.0/8", "10.0.0.0/8", "::1/128"]

[sandbox.apache]
exec = ["apache-helpers"]
network = ["@localnet", "192.0.2.10/32"]

[sandbox.apache.deny]
create = ["*.php"]
rename = ["*.php"]
write = ["*.php"]
```

| Key | Without it | With it |
|---|---|---|
| `exec` | The task executes anything. | It executes only files labeled with its own policy or with one of the policy IDs listed, each a `[[upatches.policy]]` table of the Beefile. `exec = []` allows its own files alone. |
| `network` | The task connects anywhere. | It connects and sends only to the networks listed, IPv4 or IPv6 in CIDR form, or `@<name>` for a list of `[networks]`. An IPv4 network also covers its IPv4-mapped IPv6 form. It creates no raw and no packet socket. `network = []` allows no IP peer. |
| `deny.create` | | It creates no file, directory, device, symbolic link or hard link with a matching name. |
| `deny.rename` | | It renames no file from or to a matching name. |
| `deny.write` | | It opens no file with a matching name for writing and does not truncate one. |

A pattern is matched against the last component of the path. It is the
name itself, or holds one `*` for any run of bytes, and `?` for any one
byte, with at most 32 bytes on each side of the `*`.

A script is executed with its interpreter, and the kernel asks for
both: a sandbox with `exec` runs a script only when the script and its
interpreter are each labeled with a policy the sandbox allows.

The package holds up to 32 sandboxes with `exec`, 128 networks and 64
patterns. A task in two sandboxes, one that executed files of both, is
held to the rules of each.

`gen_policy.py` turns `sandbox.toml` into the `sandbox_policy` variable
of the upatch when `shirudo bpm build` runs, and fails the build for a
sandbox the Beefile declares no policy for, a network or a pattern it
cannot read and a table it does not know. Read back what a build holds
with:

```sh
shirudo bpm info data app-sandbox-<version>.bee upatches/app-sandbox.upatch
```

## Build and publish

Build in a directory that holds shirudo's BPF headers and a `vmlinux.h`
(see `Documentation/start/guides/publish-package.rst`):

```sh
shirudo bpm build upatches/app-sandbox --version 1.0.0 --keys-dir <keys>
shirudo bpm push app-sandbox-1.0.0.bee oci://<registry>/<namespace>/app-sandbox --keys-dir <keys>
shirudo bpm tree append app-sandbox-1.0.0.bee oci://<registry>/<tree> --keys-dir <keys>
```

The Beefile has a tree entry without a selector, with the advisories
above as its `fixes`, so every node that syncs the tree loads the
upatch; on a node without the applications it labels nothing and
restricts nothing. Add a selector to load it only where they run:

```toml
[upatches.tree.selector.labels]
role = ["web"]
```

`tools/put-shields`, and `make shields` with it, publishes the package
with the other shields of `upatches/`.

`--rodata-input sandbox=<file>` builds with other rules for the
policies of the Beefile, and `shirudo bpm config update` signs new rules
into a package already built, without compiling it again.

## What a load does

The load labels each path of the Beefile that exists on the target with
its policy bit, in the `security.bpf.shirudo.policy` xattr. shirudo
gives a task the bits of every file it executes, and its children
inherit them, so a task enters a sandbox at its next `execve()` of a
labeled file: restart the application after the first load. An unload
leaves the labels, which restrict nothing once the upatch is gone.

Every refusal is `EACCES`.

## Contain other 2Shell workloads

`Beefile.2shell-containment` builds a second package using the same BPF
sandbox. It covers nginx for CVE-2026-123007 and CVE-2026-123633, Ruby
for CVE-2026-132825, and the Node.js, Bun and Envoy executables for
CVE-2026-111497 in their Brotli decoders. It can run alongside the PHP
sandbox. Each profile allows execution of its own labeled files and
allows new IP connections only to loopback. The sandbox cannot repair
the vulnerable code in a running process or cover every application
that embeds Brotli. The tree entry leaves advisory fix status to the
vendor upgrades.

Review the executable paths and policy bits in `Beefile.2shell-containment`
before signing. The restrictions apply to every task that executes a
labeled inode, regardless of its path, and its descendants. Use separate
copies of the executable where applications need different policies. Add
the actual paths for any other Brotli consumers you intend to contain.
Allow the services' required upstream IP networks and child executables
in a site policy, then test the services on a Shirudo target. The limits
below also apply to this package.

```sh
shirudo bpm build --file upatches/app-sandbox/Beefile.2shell-containment \
    --version 1.0.0 --keys-dir "$KEYS" \
    --rodata-input 2shell-policy=/path/to/site-policy.toml
shirudo bpm info data 2shell-containment-1.0.0.bee upatches/2shell-containment.upatch
```

Tree delivery selects nodes whose `shell-wave-containment` label is
`enabled`. A direct install applies the policy without that selection.
Restart the selected services after the first load so their workers
acquire the policy bits. For the underlying fixes, use these upstream
releases or your vendor's backports.

| CVE | Fixed upstream releases |
|---|---|
| CVE-2026-109618, CVE-2026-109619 | PHP 8.2.35, 8.3.36, 8.4.27 and 8.5.12. [PHP security release](https://www.php.net/archive/2026.php#2026-10-21-5) |
| CVE-2026-111497 | Brotli 1.0.10, 1.1.1 and 1.2.1. Update each product that embeds a copy. [Brotli releases](https://github.com/google/brotli/releases), [Node.js security release](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases), [Bun advisory](https://github.com/oven-sh/bun/security/advisories/GHSA-663w-cv8g-jj2p), [Envoy advisory](https://github.com/envoyproxy/envoy/security/advisories/GHSA-3wvj-j6qm-62mr) |
| CVE-2026-123007, CVE-2026-123633 | nginx 1.30.7 and 1.31.9. [nginx advisories](https://nginx.org/en/security_advisories.html) |
| CVE-2026-132825 | Ruby 3.3.14, 3.4.13 and 4.0.10. [Ruby advisory](https://www.ruby-lang.org/en/news/2026/11/18/multiple-vulnerabilities-in-regexp-and-string/) |

## Try it with Apache

`demo/` in the source of this package holds a web server to try the
`apache` sandbox on: Apache httpd with PHP from the official
`php:8.4-apache` image, a site on port 8443 and `attack.php`, which
does from inside PHP what an attacker would next. `demo/build.sh` writes
the image's file system to an archive, and `demo/apache.sh` unpacks it
on a target and runs Apache from it in a chroot, with `/usr/sbin/apache2`
a hard link to its binary. `Documentation/start/guides/system-hardening.rst`
walks through it.

## Limits

- A path that does not exist at the load is not labeled, and a file
  that replaces a labeled one, as a package upgrade does, is a new file
  without the label, whether a path or a pattern named it. Load the upatch again after the application is
  installed or upgraded.
- The file rules name files, not their contents: a descriptor that was
  open for writing before the task entered the sandbox, or that another
  process passes to it, still writes.
- The network rules cover `connect()` and the address of `sendmsg()`
  and `sendto()` on IPv4 and IPv6 sockets. Other address families pass,
  and so does what a task receives or accepts.
- Root outside a sandbox can remove nothing of it, as only shirudo's
  runtime sets the label, but a task that root starts from an unlabeled
  file is in no sandbox.

## Kernels and cost

The programs keep no state of their own: they read the task's policy
bits and the rules, which never change after the load, so they are
right on every preemption model.

A task in no sandbox pays one task-storage lookup at each hook, and
none when it opens a file for reading. The hooks are the LSM hooks of
`execve()`, `connect()`, `sendmsg()`, `socket()`, the creation, linking
and renaming of a directory entry, an open for writing and a change of
size. A task in a sandbox pays a scan of the rules on top: at most 128
networks, or 64 patterns of at most 64 bytes.
