# Patch-now list

`patch-now.json` names security fixes that cannot wait. Every infra-TAK console reads it from
`main` once an hour. A box that still has an affected version installed emails its Guard Dog
alert address right away ("🔒 Security update pending … patch now") and again every 24 hours
until the fixed version is installed. Editing this file on `main` reaches the whole fleet
within the hour; no release is needed.

Add an entry only when a fix is out in the package repositories and is urgent (actively
exploited or critical). Remove it once the fleet has moved on; boxes that are already fixed
ignore it either way.

```json
{
  "advisories": [
    {
      "id": "CVE-2026-12345",
      "what": "A bug in Docker that lets a container take over the whole server.",
      "why": "It is being actively attacked.",
      "packages": {
        "docker-ce": "28.5.2",
        "openssl": {"ubuntu-22.04": "3.0.2-0ubuntu1.20", "ubuntu-24.04": "3.0.13-0ubuntu3.6",
                    "rocky-9": "3.2.2-6.el9_5.1"},
        "kernel": {"ubuntu-22.04": "5.15.0-198", "ubuntu-22.04/aws": "6.8.0-1030",
                   "rocky-9": "5.14.0-570.12.1"}
      }
    }
  ]
}
```

- `what` and `why` are shown to customers as written: plain words, no jargon.
- A package's version is the first version with the fix. A plain string applies to every OS;
  otherwise key it by OS: `ubuntu-22.04`, `ubuntu-24.04`, `rocky-9` (the whole RHEL 9 family).
- Leave out the epoch (`28.5.2`, not `5:28.5.2`) unless it changes. Leave out the
  `-revision` to accept any build of that version.
- `kernel` is compared with the kernel the box is running, so a box that installed the fix
  but has not restarted is told to reboot. Cloud kernels (`-aws`, `-azure`, `-gcp`) number
  their releases differently: give them their own key (`ubuntu-22.04/aws`), or they are skipped.
- An entry that does not match this shape is ignored whole.
