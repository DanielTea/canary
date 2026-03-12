# The XZ Utils / OpenSSH Backdoor (CVE-2024-3094)

## How Andres Freund Discovered It

### Who is Andres Freund?

Andres Freund is a Microsoft principal software engineer and a PostgreSQL developer/committer. He was not doing a security audit — he stumbled onto one of the most sophisticated supply chain attacks in open-source history by accident.

### The Initial Clue: A 500ms Delay

On **March 28, 2024**, Freund was running routine performance benchmarks on a **Debian Sid (unstable)** installation. He noticed that **SSH logins were taking ~500ms longer than expected** — login time jumped from roughly 0.3 seconds to 0.8 seconds. He also observed that failed SSH login attempts (from automated bots) were consuming an unusual amount of CPU.

### What Made Him Suspicious

Several things combined to raise his suspicion:

1. **Unusual CPU usage in `liblzma`**: He profiled `sshd` and found it was spending significant CPU time inside `liblzma` (the compression library from XZ Utils). The profiling tool `perf` could not attribute the CPU usage to any known symbol — a red flag.

2. **Valgrind errors**: Weeks earlier, Freund had noticed odd Valgrind (memory debugging tool) complaints during automated testing of PostgreSQL, which appeared after system package updates. At the time he noted them but didn't investigate deeply.

3. **Connecting the dots**: The SSH slowdown made him recall those earlier Valgrind errors. He traced both anomalies back to the recently updated `xz`/`liblzma` library.

4. **Obfuscated code in build artifacts**: When he dug into the XZ Utils build artifacts (the tarball distribution, not the git source), he found **obfuscated malicious code** injected during the build process. The backdoor was hidden in test fixture files (`bad-3-corrupt_lzma2.xz` and `good-large_compressed.lzma`) and activated by a modified build script.

As Freund wrote on Mastodon:

> "Profiled sshd, showing lots of cpu time in liblzma, with perf unable to attribute it to a symbol. Got suspicious. Recalled that I had seen an odd valgrind complaint in automated testing of postgres, a few weeks earlier, after package updates. **Really required a lot of coincidences.**"

### Timeline of the Discovery and Response

| Date | Event |
|------|-------|
| **~2021-11** | User "Jia Tan" begins contributing to XZ Utils, starting a ~3-year social engineering campaign |
| **2024-02** | XZ Utils versions 5.6.0 and 5.6.1 are released containing the backdoor |
| **2024-03-27** | Freund contacts the Debian security team about SSH slowdown tied to the new XZ library |
| **2024-03-28** | Debian security relays the info to Red Hat InfoSec |
| **2024-03-29** | Freund publicly discloses the backdoor on the Openwall `oss-security` mailing list |
| **2024-03-29** | Red Hat issues an urgent security alert; CISA publishes an advisory |
| **2024-03-29** | GitHub suspends Jia Tan's account and disables the XZ Utils repository |
| **Hours later** | Every major Linux distribution begins emergency rollbacks |

### What the Backdoor Actually Did

- The backdoor targeted **OpenSSH's `sshd`** (the SSH server daemon).
- On many Linux distributions (Debian, Ubuntu, Fedora, etc.), `sshd` is patched to support **systemd notifications**. The `libsystemd` library depends on `liblzma`, which created the attack path: `sshd → libsystemd → liblzma (backdoored)`.
- The malicious code hooked into the **RSA key verification** process during SSH authentication.
- An attacker possessing a specific **Ed448 private key** could achieve **remote code execution** on any affected system — essentially a universal skeleton key for SSH.

### Why It Nearly Went Unnoticed

- The backdoor was **not present in the git source code** — it was only injected during the tarball build process via obfuscated scripts.
- The malicious test fixture files looked like normal compressed data.
- The attacker ("Jia Tan") had spent **nearly 3 years** building trust, eventually becoming a co-maintainer of XZ Utils.
- The affected versions (5.6.0 and 5.6.1) had only reached **bleeding-edge/unstable** distributions, not yet stable releases — meaning only a narrow window of systems were affected.

### Key Takeaway

As computer scientist Alex Stamos noted: *"This could have been the most widespread and effective backdoor ever planted in any software product."*

The discovery was a combination of:
- **Sharp observation** — noticing a half-second delay
- **Technical rigor** — profiling with `perf`, debugging with Valgrind
- **Curiosity** — not dismissing small anomalies
- **Luck** — as Freund himself admitted, it "really required a lot of coincidences"

## Sources

- [XZ Utils backdoor - Wikipedia](https://en.wikipedia.org/wiki/XZ_Utils_backdoor)
- [500ms to midnight: XZ/liblzma backdoor - Elastic Security Labs](https://www.elastic.co/security-labs/500ms-to-midnight)
- [oss-security - backdoor in upstream xz/liblzma (Freund's original post)](https://www.openwall.com/lists/oss-security/2024/03/29/4)
- [XZ Utils SSHd Backdoor - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2024/03/29/xz-utils-sshd-backdoor)
- [Understanding Red Hat's response to the XZ security incident](https://www.redhat.com/en/blog/understanding-red-hats-response-xz-security-incident)
- [Behind Enemy Lines: Understanding the XZ Backdoor - OffSec](https://www.offsec.com/blog/xz-backdoor/)
- [SSH Backdoor from Compromised XZ Utils Library - InfoQ](https://www.infoq.com/news/2024/04/xz-backdoor/)
- [XZ Utils Backdoor - Akamai](https://www.akamai.com/blog/security-research/critical-linux-backdoor-xz-utils-discovered-what-to-know)
