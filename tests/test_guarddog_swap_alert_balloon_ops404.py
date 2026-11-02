"""Guard Dog swap-pressure alert (ops #404).

- Alerts only when two checks in a row see pressure (a short squeeze mails nobody).
- When the VPS host's memory balloon is large, the mail says the provider is reclaiming
  RAM instead of blaming a process; with no balloon the text is the original.
"""
import pathlib
import subprocess

import pytest

SCRIPT = (pathlib.Path(__file__).resolve().parent.parent
          / 'scripts' / 'guarddog' / 'tak-swap-reclaim.sh').read_text()


@pytest.fixture
def swap(tmp_path):
    state = tmp_path / 'state'
    mail = tmp_path / 'mail'
    sender = tmp_path / 'send-alert-email.sh'
    sender.write_text('#!/bin/bash\n{ echo "SUBJECT: $1"; cat; } >> "%s"\n' % mail)
    sender.chmod(0o755)
    script = (SCRIPT.replace('/opt/tak-guarddog/send-alert-email.sh', str(sender))
                    .replace('/opt/tak-guarddog/server_identifier', str(tmp_path / 'none'))
                    .replace('/var/lib/takguard', str(state))
                    .replace('/proc/meminfo', str(tmp_path / 'meminfo'))
                    .replace('/proc/vmstat', str(tmp_path / 'vmstat')))
    sp = tmp_path / 'swap.sh'
    sp.write_text(script)

    def run(swap_pct=95, mem_avail_kb=100000, inflate=None, deflate=0):
        total = 1000000
        free = total - total * swap_pct // 100
        (tmp_path / 'meminfo').write_text(
            'SwapTotal: %d kB\nSwapFree: %d kB\nMemAvailable: %d kB\n' % (total, free, mem_avail_kb))
        vm = 'nr_free_pages 1\n'
        if inflate is not None:
            vm += 'balloon_inflate %d\nballoon_deflate %d\n' % (inflate, deflate)
        (tmp_path / 'vmstat').write_text(vm)
        r = subprocess.run(['bash', str(sp)], capture_output=True, text=True, timeout=60)
        assert r.returncode == 0, r.stderr
        return mail.read_text() if mail.exists() else ''
    return run


def test_one_pressure_check_sends_nothing(swap):
    assert swap() == ''


def test_second_pressure_check_in_a_row_alerts_once(swap):
    swap()
    first = swap()
    assert 'swap 95% full, low free RAM' in first
    assert 'This usually means a process is using a lot of memory' in first
    assert 'hosting provider' not in first
    # still pressured: no second mail until it clears
    assert swap() == first


def test_squeeze_that_clears_between_checks_resets_the_count(swap):
    swap()
    swap(swap_pct=10)          # clears
    assert swap() == ''        # pressure again counts as the first check
    assert 'Memory pressure' in swap()


def test_large_balloon_says_the_provider_is_reclaiming_ram(swap):
    swap(inflate=10000000, deflate=0)
    mail = swap(inflate=10000000, deflate=0)      # 10M pages * 4 kB = 39062 MB
    assert 'your hosting provider is reclaiming RAM' in mail
    assert 'Nothing on your server is leaking. Swap clears on its own.' in mail
    assert 'about 39062 MB' in mail
    assert 'using a lot of memory' not in mail


def test_small_or_deflated_balloon_keeps_the_original_text(swap):
    swap(inflate=500000, deflate=499000)           # 1000 pages = 3 MB
    mail = swap(inflate=500000, deflate=499000)
    assert 'swap 95% full, low free RAM' in mail
    assert 'hosting provider' not in mail
