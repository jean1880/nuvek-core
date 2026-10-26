//! Small shared helpers used across nuvek-core modules.

use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// How long [`command_output_timeout`] waits for the pipes to close after killing an overrunning
/// process group, before it stops reading. A descendant that left the group (`setsid`) can hold
/// them open forever.
const KILL_GRACE: Duration = Duration::from_secs(2);

/// Most bytes kept from each of stdout and stderr (16 MiB). Past it, output is still read (so the
/// writer never blocks on a full pipe) but discarded.
const OUTPUT_CAP_BYTES: usize = 16 * 1024 * 1024;

/// How often a reader thread checks whether it has been told to stop.
const READER_TICK_MS: libc::c_int = 50;

/// Run a subprocess with a hard wall-clock timeout, killing it if it overruns.
///
/// Returns `Ok(Some(output))` when the process exited and its output pipes closed within `dur`,
/// and `Ok(None)` if it overran and was killed and reaped. Callers needing fail-closed semantics
/// (e.g. `scrub::gitleaks_clean`) treat both `Ok(None)` and `Err` as "could not prove clean".
///
/// - **Process group.** The child runs in a process group of its own, and an overrun kills the
///   whole group, so a grandchild holding the pipes cannot keep the call waiting. A process group
///   set on `cmd` by the caller is replaced.
/// - **No PID reuse.** The child is reaped only after the kill decision, so the PID and PGID being
///   signalled still belong to it (an unreaped process, even a zombie, keeps both reserved).
/// - **Bounded time.** The call returns within `dur` plus a two-second grace after a kill, even
///   if a descendant left the group and keeps the pipes open: reading then stops, the pipes are
///   closed, and no thread or descriptor is left behind.
/// - **Bounded memory.** At most 16 MiB of each stream is kept. Anything beyond is still read,
///   so the writer is not blocked, but discarded without notice, because [`Output`] has no field
///   to report it.
///
/// # Errors
///
/// - The process could not be spawned.
/// - The child could no longer be observed (`waitid` failed, typically `ECHILD`): it is no longer
///   ours, so nothing is signalled, and the error is returned at once.
/// - `SIGKILL` could not be delivered (`EPERM`, e.g. a child that changed its privileges): the
///   error is returned after the grace period, and the child, which may still be running, is
///   left unreaped.
/// - The killed child had still not exited at the end of the grace period: a
///   [`TimedOut`](std::io::ErrorKind::TimedOut) error, leaving it unreaped (a zombie once it
///   exits). The one known cause is a process in uninterruptible kernel sleep (`D` state, e.g.
///   on a hung network filesystem), which cannot act on `SIGKILL` until the kernel wakes it.
///
/// # Caller requirements
///
/// The process must not ignore `SIGCHLD` (`SIG_IGN` makes the kernel reap children itself), and
/// nothing else in the process may reap this child (a `waitpid(-1, …)` loop, a child-reaper
/// crate). Either releases the PID behind this function's back. The function detects that as an
/// error and then signals nothing, but it cannot return the child's output.
pub fn command_output_timeout(cmd: Command, dur: Duration) -> std::io::Result<Option<Output>> {
    run_bounded(cmd, dur, |_| {}, kill_leader_and_group)
}

/// [`command_output_timeout`] with two test seams: `between` is called after the wait for the
/// child's exit ends and before the timeout decision is acted on (tests force an interleaving
/// there), and `kill` sends the SIGKILLs (tests make it fail, or do nothing, to exercise the error
/// paths). The public function passes a no-op and [`kill_leader_and_group`].
fn run_bounded(
    mut cmd: Command,
    dur: Duration,
    between: impl FnOnce(libc::pid_t),
    kill: fn(libc::pid_t) -> std::io::Result<()>,
) -> std::io::Result<Option<Output>> {
    cmd.process_group(0);
    let mut child = cmd.spawn()?;
    let pid = libc::pid_t::try_from(child.id())
        .map_err(|_| std::io::Error::other("child pid out of range"))?;
    let deadline = Instant::now() + dur;
    // Dropped like `wait_with_output` does, so a child reading stdin sees EOF.
    drop(child.stdin.take());

    let stop = Arc::new(AtomicBool::new(false));
    let stdout = child
        .stdout
        .take()
        .map(|p| spawn_reader(p, Arc::clone(&stop)));
    let stderr = child
        .stderr
        .take()
        .map(|p| spawn_reader(p, Arc::clone(&stop)));

    // Stops the readers (they return within one tick and drop their pipe ends) and collects
    // what they kept. Every return below goes through it, so no reader outlives the call.
    let finish_readers = |stdout: Option<JoinHandle<Vec<u8>>>,
                          stderr: Option<JoinHandle<Vec<u8>>>| {
        stop.store(true, Ordering::Release);
        (join_reader(stdout), join_reader(stderr))
    };

    let exited = match wait_exit_unreaped(pid, deadline) {
        Ok(exited) => exited,
        Err(e) => {
            // The child cannot be observed (ECHILD: someone else reaped it, or SIGCHLD is
            // ignored). Its PID may already belong to another process, so nothing is signalled.
            finish_readers(stdout, stderr);
            return Err(e);
        }
    };
    between(pid);
    // The child is exited-but-unreaped or still running. Either way its PID and PGID are still
    // reserved, so signalling them cannot reach an unrelated process.
    let finished = exited && wait_readers(&[&stdout, &stderr], deadline);
    if finished {
        let (out, err) = finish_readers(stdout, stderr);
        // Exited (observed above, still unreaped), so this reap returns at once.
        let status = child.wait()?;
        return Ok(Some(Output {
            status,
            stdout: out,
            stderr: err,
        }));
    }

    let grace_end = Instant::now() + KILL_GRACE;
    let killed = kill(pid);
    wait_readers(&[&stdout, &stderr], grace_end);
    finish_readers(stdout, stderr);
    // SIGKILL not delivered: the child may still be running. Waiting for it could take forever,
    // so it is left unreaped and the error returned.
    killed?;
    // Bounded reap: wait for the exit within the same grace, then reap (which is then immediate).
    if !exited && !wait_exit_unreaped(pid, grace_end)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "the killed child had not exited by the end of the grace period; left unreaped",
        ));
    }
    child.wait()?;
    Ok(None)
}

/// Wait until `pid` has exited or `deadline` passes, WITHOUT reaping it (`WNOWAIT`).
///
/// Returns whether it exited. Polls with a short, growing interval: a dedicated waiting thread
/// would have to reap to learn of the exit, which is exactly what must not happen yet.
fn wait_exit_unreaped(pid: libc::pid_t, deadline: Instant) -> std::io::Result<bool> {
    let mut pause = Duration::from_millis(1);
    loop {
        if has_exited_unreaped(pid)? {
            return Ok(true);
        }
        let now = Instant::now();
        if now >= deadline {
            return Ok(false);
        }
        std::thread::sleep(pause.min(deadline - now));
        pause = (pause * 2).min(Duration::from_millis(20));
    }
}

/// Has `pid` exited? Leaves it unreaped either way.
fn has_exited_unreaped(pid: libc::pid_t) -> std::io::Result<bool> {
    let Ok(id) = libc::id_t::try_from(pid) else {
        return Err(std::io::Error::other("child pid out of range"));
    };
    loop {
        // SAFETY: `info` is a zeroed, properly aligned `siginfo_t` that lives across the call;
        // `waitid` only writes into it. With WNOHANG and no exit, it leaves `si_pid` zero.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::waitid(
                libc::P_PID,
                id,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if rc == 0 {
            // SAFETY: after a successful `waitid`, `si_pid` is the field it defines.
            return Ok(unsafe { info.si_pid() } != 0);
        }
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

/// SIGKILL the child and its process group.
///
/// Only called while the child is unreaped, so `pid` is still its PID and its group's ID. The
/// leader is signalled directly as well, in case it moved itself to another group. Signalling the
/// leader must succeed (an unreaped leader, even a zombie, accepts a signal). `ESRCH` from the
/// group is tolerated: it only means the leader left the group and no member is left in it.
fn kill_leader_and_group(pid: libc::pid_t) -> std::io::Result<()> {
    if pid <= 0 {
        return Err(std::io::Error::other(
            "refusing to signal a non-positive pid",
        ));
    }
    // SAFETY: `kill` takes integers and touches no memory. `pid > 0` rules out the special values
    // (0 = our own group, negative = a group or every process), and `pid` is our unreaped child,
    // so it cannot have been reused.
    if unsafe { libc::kill(pid, libc::SIGKILL) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: as above; `pid` is also the ID of the group the child was spawned to lead.
    if unsafe { libc::killpg(pid, libc::SIGKILL) } != 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::ESRCH) {
            return Err(e);
        }
    }
    Ok(())
}

/// Read a pipe to EOF in a thread, keeping at most [`OUTPUT_CAP_BYTES`], until `stop` is set.
fn spawn_reader<R>(mut pipe: R, stop: Arc<AtomicBool>) -> JoinHandle<Vec<u8>>
where
    R: Read + AsRawFd + Send + 'static,
{
    std::thread::spawn(move || {
        let mut kept = Vec::new();
        let mut buf = [0u8; 64 * 1024];
        let mut pfd = libc::pollfd {
            fd: pipe.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        while !stop.load(Ordering::Acquire) {
            // Poll with a timeout so a set `stop` is noticed even while nothing arrives.
            // SAFETY: `pfd` is a valid, live `pollfd` for one descriptor this thread owns.
            let ready = unsafe { libc::poll(&mut pfd, 1, READER_TICK_MS) };
            if ready < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                break;
            }
            if ready == 0 {
                continue;
            }
            match pipe.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let room = OUTPUT_CAP_BYTES.saturating_sub(kept.len());
                    kept.extend_from_slice(&buf[..n.min(room)]);
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
        // `pipe` drops here, closing our end.
        kept
    })
}

/// Wait until every present reader has finished, or `deadline` passes. Returns whether they did.
fn wait_readers(readers: &[&Option<JoinHandle<Vec<u8>>>], deadline: Instant) -> bool {
    loop {
        if readers
            .iter()
            .all(|r| r.as_ref().is_none_or(JoinHandle::is_finished))
        {
            return true;
        }
        let now = Instant::now();
        if now >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(5).min(deadline - now));
    }
}

fn join_reader(reader: Option<JoinHandle<Vec<u8>>>) -> Vec<u8> {
    reader.and_then(|h| h.join().ok()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;

    #[test]
    fn completes_within_timeout_and_captures_stdout() {
        let mut cmd = Command::new("printf");
        cmd.arg("hello");
        cmd.stdout(Stdio::piped());
        let out = command_output_timeout(cmd, Duration::from_secs(5))
            .expect("spawn printf")
            .expect("completed in time");
        assert!(out.status.success());
        assert_eq!(String::from_utf8_lossy(&out.stdout), "hello");
    }

    #[test]
    fn captures_stderr_and_the_exit_code() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "echo oops >&2; exit 3"]);
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        let out = command_output_timeout(cmd, Duration::from_secs(5))
            .expect("spawn sh")
            .expect("completed in time");
        assert_eq!(out.status.code(), Some(3));
        assert_eq!(String::from_utf8_lossy(&out.stderr), "oops\n");
    }

    #[test]
    fn kills_on_overrun() {
        let mut cmd = Command::new("sleep");
        cmd.arg("30");
        let out = command_output_timeout(cmd, Duration::from_millis(200)).expect("spawn sleep");
        assert!(out.is_none(), "expected timeout to yield None");
    }

    #[test]
    fn spawn_failure_is_err() {
        let cmd = Command::new("definitely-not-a-real-binary-xyz");
        assert!(command_output_timeout(cmd, Duration::from_secs(1)).is_err());
    }

    /// A grandchild that inherited stdout keeps the pipe open after its parent dies. Killing only
    /// the child left the call waiting for the grandchild's 30 seconds.
    #[test]
    fn a_grandchild_holding_the_pipes_is_killed_with_the_group() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "sleep 30 & echo started; wait"]);
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        let start = Instant::now();
        let out = command_output_timeout(cmd, Duration::from_millis(300)).expect("spawn sh");
        assert!(out.is_none(), "expected a timeout");
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "returned after {:?}",
            start.elapsed()
        );
    }

    /// The child exiting just before the deadline, with the decision delayed past it: the child
    /// must still be unreaped when the decision is taken, so no signal can reach a reused PID.
    #[test]
    fn the_child_is_not_reaped_before_the_decision() {
        let mut cmd = Command::new("true");
        cmd.stdout(Stdio::piped());
        let out = run_bounded(
            cmd,
            Duration::from_secs(5),
            |pid| {
                assert!(
                    has_exited_unreaped(pid).expect("waitid"),
                    "the child must have exited yet still be unreaped (its PID reserved)"
                );
                // Descheduled here: the decision must still be correct.
                std::thread::sleep(Duration::from_millis(200));
                assert!(has_exited_unreaped(pid).expect("still unreaped"));
            },
            |_| panic!("a child that exited in time must not be signalled"),
        )
        .expect("spawn true");
        assert!(
            out.expect("exited in time").status.success(),
            "a completed run is reported as such"
        );
    }

    /// The same on the timeout path: when the deadline passes, the child is still running and
    /// unreaped at the decision, so the kill reaches the right group.
    #[test]
    fn a_timed_out_child_is_unreaped_when_it_is_killed() {
        let mut cmd = Command::new("sleep");
        cmd.arg("30");
        let start = Instant::now();
        let out = run_bounded(
            cmd,
            Duration::from_millis(200),
            |pid| {
                assert!(
                    !has_exited_unreaped(pid).expect("waitid"),
                    "still running at the decision"
                );
            },
            kill_leader_and_group,
        )
        .expect("spawn sleep");
        assert!(out.is_none());
        assert!(start.elapsed() < Duration::from_secs(3));
    }

    /// Clean up a child a test left unreaped on purpose: kill it for real and reap it.
    fn kill_and_reap(pid: libc::pid_t) {
        let _ = kill_leader_and_group(pid);
        // SAFETY: `pid` is this process's own unreaped child; a null status pointer is allowed.
        unsafe {
            libc::waitpid(pid, std::ptr::null_mut(), 0);
        }
    }

    /// With SIGCHLD ignored, the kernel reaps the child itself and its PID is released at once,
    /// so `waitid` reports ECHILD. Nothing may be signalled then: the PID could already be
    /// someone else's. In its own process, because the signal disposition is process-wide.
    #[test]
    fn an_auto_reaped_child_is_never_signalled() {
        crate::test_isolation::isolated(
            "util::tests::an_auto_reaped_child_is_never_signalled",
            || {
                // SAFETY: installing SIG_IGN for SIGCHLD in this single-threaded child process,
                // which runs nothing else.
                unsafe {
                    libc::signal(libc::SIGCHLD, libc::SIG_IGN);
                }
                let mut cmd = Command::new("true");
                cmd.stdout(Stdio::piped());
                let err = run_bounded(
                    cmd,
                    Duration::from_secs(5),
                    |_| panic!("a child we no longer own must not reach the decision"),
                    |_| panic!("a child we no longer own must not be signalled"),
                )
                .expect_err("an auto-reaped child is an error");
                assert_eq!(err.raw_os_error(), Some(libc::ECHILD), "got {err:?}");
            },
        );
    }

    /// SIGKILL refused (EPERM, as for a child that changed its privileges): the error is
    /// returned after the grace period instead of waiting for a child that may never exit.
    #[test]
    fn a_refused_kill_is_an_error_not_a_hang() {
        let mut cmd = Command::new("sleep");
        cmd.arg("30");
        cmd.stdout(Stdio::piped());
        let pid = std::cell::Cell::new(0);
        let start = Instant::now();
        let err = run_bounded(
            cmd,
            Duration::from_millis(200),
            |p| pid.set(p),
            |_| Err(std::io::Error::from_raw_os_error(libc::EPERM)),
        )
        .expect_err("a refused kill is an error");
        let took = start.elapsed();
        kill_and_reap(pid.get());
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err:?}");
        assert!(
            took < Duration::from_millis(200) + KILL_GRACE + Duration::from_secs(1),
            "returned after {took:?}"
        );
    }

    /// A killed child that still has not exited by the end of the grace period (as in
    /// uninterruptible sleep) is a TimedOut error, and the reap does not block on it.
    #[test]
    fn the_reap_after_a_kill_is_bounded() {
        let mut cmd = Command::new("sleep");
        cmd.arg("30");
        let pid = std::cell::Cell::new(0);
        let start = Instant::now();
        // A "kill" that reports success but sends nothing stands in for a child that cannot act
        // on SIGKILL yet.
        let err = run_bounded(cmd, Duration::from_millis(200), |p| pid.set(p), |_| Ok(()))
            .expect_err("an unexited child is an error");
        let took = start.elapsed();
        kill_and_reap(pid.get());
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "{err:?}");
        assert!(
            took < Duration::from_millis(200) + KILL_GRACE + Duration::from_secs(1),
            "returned after {took:?}"
        );
    }

    /// Output past the cap is discarded, but still read, so the writer finishes instead of
    /// blocking on a full pipe.
    #[test]
    fn output_is_capped_and_the_writer_is_not_blocked() {
        let mut cmd = Command::new("head");
        cmd.args(["-c", "20000000", "/dev/zero"]);
        cmd.stdout(Stdio::piped());
        let out = command_output_timeout(cmd, Duration::from_secs(20))
            .expect("spawn head")
            .expect("head finished: the pipe kept draining past the cap");
        assert!(out.status.success());
        assert_eq!(out.stdout.len(), OUTPUT_CAP_BYTES);
    }

    fn open_fds() -> usize {
        std::fs::read_dir("/proc/self/fd")
            .expect("read /proc/self/fd")
            .count()
    }

    fn threads() -> usize {
        std::fs::read_to_string("/proc/self/status")
            .expect("read /proc/self/status")
            .lines()
            .find_map(|l| l.strip_prefix("Threads:"))
            .and_then(|n| n.trim().parse().ok())
            .expect("a Threads line")
    }

    /// A descendant that left the group and writes forever: the call still returns within the
    /// timeout plus the grace period, and leaves no thread or descriptor behind. In its own
    /// process, so other tests' threads and descriptors do not disturb the counts.
    #[test]
    fn an_escaped_writer_leaves_nothing_behind() {
        crate::test_isolation::isolated(
            "util::tests::an_escaped_writer_leaves_nothing_behind",
            || {
                let (fds, nthreads) = (open_fds(), threads());
                let mut cmd = Command::new("sh");
                cmd.args([
                    "-c",
                    "setsid sh -c 'while :; do echo x || exit; done' & sleep 30",
                ]);
                cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
                let start = Instant::now();
                let out =
                    command_output_timeout(cmd, Duration::from_millis(300)).expect("spawn sh");
                let took = start.elapsed();
                assert!(out.is_none(), "expected a timeout");
                assert!(
                    took < Duration::from_millis(300) + KILL_GRACE + Duration::from_secs(1),
                    "returned after {took:?}"
                );
                assert_eq!(open_fds(), fds, "a pipe end was left open");
                assert_eq!(threads(), nthreads, "a reader thread was left running");
            },
        );
    }
}
