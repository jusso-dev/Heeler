//! Clock-source abstraction.
//!
//! Heeler serves time from a [`ClockSource`]. Version 1 ships two
//! implementations:
//!
//! * [`SystemClockSource`] — reads the operating-system wall clock, detects
//!   implausible jumps by comparing against a monotonic clock, and never
//!   modifies the system clock;
//! * [`MockClockSource`] — a scripted clock for deterministic tests.
//!
//! The trait is deliberately small so that future sources (upstream NTP,
//! GPS/GNSS, PPS, PHC) can slot in without changes to the packet or server
//! layers.
//!
//! # Wall time vs monotonic time
//!
//! Wall-clock readings are used **only** for timestamps placed into NTP
//! packets. Interval measurement (jump detection windows, rate limiting,
//! uptime) uses `std::time::Instant`, which cannot move backwards.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use crate::error::ClockError;
use crate::timestamp::{NtpInstant, NtpTimestamp};

/// Clock precision as a signed base-2 exponent of seconds (e.g. `-20` is
/// about 1 µs), matching the packet precision field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockPrecision(pub i8);

impl ClockPrecision {
    /// Estimates precision from the smallest observable positive step of
    /// the system clock: `floor(log2(step_seconds))`, clamped to a sane
    /// range for the wire field.
    #[must_use]
    pub fn measure_system() -> Self {
        let mut smallest = Duration::from_secs(1);
        for _ in 0..16 {
            let start = SystemTime::now();
            // Spin until the wall clock visibly advances.
            for _ in 0..100_000 {
                if let Ok(step) = SystemTime::now().duration_since(start) {
                    if !step.is_zero() {
                        if step < smallest {
                            smallest = step;
                        }
                        break;
                    }
                }
            }
        }
        Self::from_duration(smallest)
    }

    /// Converts a duration to the log2-seconds exponent, clamped to
    /// `[-30, 0]`.
    #[must_use]
    pub fn from_duration(step: Duration) -> Self {
        // Floating point is acceptable here: precision is an estimate for
        // the packet metadata field, not timestamp arithmetic.
        let seconds = (step.as_nanos().max(1) as f64) / 1e9;
        let exponent = seconds.log2().floor();
        Self(exponent.clamp(-30.0, 0.0) as i8)
    }

    /// The signed exponent for the packet precision field.
    #[must_use]
    pub const fn exponent(self) -> i8 {
        self.0
    }
}

/// Synchronisation state of the clock source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockStatus {
    /// The source is considered valid; responses may claim synchronisation.
    Synchronised,
    /// The source is not trusted; responses carry leap indicator 3 and
    /// stratum 16.
    Unsynchronised,
}

/// A single reading of the clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockReading {
    /// The absolute instant of the reading.
    pub instant: NtpInstant,
    /// The wire-format timestamp of the reading.
    pub timestamp: NtpTimestamp,
}

impl ClockReading {
    /// Builds a reading from an absolute instant, failing for pre-1900
    /// instants that cannot be encoded.
    pub fn from_instant(instant: NtpInstant) -> Result<Self, ClockError> {
        let timestamp = instant.to_timestamp()?;
        Ok(Self { instant, timestamp })
    }
}

/// A source of wall-clock time for the NTP server.
pub trait ClockSource: Send + Sync {
    /// Reads the current time. Must never panic; clock trouble is an error.
    fn now(&self) -> Result<ClockReading, ClockError>;

    /// Current synchronisation status.
    fn status(&self) -> ClockStatus;

    /// When the source was last considered valid, as a wire timestamp.
    /// `None` when the source has never been valid.
    fn reference_timestamp(&self) -> Option<NtpTimestamp>;

    /// Estimated reading precision.
    fn estimated_precision(&self) -> ClockPrecision;

    /// Estimated root dispersion contributed by this source.
    fn estimated_root_dispersion(&self) -> Duration;
}

/// Thresholds for treating a wall-clock movement as a jump.
#[derive(Debug, Clone, Copy)]
pub struct JumpPolicy {
    /// Maximum tolerated backward movement relative to the monotonic clock.
    pub max_backward: Duration,
    /// Maximum tolerated forward movement relative to the monotonic clock.
    pub max_forward: Duration,
    /// Whether a detected jump marks the source unsynchronised.
    pub mark_unsynchronised_on_jump: bool,
}

impl Default for JumpPolicy {
    fn default() -> Self {
        Self {
            max_backward: Duration::from_millis(250),
            max_forward: Duration::from_millis(5000),
            mark_unsynchronised_on_jump: true,
        }
    }
}

/// A detected wall-clock jump, reported by [`SystemClockSource::check_jump`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockJump {
    /// Signed wall-clock movement minus monotonic elapsed time, in
    /// nanoseconds. Negative means the wall clock moved backwards.
    pub drift_nanos: i128,
    /// Whether the source was marked unsynchronised as a result.
    pub marked_unsynchronised: bool,
}

struct JumpState {
    last_wall: NtpInstant,
    last_mono: Instant,
}

/// Clock source backed by the operating-system wall clock.
///
/// Reads `SystemTime` for packet timestamps and cross-checks it against the
/// monotonic clock to detect implausible jumps. It never adjusts, steps, or
/// disciplines the system clock, and it never shells out to any utility.
pub struct SystemClockSource {
    policy: JumpPolicy,
    precision: ClockPrecision,
    root_dispersion: Duration,
    synchronised: AtomicBool,
    reference: Mutex<Option<NtpTimestamp>>,
    jump_state: Mutex<JumpState>,
}

impl SystemClockSource {
    /// Creates a system clock source, accepting the current system clock as
    /// the initial reference and recording the reference timestamp now.
    ///
    /// `root_dispersion` is the operator-configured dispersion floor.
    pub fn new(policy: JumpPolicy, root_dispersion: Duration) -> Result<Self, ClockError> {
        let precision = ClockPrecision::measure_system();
        let now_wall = NtpInstant::from_system_time(SystemTime::now());
        let reference = now_wall.to_timestamp()?;
        Ok(Self {
            policy,
            precision,
            root_dispersion,
            synchronised: AtomicBool::new(true),
            reference: Mutex::new(Some(reference)),
            jump_state: Mutex::new(JumpState {
                last_wall: now_wall,
                last_mono: Instant::now(),
            }),
        })
    }

    /// Compares wall-clock movement against monotonic elapsed time since the
    /// previous check. Returns a [`ClockJump`] when the drift exceeds the
    /// configured thresholds; the caller decides how to log it.
    ///
    /// Reference-timestamp policy: the reference timestamp is set when the
    /// clock is first accepted at startup and refreshed only on a
    /// synchronised → synchronised periodic check (i.e. while the source
    /// remains valid). It is never derived from per-request transmit times.
    pub fn check_jump(&self) -> Option<ClockJump> {
        let now_wall = NtpInstant::from_system_time(SystemTime::now());
        let now_mono = Instant::now();

        let mut state = match self.jump_state.lock() {
            Ok(guard) => guard,
            // A poisoned lock means a panic elsewhere; fail conservative.
            Err(poisoned) => poisoned.into_inner(),
        };
        let mono_elapsed = now_mono.duration_since(state.last_mono).as_nanos() as i128;
        let wall_elapsed = now_wall.nanos_since(state.last_wall);
        state.last_wall = now_wall;
        state.last_mono = now_mono;
        drop(state);

        let drift = wall_elapsed - mono_elapsed;
        let jumped = drift < -(self.policy.max_backward.as_nanos() as i128)
            || drift > self.policy.max_forward.as_nanos() as i128;

        if jumped {
            let marked = self.policy.mark_unsynchronised_on_jump;
            if marked {
                self.synchronised.store(false, Ordering::Relaxed);
            }
            Some(ClockJump {
                drift_nanos: drift,
                marked_unsynchronised: marked,
            })
        } else {
            // The source remains valid: refresh the reference timestamp.
            if self.synchronised.load(Ordering::Relaxed) {
                if let Ok(ts) = now_wall.to_timestamp() {
                    if let Ok(mut reference) = self.reference.lock() {
                        *reference = Some(ts);
                    }
                }
            }
            None
        }
    }
}

impl ClockSource for SystemClockSource {
    fn now(&self) -> Result<ClockReading, ClockError> {
        ClockReading::from_instant(NtpInstant::from_system_time(SystemTime::now()))
    }

    fn status(&self) -> ClockStatus {
        if self.synchronised.load(Ordering::Relaxed) {
            ClockStatus::Synchronised
        } else {
            ClockStatus::Unsynchronised
        }
    }

    fn reference_timestamp(&self) -> Option<NtpTimestamp> {
        self.reference.lock().ok().and_then(|guard| *guard)
    }

    fn estimated_precision(&self) -> ClockPrecision {
        self.precision
    }

    fn estimated_root_dispersion(&self) -> Duration {
        self.root_dispersion
    }
}

/// Deterministic, scripted clock source for tests.
///
/// `now()` pops scripted readings in order; when the script is exhausted it
/// keeps returning the last reading (or [`ClockError::MockExhausted`] if the
/// script was empty). Status, reference timestamp, precision, and dispersion
/// are directly settable.
pub struct MockClockSource {
    readings: Mutex<MockScript>,
    status: Mutex<ClockStatus>,
    reference: Mutex<Option<NtpTimestamp>>,
    precision: ClockPrecision,
    root_dispersion: Duration,
}

struct MockScript {
    queue: std::collections::VecDeque<Result<NtpInstant, ClockError>>,
    last: Option<Result<NtpInstant, ClockError>>,
}

impl MockClockSource {
    /// Creates a mock clock with a script of readings.
    #[must_use]
    pub fn new(readings: Vec<Result<NtpInstant, ClockError>>) -> Self {
        Self {
            readings: Mutex::new(MockScript {
                queue: readings.into(),
                last: None,
            }),
            status: Mutex::new(ClockStatus::Synchronised),
            reference: Mutex::new(None),
            precision: ClockPrecision(-20),
            root_dispersion: Duration::from_millis(5),
        }
    }

    /// Creates a mock clock that always returns `instant`.
    #[must_use]
    pub fn fixed(instant: NtpInstant) -> Self {
        Self::new(vec![Ok(instant)])
    }

    /// Sets the reported synchronisation status.
    pub fn set_status(&self, status: ClockStatus) {
        if let Ok(mut guard) = self.status.lock() {
            *guard = status;
        }
    }

    /// Sets the reported reference timestamp.
    pub fn set_reference_timestamp(&self, ts: Option<NtpTimestamp>) {
        if let Ok(mut guard) = self.reference.lock() {
            *guard = ts;
        }
    }

    /// Appends a reading to the script.
    pub fn push_reading(&self, reading: Result<NtpInstant, ClockError>) {
        if let Ok(mut guard) = self.readings.lock() {
            guard.queue.push_back(reading);
        }
    }
}

impl ClockSource for MockClockSource {
    fn now(&self) -> Result<ClockReading, ClockError> {
        let mut script = match self.readings.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let next = match script.queue.pop_front() {
            Some(reading) => {
                script.last = Some(reading.clone());
                reading
            }
            None => script.last.clone().ok_or(ClockError::MockExhausted)?,
        };
        ClockReading::from_instant(next?)
    }

    fn status(&self) -> ClockStatus {
        self.status
            .lock()
            .map(|guard| *guard)
            .unwrap_or(ClockStatus::Unsynchronised)
    }

    fn reference_timestamp(&self) -> Option<NtpTimestamp> {
        self.reference.lock().ok().and_then(|guard| *guard)
    }

    fn estimated_precision(&self) -> ClockPrecision {
        self.precision
    }

    fn estimated_root_dispersion(&self) -> Duration {
        self.root_dispersion
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precision_from_duration() {
        // 1 µs ≈ 2^-20 s
        assert_eq!(
            ClockPrecision::from_duration(Duration::from_micros(1)).0,
            -20
        );
        // 1 ns clamps near the bottom of the range.
        assert_eq!(
            ClockPrecision::from_duration(Duration::from_nanos(1)).0,
            -30
        );
        // 1 s is exponent 0.
        assert_eq!(ClockPrecision::from_duration(Duration::from_secs(1)).0, 0);
        // 1 ms ≈ 2^-10 s
        assert_eq!(
            ClockPrecision::from_duration(Duration::from_millis(1)).0,
            -10
        );
    }

    #[test]
    fn mock_clock_scripted_readings() {
        let a = NtpInstant::from_unix_nanos(1_700_000_000_000_000_000);
        let b = a.add_nanos(1_000_000);
        let clock = MockClockSource::new(vec![Ok(a), Ok(b)]);
        assert_eq!(clock.now().unwrap().instant, a);
        assert_eq!(clock.now().unwrap().instant, b);
        // Exhausted: repeats the last reading.
        assert_eq!(clock.now().unwrap().instant, b);
    }

    #[test]
    fn mock_clock_failure_and_empty() {
        let clock = MockClockSource::new(vec![Err(ClockError::SystemClock("gone".into()))]);
        assert!(clock.now().is_err());
        let empty = MockClockSource::new(vec![]);
        assert_eq!(empty.now(), Err(ClockError::MockExhausted));
    }

    #[test]
    fn system_clock_reads_and_reports() {
        let clock =
            SystemClockSource::new(JumpPolicy::default(), Duration::from_millis(5)).unwrap();
        let reading = clock.now().unwrap();
        assert!(reading.instant.as_unix_nanos() > 0);
        assert_eq!(clock.status(), ClockStatus::Synchronised);
        assert!(clock.reference_timestamp().is_some());
        // No jump across two immediate checks.
        assert_eq!(clock.check_jump(), None);
    }
}
