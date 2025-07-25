//! The [`LibFuzzerMonitor`] displays both cumulative and per-client stats.

use core::fmt::{Debug, Formatter, Write};

use libafl_bolts::{ClientId, Error};

use libafl::monitors::{Monitor, stats::ClientStatsManager};

/// Tracking monitor during fuzzing and display both per-client and cumulative info.
#[derive(Clone)]
pub struct LibFuzzerMonitor<F>
where
    F: FnMut(&str),
{
    print_fn: F,
}

impl<F> Debug for LibFuzzerMonitor<F>
where
    F: FnMut(&str),
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LibFuzzerMonitor").finish_non_exhaustive()
    }
}

impl<F> Monitor for LibFuzzerMonitor<F>
where
    F: FnMut(&str),
{
    fn display(
        &mut self,
        client_stats_manager: &mut ClientStatsManager,
        event_msg: &str,
        _sender_id: ClientId,
    ) -> Result<(), Error> {
        let mut fmt = format!(
            "#{runs}\t{event_msg}",
            runs = client_stats_manager.global_stats().total_execs
        );
        if let Some(coverage) = client_stats_manager.edges_coverage() {
            write!(
                fmt,
                " cov: {cov} ft: {ft}",
                cov = coverage.edges_hit,
                ft = coverage.edges_total
            )
            .unwrap();
        }
        write!(
            fmt,
            " corp: {corp}",
            corp = client_stats_manager.global_stats().corpus_size,
        )
        .unwrap();

        // TODO: Print /corpus_size(b|Kb|Mb), needs updates to
        // the whole corpus stack

        // TODO: Print focus: #inputs_that_touch_focus_fn

        write!(
            fmt,
            " exec/s: {execs}",
            execs = client_stats_manager.global_stats().execs_per_sec as u64
        )
        .unwrap();

        (self.print_fn)(&fmt);

        // Only print perf monitor if the feature is enabled
        Ok(())
    }
}

impl<F> LibFuzzerMonitor<F>
where
    F: FnMut(&str),
{
    /// Creates the monitor, using the `current_time` as `start_time`.
    pub fn new(print_fn: F) -> Self {
        Self { print_fn }
    }
}
