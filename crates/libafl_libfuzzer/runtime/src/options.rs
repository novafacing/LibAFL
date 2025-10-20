#![allow(unused)]
use core::fmt::{Display, Formatter};
use std::{path::PathBuf, time::Duration};

use libafl::{LibFuzzerParse, mutators::Tokens};
use serde::{Deserialize, Serialize};

use crate::options::RawOption::{Directory, File, Flag};

/// seed                                   0       Random seed. If 0, seed is generated.
/// runs                                   -1      Number of individual test runs (-1 for infinite runs).
/// max_len                                0       Maximum length of the test input. Contents of corpus files are going to be truncated to this value. If 0, libFuzzer tries to guess a good value based on the corpus and reports it.
/// len_control                            100     Try generating small inputs first, then try larger inputs over time.  Specifies the rate at which the length limit is increased (smaller == faster).  If 0, immediately try inputs with size up to max_len. Default value is 0, if LLVMFuzzerCustomMutator is used.
/// seed_inputs                            0       A comma-separated list of input files to use as an additional seed corpus. Alternatively, an \"@\" followed by the name of a file containing the comma-separated list.
/// keep_seed                              0       If 1, keep seed inputs in the corpus even if they do not produce new coverage. When used with |reduce_inputs==1|, the seed inputs will never be reduced. This option can be useful when seeds arenot properly formed for the fuzz target but still have useful snippets.
/// cross_over                             1       If 1, cross over inputs.
/// cross_over_uniform_dist                0       Experimental. If 1, use a uniform probability distribution when choosing inputs to cross over with. Some of the inputs in the corpus may never get chosen for mutation depending on the input mutation scheduling policy. With this flag, all inputs, regardless of the input mutation scheduling policy, can be chosen as an input to cross over with. This can be particularly useful with |keep_seed==1|; all the initial seed inputs, even though they do not increase coverage because they are not properly formed, will still be chosen as an input to cross over with.
/// mutate_depth                           5       Apply this number of consecutive mutations to each input.
/// reduce_depth                           0       Experimental/internal. Reduce depth if mutations lose unique features
/// shuffle                                1       Shuffle inputs at startup
/// prefer_small                           1       If 1, always prefer smaller inputs during the corpus shuffle.
/// timeout                                1200    Timeout in seconds (if positive). If one unit runs more than this number of seconds the process will abort.
/// error_exitcode                         77      When libFuzzer itself reports a bug this exit code will be used.
/// timeout_exitcode                       70      When libFuzzer reports a timeout this exit code will be used.
/// max_total_time                         0       If positive, indicates the maximal total time in seconds to run the fuzzer.
/// help                                   0       Print help.
/// fork                                   0       Experimental mode where fuzzing happens in a subprocess
/// fork_corpus_groups                     0       For fork mode, enable the corpus-group strategy, The main corpus will be grouped according to size, and each sub-process will randomly select seeds from different groups as the sub-corpus.
/// ignore_timeouts                        1       Ignore timeouts in fork mode
/// ignore_ooms                            1       Ignore OOMs in fork mode
/// ignore_crashes                         0       Ignore crashes in fork mode
/// merge                                  0       If 1, the 2-nd, 3-rd, etc corpora will be merged into the 1-st corpus. Only interesting units will be taken. This flag can be used to minimize a corpus.
/// set_cover_merge                        0       If 1, the 2-nd, 3-rd, etc corpora will be merged into the 1-st corpus. Same as the 'merge' flag, but uses the standard greedy algorithm for the set cover problem to compute an approximation of the minimum set of testcases that provide the same coverage as the initial corpora
/// stop_file                              0       Stop fuzzing ASAP if this file exists
/// merge_control_file                     0       Specify a control file used for the merge process. If a merge process gets killed it tries to leave this file in a state suitable for resuming the merge. By default a temporary file will be used.The same file can be used for multistep merge process.
/// minimize_crash                         0       If 1, minimizes the provided crash input. Use with -runs=N or -max_total_time=N to limit the number attempts. Use with -exact_artifact_path to specify the output. Combine with ASAN_OPTIONS=dedup_token_length=3 (or similar) to ensure that the minimized input triggers the same crash.
/// cleanse_crash                          0       If 1, tries to cleanse the provided crash input to make it contain fewer original bytes. Use with -exact_artifact_path to specify the output.
/// mutation_graph_file                    0       Saves a graph (in DOT format) to mutation_graph_file. The graph contains a vertex for each input that has unique coverage; directed edges are provided between parents and children where the child has unique coverage, and are recorded with the type of mutation that caused the child.
/// use_counters                           1       Use coverage counters
/// use_memmem                             1       Use hints from intercepting memmem, strstr, etc
/// use_value_profile                      0       Experimental. Use value profile to guide fuzzing.
/// use_cmp                                1       Use CMP traces to guide mutations
/// shrink                                 0       Experimental. Try to shrink corpus inputs.
/// reduce_inputs                          1       Try to reduce the size of inputs while preserving their full feature sets
/// jobs                                   0       Number of jobs to run. If jobs >= 1 we spawn this number of jobs in separate worker processes with stdout/stderr redirected to fuzz-JOB.log.
/// workers                                0       Number of simultaneous worker processes to run the jobs. If zero, \"min(jobs,NumberOfCpuCores()/2)\" is used.
/// reload                                 1       Reload the main corpus every <N> seconds to get new units discovered by other processes. If 0, disabled
/// report_slow_units                      10      Report slowest units if they run for more than this number of seconds.
/// only_ascii                             0       If 1, generate only ASCII (isprint+isspace) inputs.
/// dict                                   0       Experimental. Use the dictionary file.
/// artifact_prefix                        0       Write fuzzing artifacts (crash, timeout, or slow inputs) as $(artifact_prefix)file
/// exact_artifact_path                    0       Write the single artifact on failure (crash, timeout) as $(exact_artifact_path). This overrides -artifact_prefix and will not use checksum in the file name. Do not use the same path for several parallel processes.
/// print_pcs                              0       If 1, print out newly covered PCs.
/// print_funcs                            2       If >=1, print out at most this number of newly covered functions.
/// print_final_stats                      0       If 1, print statistics at exit.
/// print_corpus_stats                     0       If 1, print statistics on corpus elements at exit.
/// print_coverage                         0       If 1, print coverage information as text at exit.
/// print_full_coverage                    0       If 1, print full coverage information (all branches) as text at exit.
/// dump_coverage                          0       Deprecated.
/// handle_segv                            1       If 1, try to intercept SIGSEGV.
/// handle_bus                             1       If 1, try to intercept SIGBUS.
/// handle_abrt                            1       If 1, try to intercept SIGABRT.
/// handle_ill                             1       If 1, try to intercept SIGILL.
/// handle_fpe                             1       If 1, try to intercept SIGFPE.
/// handle_int                             1       If 1, try to intercept SIGINT.
/// handle_term                            1       If 1, try to intercept SIGTERM.
/// handle_xfsz                            1       If 1, try to intercept SIGXFSZ.
/// handle_usr1                            1       If 1, try to intercept SIGUSR1.
/// handle_usr2                            1       If 1, try to intercept SIGUSR2.
/// handle_winexcept                       1       If 1, try to intercept uncaught Windows Visual C++ Exceptions.
/// close_fd_mask                          0       If 1, close stdout at startup; if 2, close stderr; if 3, close both. Be careful, this will also close e.g. stderr of asan.
/// detect_leaks                           1       If 1, and if LeakSanitizer is enabled try to detect memory leaks during fuzzing (i.e. not only at shut down).
/// purge_allocator_interval               1       Purge allocator caches and quarantines every <N> seconds. When rss_limit_mb is specified (>0), purging starts when RSS exceeds 50% of rss_limit_mb. Pass purge_allocator_interval=-1 to disable this functionality.
/// trace_malloc                           0       If >= 1 will print all mallocs/frees. If >= 2 will also print stack traces.
/// rss_limit_mb                           2048    If non-zero, the fuzzer will exit upon reaching this limit of RSS memory usage.
/// malloc_limit_mb                        0       If non-zero, the fuzzer will exit if the target tries to allocate this number of Mb with one malloc call. If zero (default) same limit as rss_limit_mb is applied.
/// exit_on_src_pos                        0       Exit if a newly found PC originates from the given source location. Example: -exit_on_src_pos=foo.cc:123. Used primarily for testing libFuzzer itself.
/// exit_on_item                           0       Exit if an item with a given sha1 sum was added to the corpus. Used primarily for testing libFuzzer itself.
/// ignore_remaining_args                  0       If 1, ignore all arguments passed after this one. Useful for fuzzers that need to do their own argument parsing.
/// focus_function                         0       Experimental. Fuzzing will focus on inputs that trigger calls to this function. If -focus_function=auto and -data_flow_trace is used, libFuzzer will choose the focus functions automatically. Disables -entropic when specified.
/// entropic                               1       Enables entropic power schedule.
/// entropic_feature_frequency_threshold   255     Experimental. If entropic is enabled, all features which are observed less often than the specified value are considered as rare.
/// entropic_number_of_rarest_features     100     Experimental. If entropic is enabled, we keep track of the frequencies only for the Top-X least abundant features (union features that are considered as rare).
/// entropic_scale_per_exec_time           0       Experimental. If 1, the Entropic power schedule gets scaled based on the input execution time. Inputs with lower execution time get scheduled more (up to 30x). Note that, if 1, fuzzer stops from being deterministic even if a non-zero random seed is given.
/// analyze_dict                           0       Experimental
/// use_clang_coverage                     0       Deprecated; don't use
/// data_flow_trace                        0       Experimental: use the data flow trace
/// collect_data_flow                      0       Experimental: collect the data flow trace
/// create_missing_dirs                    0       Automatically attempt to create directories for arguments that would normally expect them to already exist (i.e. artifact_prefix, exact_artifact_path, features_dir, corpus)

#[derive(LibFuzzerParse, Debug)]
pub struct LibFuzzerOptions2 {
    #[libfuzzer_parse(default = 1)]
    /// Verbosity level.
    pub verbosity: usize,
    #[libfuzzer_parse(default = 0)]
    /// Random seed. If 0, seed is generated.
    pub seed: usize,
    #[libfuzzer_parse(default = -1)]
    /// Number of individual test runs (-1 for infinite runs).
    pub runs: isize,
    #[libfuzzer_parse(default = 0)]
    /// Maximum length of the test input. Contents of corpus files are going to be truncated to this value. If 0, libFuzzer tries to guess a good value based on the corpus and reports it.
    pub max_len: usize,
    #[libfuzzer_parse(default = 100)]
    /// Try generating small inputs first, then try larger inputs over time.  Specifies the rate at which the length limit is increased (smaller == faster).  If 0, immediately try inputs with size up to max_len. Default value is 0, if LLVMFuzzerCustomMutator is used.
    pub len_control: usize,
    /// A comma-separated list of input files to use as an additional seed corpus. Alternatively, an "@" followed by the name of a file containing the comma-separated list.
    pub seed_inputs: Option<String>,
    #[libfuzzer_parse(default = 0)]
    /// If 1, keep seed inputs in the corpus even if they do not produce new coverage. When used with |reduce_inputs==1|, the seed inputs will never be reduced. This option can be useful when seeds arenot properly formed for the fuzz target but still have useful snippets.
    pub keep_seed: bool,
    #[libfuzzer_parse(default = 1)]
    /// If 1, cross over inputs.
    pub cross_over: bool,
    #[libfuzzer_parse(default = 0)]
    /// Experimental. If 1, use a uniform probability distribution when choosing inputs to cross over with. Some of the inputs in the corpus may never get chosen for mutation depending on the input mutation scheduling policy. With this flag, all inputs, regardless of the input mutation scheduling policy, can be chosen as an input to cross over with. This can be particularly useful with |keep_seed==1|; all the initial seed inputs, even though they do not increase coverage because they are not properly formed, will still be chosen as an input to cross over with.
    pub cross_over_uniform_dist: bool,
    #[libfuzzer_parse(default = 5)]
    /// Apply this number of consecutive mutations to each input.
    pub mutate_depth: usize,
    #[libfuzzer_parse(default = 0)]
    /// Experimental/internal. Reduce depth if mutations lose unique features
    pub reduce_depth: usize,
    #[libfuzzer_parse(default = 1)]
    /// Shuffle inputs at startup
    pub shuffle: bool,
    #[libfuzzer_parse(default = 1)]
    /// If 1, always prefer smaller inputs during the corpus shuffle.
    pub prefer_small: bool,
    #[libfuzzer_parse(default = 1200)]
    /// Timeout in seconds (if positive). If one unit runs more than this number of seconds the process will abort.
    pub timeout: usize,
    #[libfuzzer_parse(default = 77)]
    /// When libFuzzer itself reports a bug this exit code will be used.
    pub error_exitcode: usize,
    #[libfuzzer_parse(default = 70)]
    /// When libFuzzer reports a timeout this exit code will be used.
    pub timeout_exitcode: usize,
    #[libfuzzer_parse(default = 0)]
    /// If positive, indicates the maximal total time in seconds to run the fuzzer.
    pub max_total_time: usize,
    #[libfuzzer_parse(default = 0)]
    /// Print help.
    pub help: bool,
    #[libfuzzer_parse(default = 0)]
    /// Experimental mode where fuzzing happens in a subprocess
    pub fork: usize,
    #[libfuzzer_parse(default = 0)]
    /// For fork mode, enable the corpus-group strategy, The main corpus will be grouped according to size, and each sub-process will randomly select seeds from different groups as the sub-corpus.
    pub fork_corpus_groups: bool,
    #[libfuzzer_parse(default = 1)]
    /// Ignore timeouts in fork mode
    pub ignore_timeouts: bool,
    #[libfuzzer_parse(default = 1)]
    /// Ignore OOMs in fork mode
    pub ignore_ooms: bool,
    #[libfuzzer_parse(default = 0)]
    /// Ignore crashes in fork mode
    pub ignore_crashes: bool,
    #[libfuzzer_parse(default = 0)]
    /// If 1, the 2-nd, 3-rd, etc corpora will be merged into the 1-st corpus. Only interesting units will be taken. This flag can be used to minimize a corpus.
    pub merge: bool,
    #[libfuzzer_parse(default = 0)]
    /// If 1, the 2-nd, 3-rd, etc corpora will be merged into the 1-st corpus. Same as the 'merge' flag, but uses the standard greedy algorithm for the set cover problem to compute an approximation of the minimum set of testcases that provide the same coverage as the initial corpora
    pub set_cover_merge: bool,
    #[libfuzzer_parse(default = "".to_string())]
    /// Stop fuzzing ASAP if this file exists
    pub stop_file: String,
    #[libfuzzer_parse(default = "".to_string())]
    /// Specify a control file used for the merge process. If a merge process gets killed it tries to leave this file in a state suitable for resuming the merge. By default a temporary file will be used.The same file can be used for multistep merge process.
    pub merge_control_file: String,
    #[libfuzzer_parse(default = 0)]
    /// If 1, minimizes the provided crash input. Use with -runs=N or -max_total_time=N to limit the number attempts. Use with -exact_artifact_path to specify the output. Combine with ASAN_OPTIONS=dedup_token_length=3 (or similar) to ensure that the minimized input triggers the same crash.
    pub minimize_crash: bool,
    #[libfuzzer_parse(default = 0)]
    /// If 1, tries to cleanse the provided crash input to make it contain fewer original bytes. Use with -exact_artifact_path to specify the output.
    pub cleanse_crash: bool,
    #[libfuzzer_parse(default = "".to_string())]
    /// Saves a graph (in DOT format) to mutation_graph_file. The graph contains a vertex for each input that has unique coverage; directed edges are provided between parents and children where the child has unique coverage, and are recorded with the type of mutation that caused the child.
    pub mutation_graph_file: String,
    #[libfuzzer_parse(default = 1)]
    /// Use coverage counters
    pub use_counters: bool,
    #[libfuzzer_parse(default = 1)]
    /// Use hints from intercepting memmem, strstr, etc
    pub use_memmem: bool,
    #[libfuzzer_parse(default = 0)]
    /// Experimental. Use value profile to guide fuzzing.
    pub use_value_profile: bool,
    #[libfuzzer_parse(default = 1)]
    /// Use CMP traces to guide mutations
    pub use_cmp: bool,
    #[libfuzzer_parse(default = 0)]
    /// Experimental. Try to shrink corpus inputs.
    pub shrink: bool,
    #[libfuzzer_parse(default = 1)]
    /// Try to reduce the size of inputs while preserving their full feature sets
    pub reduce_inputs: bool,
    #[libfuzzer_parse(default = 0)]
    /// Number of jobs to run. If jobs >= 1 we spawn this number of jobs in separate worker processes with stdout/stderr redirected to fuzz-JOB.log.
    pub jobs: usize,
    #[libfuzzer_parse(default = 0)]
    /// Number of simultaneous worker processes to run the jobs. If zero, "min(jobs,NumberOfCpuCores()/2)" is used.
    pub workers: usize,
    #[libfuzzer_parse(default = 1)]
    /// Reload the main corpus every <N> seconds to get new units discovered by other processes. If 0, disabled
    pub reload: usize,
    #[libfuzzer_parse(default = 10)]
    /// Report slowest units if they run for more than this number of seconds.
    pub report_slow_units: usize,
    #[libfuzzer_parse(default = 0)]
    /// If 1, generate only ASCII (isprint+isspace) inputs.
    pub only_ascii: bool,
    #[libfuzzer_parse(default = "".to_string())]
    /// Experimental. Use the dictionary file.
    pub dict: String,
    #[libfuzzer_parse(default = "".to_string())]
    /// Write fuzzing artifacts (crash, timeout, or slow inputs) as $(artifact_prefix)file
    pub artifact_prefix: String,
    #[libfuzzer_parse(default = "".to_string())]
    /// Write the single artifact on failure (crash, timeout) as $(exact_artifact_path). This overrides -artifact_prefix and will not use checksum in the file name. Do not use the same path for several parallel processes.
    pub exact_artifact_path: String,
    #[libfuzzer_parse(default = 0)]
    /// If 1, print out newly covered PCs.
    pub print_pcs: bool,
    #[libfuzzer_parse(default = 2)]
    /// If >=1, print out at most this number of newly covered functions.
    pub print_funcs: usize,
    #[libfuzzer_parse(default = 0)]
    /// If 1, print statistics at exit.
    pub print_final_stats: bool,
    #[libfuzzer_parse(default = 0)]
    /// If 1, print statistics on corpus elements at exit.
    pub print_corpus_stats: bool,
    #[libfuzzer_parse(default = 0)]
    /// If 1, print coverage information as text at exit.
    pub print_coverage: bool,
    #[libfuzzer_parse(default = 0)]
    /// If 1, print full coverage information (all branches) as text at exit.
    pub print_full_coverage: bool,
    #[libfuzzer_parse(default = 0)]
    /// Deprecated.
    pub dump_coverage: bool,
    #[libfuzzer_parse(default = 1)]
    /// If 1, try to intercept SIGSEGV.
    pub handle_segv: bool,
    #[libfuzzer_parse(default = 1)]
    /// If 1, try to intercept SIGBUS.
    pub handle_bus: bool,
    #[libfuzzer_parse(default = 1)]
    /// If 1, try to intercept SIGABRT.
    pub handle_abrt: bool,
    #[libfuzzer_parse(default = 1)]
    /// If 1, try to intercept SIGILL.
    pub handle_ill: bool,
    #[libfuzzer_parse(default = 1)]
    /// If 1, try to intercept SIGFPE.
    pub handle_fpe: bool,
    #[libfuzzer_parse(default = 1)]
    /// If 1, try to intercept SIGINT.
    pub handle_int: bool,
    #[libfuzzer_parse(default = 1)]
    /// If 1, try to intercept SIGTERM.
    pub handle_term: bool,
    #[libfuzzer_parse(default = 1)]
    /// If 1, try to intercept SIGXFSZ.
    pub handle_xfsz: bool,
    #[libfuzzer_parse(default = 1)]
    /// If 1, try to intercept SIGUSR1.
    pub handle_usr1: bool,
    #[libfuzzer_parse(default = 1)]
    /// If 1, try to intercept SIGUSR2.
    pub handle_usr2: bool,
    #[libfuzzer_parse(default = 1)]
    /// If 1, try to intercept uncaught Windows Visual C++ Exceptions.
    pub handle_winexcept: bool,
    #[libfuzzer_parse(default = 0)]
    /// If 1, close stdout at startup; if 2, close stderr; if 3, close both. Be careful, this will also close e.g. stderr of asan.
    pub close_fd_mask: u8,
    #[libfuzzer_parse(default = 1)]
    /// If 1, and if LeakSanitizer is enabled try to detect memory leaks during fuzzing (i.e. not only at shut down).
    pub detect_leaks: bool,
    #[libfuzzer_parse(default = 1)]
    /// Purge allocator caches and quarantines every <N> seconds. When rss_limit_mb is specified (>0), purging starts when RSS exceeds 50% of rss_limit_mb. Pass purge_allocator_interval=-1 to disable this functionality.
    pub purge_allocator_interval: isize,
    #[libfuzzer_parse(default = 0)]
    /// If >= 1 will print all mallocs/frees. If >= 2 will also print stack traces.
    pub trace_malloc: usize,
    #[libfuzzer_parse(default = 2048)]
    /// If non-zero, the fuzzer will exit upon reaching this limit of RSS memory usage.
    pub rss_limit_mb: usize,
    #[libfuzzer_parse(default = 0)]
    /// If non-zero, the fuzzer will exit if the target tries to allocate this number of Mb with one malloc call. If zero (default) same limit as rss_limit_mb is applied.
    pub malloc_limit_mb: usize,
    #[libfuzzer_parse(default = "".to_string())]
    /// Exit if a newly found PC originates from the given source location. Example: -exit_on_src_pos=foo.cc:123. Used primarily for testing libFuzzer itself.
    pub exit_on_src_pos: String,
    #[libfuzzer_parse(default = "".to_string())]
    /// Exit if an item with a given sha1 sum was added to the corpus. Used primarily for testing libFuzzer itself.
    pub exit_on_item: String,
    #[libfuzzer_parse(default = 0)]
    /// If 1, ignore all arguments passed after this one. Useful for fuzzers that need to do their own argument parsing.
    pub ignore_remaining_args: bool,
    #[libfuzzer_parse(default = "".to_string())]
    /// Experimental. Fuzzing will focus on inputs that trigger calls to this function. If -focus_function=auto and -data_flow_trace is used, libFuzzer will choose the focus functions automatically. Disables -entropic when specified.
    pub focus_function: String,
    #[libfuzzer_parse(default = 1)]
    /// Enables entropic power schedule.
    pub entropic: bool,
    #[libfuzzer_parse(default = 255)]
    /// Experimental. If entropic is enabled, all features which are observed less often than the specified value are considered as rare.
    pub entropic_feature_frequency_threshold: usize,
    #[libfuzzer_parse(default = 100)]
    /// Experimental. If entropic is enabled, we keep track of the frequencies only for the Top-X least abundant features (union features that are considered as rare).
    pub entropic_number_of_rarest_features: usize,
    #[libfuzzer_parse(default = 0)]
    /// Experimental. If 1, the Entropic power schedule gets scaled based on the input execution time. Inputs with lower execution time get scheduled more (up to 30x). Note that, if 1, fuzzer stops from being deterministic even if a non-zero random seed is given.
    pub entropic_scale_per_exec_time: bool,
    #[libfuzzer_parse(default = 0)]
    /// Experimental
    pub analyze_dict: bool,
    #[libfuzzer_parse(default = 0)]
    /// Deprecated; don't use
    pub use_clang_coverage: bool,
    #[libfuzzer_parse(default = 0)]
    /// Experimental: use the data flow trace
    pub data_flow_trace: bool,
    #[libfuzzer_parse(default = 0)]
    /// Experimental: collect the data flow trace
    pub collect_data_flow: bool,
    #[libfuzzer_parse(default = 0)]
    /// Automatically attempt to create directories for arguments that would normally expect them to already exist (i.e. artifact_prefix, exact_artifact_path, features_dir, corpus)
    pub create_missing_dirs: bool,
    pub rest: Vec<String>,
}

enum RawOption<'a> {
    Directory(&'a str),
    File(&'a str),
    Flag { name: &'a str, value: &'a str },
}

fn parse_option(arg: &str) -> Option<RawOption<'_>> {
    if arg.starts_with("--") {
        None
    } else if arg.starts_with('-') {
        if let Some((name, value)) = arg.split_at(1).1.split_once('=') {
            Some(Flag { name, value })
        } else {
            eprintln!("warning: flag {arg} provided without a value; did you mean `{arg}=1'?");
            None
        }
    } else if PathBuf::from(arg).is_file() {
        Some(File(arg))
    } else {
        Some(Directory(arg))
    }
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum LibfuzzerMode {
    Fuzz,
    Merge,
    Tmin,
    Report,
}

#[derive(Debug)]
pub enum OptionsParseError<'a> {
    MultipleModesSelected,
    OptionValueParseFailed(&'a str, &'a str),
}

impl Display for OptionsParseError<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            OptionsParseError::MultipleModesSelected => {
                f.write_str("multiple modes selected in options")
            }
            OptionsParseError::OptionValueParseFailed(name, value) => {
                f.write_fmt(format_args!("couldn't parse value `{value}' for {name}"))
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactPrefix {
    dir: PathBuf,
    filename_prefix: String,
}

impl ArtifactPrefix {
    fn new(path: &str) -> ArtifactPrefix {
        let mut dir = PathBuf::from(path);
        if path.ends_with(std::path::MAIN_SEPARATOR) {
            Self {
                dir,
                filename_prefix: String::new(),
            }
        } else {
            let filename_prefix = dir.file_name().map_or_else(String::new, |s| {
                s.to_os_string()
                    .into_string()
                    .expect("Provided artifact prefix is not usable")
            });
            dir.pop();
            Self {
                dir,
                filename_prefix,
            }
        }
    }

    pub fn dir(&self) -> &PathBuf {
        &self.dir
    }

    pub fn filename_prefix(&self) -> &str {
        &self.filename_prefix
    }
}

impl Default for ArtifactPrefix {
    fn default() -> Self {
        Self {
            dir: std::env::current_dir().expect("Must be able to get the current directory!"),
            filename_prefix: String::new(),
        }
    }
}

#[derive(Debug, Clone)]
#[expect(clippy::struct_excessive_bools)]
pub struct LibfuzzerOptions {
    #[allow(unused)]
    fuzzer_name: String,
    mode: LibfuzzerMode,
    artifact_prefix: ArtifactPrefix,
    timeout: Duration,
    grimoire: Option<bool>,
    use_value_profile: bool,
    unicode: bool,
    forks: Option<usize>,
    dict: Option<Tokens>,
    dirs: Vec<PathBuf>,
    files: Vec<PathBuf>,
    ignore_crashes: bool,
    ignore_timeouts: bool,
    ignore_ooms: bool,
    rss_limit: usize,
    malloc_limit: usize,
    dedup: bool,
    shrink: bool,
    skip_tracing: bool,
    tui: bool,
    runs: usize,
    #[allow(unused)]
    close_fd_mask: u8,
    create_missing_dirs: bool,
    max_len: Option<usize>,
    len_control: Option<usize>,
    unknown: Vec<String>,
}

impl LibfuzzerOptions {
    pub fn new<'a>(mut args: impl Iterator<Item = &'a str>) -> Result<Self, OptionsParseError<'a>> {
        let name = args.next().unwrap();
        let name = if let Some(executable) = std::env::current_exe().ok().and_then(|path| {
            path.file_name()
                .and_then(std::ffi::OsStr::to_str)
                .map(ToString::to_string)
        }) {
            executable
        } else {
            name.to_string()
        };
        args.try_fold(LibfuzzerOptionsBuilder::default(), |builder, arg| {
            builder.consume(arg)
        })
        .map(|builder| builder.build(name))
    }

    #[cfg(unix)]
    pub fn fuzzer_name(&self) -> &str {
        &self.fuzzer_name
    }

    pub fn mode(&self) -> &LibfuzzerMode {
        &self.mode
    }

    pub fn artifact_prefix(&self) -> &ArtifactPrefix {
        &self.artifact_prefix
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub fn grimoire(&self) -> Option<bool> {
        self.grimoire
    }

    pub fn use_value_profile(&self) -> bool {
        self.use_value_profile
    }

    pub fn unicode(&self) -> bool {
        self.unicode
    }

    pub fn forks(&self) -> Option<usize> {
        self.forks
    }

    pub fn dict(&self) -> Option<&Tokens> {
        self.dict.as_ref()
    }

    pub fn files(&self) -> &[PathBuf] {
        &self.files
    }

    pub fn dirs(&self) -> &[PathBuf] {
        &self.dirs
    }

    pub fn ignore_crashes(&self) -> bool {
        self.ignore_crashes
    }

    pub fn ignore_timeouts(&self) -> bool {
        self.ignore_timeouts
    }

    pub fn ignore_ooms(&self) -> bool {
        self.ignore_ooms
    }

    pub fn rss_limit(&self) -> usize {
        self.rss_limit
    }

    pub fn malloc_limit(&self) -> usize {
        self.malloc_limit
    }

    pub fn dedup(&self) -> bool {
        self.dedup
    }

    pub fn shrink(&self) -> bool {
        self.shrink
    }

    pub fn skip_tracing(&self) -> bool {
        self.skip_tracing
    }

    pub fn tui(&self) -> bool {
        self.tui
    }

    pub fn runs(&self) -> usize {
        self.runs
    }

    #[cfg(unix)]
    pub fn close_fd_mask(&self) -> u8 {
        self.close_fd_mask
    }

    pub fn create_missing_dirs(&self) -> bool {
        self.create_missing_dirs
    }

    pub fn max_len(&self) -> Option<usize> {
        self.max_len
    }

    pub fn len_control(&self) -> Option<usize> {
        self.len_control
    }

    pub fn unknown(&self) -> &[String] {
        &self.unknown
    }
}

#[derive(Debug, Default)]
#[expect(clippy::struct_excessive_bools)]
struct LibfuzzerOptionsBuilder<'a> {
    mode: Option<LibfuzzerMode>,
    artifact_prefix: Option<&'a str>,
    timeout: Option<Duration>,
    grimoire: Option<bool>,
    use_value_profile: Option<bool>,
    unicode: Option<bool>,
    forks: Option<usize>,
    dict: Option<&'a str>,
    dirs: Vec<&'a str>,
    files: Vec<&'a str>,
    ignore_crashes: Option<bool>,
    ignore_timeouts: Option<bool>,
    ignore_ooms: Option<bool>,
    rss_limit: Option<usize>,
    malloc_limit: Option<usize>,
    ignore_remaining: bool,
    dedup: bool,
    shrink: bool,
    skip_tracing: bool,
    tui: bool,
    runs: usize,
    close_fd_mask: u8,
    create_missing_dirs: bool,
    max_len: Option<usize>,
    len_control: Option<usize>,
    unknown: Vec<&'a str>,
}

macro_rules! parse_or_bail {
    ($name:expr, $parsed:expr, $ty:ty) => {{
        if let Ok(val) = $parsed.parse::<$ty>() {
            val
        } else {
            return Err(OptionsParseError::OptionValueParseFailed($name, $parsed));
        }
    }};
}

impl<'a> LibfuzzerOptionsBuilder<'a> {
    fn consume(mut self, arg: &'a str) -> Result<Self, OptionsParseError<'a>> {
        if !self.ignore_remaining {
            if let Some(option) = parse_option(arg) {
                match option {
                    Directory(dir) => {
                        self.dirs.push(dir);
                    }
                    File(file) => {
                        self.files.push(file);
                    }
                    Flag { name, value } => match name {
                        "merge" => {
                            if parse_or_bail!(name, value, u64) > 0
                                && *self.mode.get_or_insert(LibfuzzerMode::Merge)
                                    != LibfuzzerMode::Merge
                            {
                                return Err(OptionsParseError::MultipleModesSelected);
                            }
                        }
                        "minimize_crash" => {
                            if parse_or_bail!(name, value, u64) > 0
                                && *self.mode.get_or_insert(LibfuzzerMode::Tmin)
                                    != LibfuzzerMode::Tmin
                            {
                                return Err(OptionsParseError::MultipleModesSelected);
                            }
                        }
                        "report" => {
                            if parse_or_bail!(name, value, u64) > 0
                                && *self.mode.get_or_insert(LibfuzzerMode::Report)
                                    != LibfuzzerMode::Report
                            {
                                return Err(OptionsParseError::MultipleModesSelected);
                            }
                        }
                        "grimoire" => self.grimoire = Some(parse_or_bail!(name, value, u64) > 0),
                        "use_value_profile" => {
                            self.use_value_profile = Some(parse_or_bail!(name, value, u64) > 0);
                        }
                        "unicode" => self.unicode = Some(parse_or_bail!(name, value, u64) > 0),
                        "artifact_prefix" => {
                            self.artifact_prefix = Some(value);
                        }
                        "timeout" => {
                            self.timeout =
                                Some(value.parse().map(Duration::from_secs_f64).map_err(|_| {
                                    OptionsParseError::OptionValueParseFailed(name, value)
                                })?);
                        }
                        "dict" => self.dict = Some(value),
                        #[cfg(not(windows))]
                        "fork" | "jobs" => {
                            self.forks = Some(parse_or_bail!(name, value, usize));
                            eprintln!("Running {} workers", self.forks.unwrap());
                        }
                        "ignore_crashes" => {
                            self.ignore_crashes = Some(parse_or_bail!(name, value, u64) > 0);
                        }
                        "ignore_timeouts" => {
                            self.ignore_timeouts = Some(parse_or_bail!(name, value, u64) > 0);
                        }
                        "ignore_ooms" => {
                            self.ignore_ooms = Some(parse_or_bail!(name, value, u64) > 0);
                        }
                        "rss_limit_mb" => {
                            self.rss_limit = Some(parse_or_bail!(name, value, usize) << 20);
                        }
                        "malloc_limit_mb" => {
                            self.malloc_limit = Some(parse_or_bail!(name, value, usize) << 20);
                        }
                        "ignore_remaining_args" => {
                            self.ignore_remaining = parse_or_bail!(name, value, u64) > 0;
                        }
                        "dedup" => self.dedup = parse_or_bail!(name, value, u64) > 0,
                        "shrink" => self.shrink = parse_or_bail!(name, value, u64) > 0,
                        "skip_tracing" => self.skip_tracing = parse_or_bail!(name, value, u64) > 0,
                        "tui" => {
                            self.tui = parse_or_bail!(name, value, u64) > 0;
                            if self.tui {
                                if self.ignore_crashes.is_none() {
                                    self.ignore_crashes = Some(true);
                                }
                                if self.ignore_timeouts.is_none() {
                                    self.ignore_timeouts = Some(true);
                                }
                                if self.ignore_ooms.is_none() {
                                    self.ignore_ooms = Some(true);
                                }
                            }
                        }
                        "runs" => self.runs = parse_or_bail!(name, value, usize),
                        "close_fd_mask" => self.close_fd_mask = parse_or_bail!(name, value, u8),
                        "help" => {
                            println!(
                                "Usage:\n\
                                \n\
                                To run fuzzing pass 0 or more directories.\n\
                                {name} [-flag1=val1 [-flag2=val2 ...] ] [dir1 [dir2 ...] ]\n\
                                \n\
                                To run individual tests without fuzzing pass 1 or more files:\n\
                                {name} [-flag1=val1 [-flag2=val2 ...] ] file1 [file2 ...]\n\
                                \n\
                                Flags: (strictly in form -flag=value)\n\
                                artifact_prefix                        0       Write fuzzing artifacts (crash, timeout, or slow inputs) as $(artifact_prefix)file\n\
                                timeout                                1200    Timeout in seconds. If one unit runs more than this number of seconds the process will abort.\n\
                                grimoire                               0       If 1, enable the Grimoire mutator that is structure-aware.\n\
                                use_value_profile                      0       Use value profile to guide fuzzing.\n\
                                unicode                                1       If 1, generate Unicode inputs.\n\
                                dict                                   0       Use the dictionary file.\n\
                                fork                                   0       Number of forks to use (>1 requires Unix-like OS).\n\
                                jobs                                   0       Same as fork. Number of jobs to run with stdout/stderr redirected.\n\
                                ignore_crashes                         0       If 1, ignore crashes in fork mode.\n\
                                ignore_timeouts                        0       If 1, ignore timeouts in fork mode.\n\
                                ignore_ooms                            0       If 1, ignore out-of-memory errors in fork mode.\n\
                                rss_limit_mb                           2048    If non-zero, the fuzzer will exit upon reaching this limit of RSS memory usage (in Mb).\n\
                                malloc_limit_mb                        2048    If non-zero, the fuzzer will exit if the target tries to allocate this number of Mb with one malloc call.\n\
                                ignore_remaining_args                  0       If 1, ignore all arguments passed after this one.\n\
                                dedup                                  0       If 1, deduplicate corpus elements.\n\
                                shrink                                 0       If 1, try to shrink corpus elements.\n\
                                skip_tracing                           0       If 1, skip coverage tracing for faster execution.\n\
                                tui                                    0       If 1, use the terminal UI interface.\n\
                                runs                                   0       Number of individual test runs (0 for infinite runs).\n\
                                close_fd_mask                          0       If 1, close stdout; if 2, close stderr; if 3, close both.\n\
                                merge                                  0       If 1, merge multiple corpora into a single one.\n\
                                minimize_crash                         0       If 1, minimize crashes to their smallest reproducing input.\n\
                                report                                 0       If 1, report statistics without actually fuzzing.\n\
                                help                                   0       Print this help message.\n\
                                verbosity                              1       Verbosity level.

                                seed                                   0       Random seed. If 0, seed is generated.
                                runs                                   -1      Number of individual test runs (-1 for infinite runs).
                                max_len                                0       Maximum length of the test input. Contents of corpus files are going to be truncated to this value. If 0, libFuzzer tries to guess a good value based on the corpus and reports it.
                                len_control                            100     Try generating small inputs first, then try larger inputs over time.  Specifies the rate at which the length limit is increased (smaller == faster).  If 0, immediately try inputs with size up to max_len. Default value is 0, if LLVMFuzzerCustomMutator is used.
                                seed_inputs                            0       A comma-separated list of input files to use as an additional seed corpus. Alternatively, an \"@\" followed by the name of a file containing the comma-separated list.
                                keep_seed                              0       If 1, keep seed inputs in the corpus even if they do not produce new coverage. When used with |reduce_inputs==1|, the seed inputs will never be reduced. This option can be useful when seeds arenot properly formed for the fuzz target but still have useful snippets.
                                cross_over                             1       If 1, cross over inputs.
                                cross_over_uniform_dist                0       Experimental. If 1, use a uniform probability distribution when choosing inputs to cross over with. Some of the inputs in the corpus may never get chosen for mutation depending on the input mutation scheduling policy. With this flag, all inputs, regardless of the input mutation scheduling policy, can be chosen as an input to cross over with. This can be particularly useful with |keep_seed==1|; all the initial seed inputs, even though they do not increase coverage because they are not properly formed, will still be chosen as an input to cross over with.
                                mutate_depth                           5       Apply this number of consecutive mutations to each input.
                                reduce_depth                           0       Experimental/internal. Reduce depth if mutations lose unique features
                                shuffle                                1       Shuffle inputs at startup
                                prefer_small                           1       If 1, always prefer smaller inputs during the corpus shuffle.
                                timeout                                1200    Timeout in seconds (if positive). If one unit runs more than this number of seconds the process will abort.
                                error_exitcode                         77      When libFuzzer itself reports a bug this exit code will be used.
                                timeout_exitcode                       70      When libFuzzer reports a timeout this exit code will be used.
                                max_total_time                         0       If positive, indicates the maximal total time in seconds to run the fuzzer.
                                help                                   0       Print help.
                                fork                                   0       Experimental mode where fuzzing happens in a subprocess
                                fork_corpus_groups                     0       For fork mode, enable the corpus-group strategy, The main corpus will be grouped according to size, and each sub-process will randomly select seeds from different groups as the sub-corpus.
                                ignore_timeouts                        1       Ignore timeouts in fork mode
                                ignore_ooms                            1       Ignore OOMs in fork mode
                                ignore_crashes                         0       Ignore crashes in fork mode
                                merge                                  0       If 1, the 2-nd, 3-rd, etc corpora will be merged into the 1-st corpus. Only interesting units will be taken. This flag can be used to minimize a corpus.
                                set_cover_merge                        0       If 1, the 2-nd, 3-rd, etc corpora will be merged into the 1-st corpus. Same as the 'merge' flag, but uses the standard greedy algorithm for the set cover problem to compute an approximation of the minimum set of testcases that provide the same coverage as the initial corpora
                                stop_file                              0       Stop fuzzing ASAP if this file exists
                                merge_control_file                     0       Specify a control file used for the merge process. If a merge process gets killed it tries to leave this file in a state suitable for resuming the merge. By default a temporary file will be used.The same file can be used for multistep merge process.
                                minimize_crash                         0       If 1, minimizes the provided crash input. Use with -runs=N or -max_total_time=N to limit the number attempts. Use with -exact_artifact_path to specify the output. Combine with ASAN_OPTIONS=dedup_token_length=3 (or similar) to ensure that the minimized input triggers the same crash.
                                cleanse_crash                          0       If 1, tries to cleanse the provided crash input to make it contain fewer original bytes. Use with -exact_artifact_path to specify the output.
                                mutation_graph_file                    0       Saves a graph (in DOT format) to mutation_graph_file. The graph contains a vertex for each input that has unique coverage; directed edges are provided between parents and children where the child has unique coverage, and are recorded with the type of mutation that caused the child.
                                use_counters                           1       Use coverage counters
                                use_memmem                             1       Use hints from intercepting memmem, strstr, etc
                                use_value_profile                      0       Experimental. Use value profile to guide fuzzing.
                                use_cmp                                1       Use CMP traces to guide mutations
                                shrink                                 0       Experimental. Try to shrink corpus inputs.
                                reduce_inputs                          1       Try to reduce the size of inputs while preserving their full feature sets
                                jobs                                   0       Number of jobs to run. If jobs >= 1 we spawn this number of jobs in separate worker processes with stdout/stderr redirected to fuzz-JOB.log.
                                workers                                0       Number of simultaneous worker processes to run the jobs. If zero, \"min(jobs,NumberOfCpuCores()/2)\" is used.
                                reload                                 1       Reload the main corpus every <N> seconds to get new units discovered by other processes. If 0, disabled
                                report_slow_units                      10      Report slowest units if they run for more than this number of seconds.
                                only_ascii                             0       If 1, generate only ASCII (isprint+isspace) inputs.
                                dict                                   0       Experimental. Use the dictionary file.
                                artifact_prefix                        0       Write fuzzing artifacts (crash, timeout, or slow inputs) as $(artifact_prefix)file
                                exact_artifact_path                    0       Write the single artifact on failure (crash, timeout) as $(exact_artifact_path). This overrides -artifact_prefix and will not use checksum in the file name. Do not use the same path for several parallel processes.
                                print_pcs                              0       If 1, print out newly covered PCs.
                                print_funcs                            2       If >=1, print out at most this number of newly covered functions.
                                print_final_stats                      0       If 1, print statistics at exit.
                                print_corpus_stats                     0       If 1, print statistics on corpus elements at exit.
                                print_coverage                         0       If 1, print coverage information as text at exit.
                                print_full_coverage                    0       If 1, print full coverage information (all branches) as text at exit.
                                dump_coverage                          0       Deprecated.
                                handle_segv                            1       If 1, try to intercept SIGSEGV.
                                handle_bus                             1       If 1, try to intercept SIGBUS.
                                handle_abrt                            1       If 1, try to intercept SIGABRT.
                                handle_ill                             1       If 1, try to intercept SIGILL.
                                handle_fpe                             1       If 1, try to intercept SIGFPE.
                                handle_int                             1       If 1, try to intercept SIGINT.
                                handle_term                            1       If 1, try to intercept SIGTERM.
                                handle_xfsz                            1       If 1, try to intercept SIGXFSZ.
                                handle_usr1                            1       If 1, try to intercept SIGUSR1.
                                handle_usr2                            1       If 1, try to intercept SIGUSR2.
                                handle_winexcept                       1       If 1, try to intercept uncaught Windows Visual C++ Exceptions.
                                close_fd_mask                          0       If 1, close stdout at startup; if 2, close stderr; if 3, close both. Be careful, this will also close e.g. stderr of asan.
                                detect_leaks                           1       If 1, and if LeakSanitizer is enabled try to detect memory leaks during fuzzing (i.e. not only at shut down).
                                purge_allocator_interval               1       Purge allocator caches and quarantines every <N> seconds. When rss_limit_mb is specified (>0), purging starts when RSS exceeds 50% of rss_limit_mb. Pass purge_allocator_interval=-1 to disable this functionality.
                                trace_malloc                           0       If >= 1 will print all mallocs/frees. If >= 2 will also print stack traces.
                                rss_limit_mb                           2048    If non-zero, the fuzzer will exit upon reaching this limit of RSS memory usage.
                                malloc_limit_mb                        0       If non-zero, the fuzzer will exit if the target tries to allocate this number of Mb with one malloc call. If zero (default) same limit as rss_limit_mb is applied.
                                exit_on_src_pos                        0       Exit if a newly found PC originates from the given source location. Example: -exit_on_src_pos=foo.cc:123. Used primarily for testing libFuzzer itself.
                                exit_on_item                           0       Exit if an item with a given sha1 sum was added to the corpus. Used primarily for testing libFuzzer itself.
                                ignore_remaining_args                  0       If 1, ignore all arguments passed after this one. Useful for fuzzers that need to do their own argument parsing.
                                focus_function                         0       Experimental. Fuzzing will focus on inputs that trigger calls to this function. If -focus_function=auto and -data_flow_trace is used, libFuzzer will choose the focus functions automatically. Disables -entropic when specified.
                                entropic                               1       Enables entropic power schedule.
                                entropic_feature_frequency_threshold   255     Experimental. If entropic is enabled, all features which are observed less often than the specified value are considered as rare.
                                entropic_number_of_rarest_features     100     Experimental. If entropic is enabled, we keep track of the frequencies only for the Top-X least abundant features (union features that are considered as rare).
                                entropic_scale_per_exec_time           0       Experimental. If 1, the Entropic power schedule gets scaled based on the input execution time. Inputs with lower execution time get scheduled more (up to 30x). Note that, if 1, fuzzer stops from being deterministic even if a non-zero random seed is given.
                                analyze_dict                           0       Experimental
                                use_clang_coverage                     0       Deprecated; don't use
                                data_flow_trace                        0       Experimental: use the data flow trace
                                collect_data_flow                      0       Experimental: collect the data flow trace
                                create_missing_dirs                    0       Automatically attempt to create directories for arguments that would normally expect them to already exist (i.e. artifact_prefix, exact_artifact_path, features_dir, corpus)
                                \n\
                                Flags starting with '--' will be ignored and will be passed verbatim to subprocesses.\n\
                            "
                            );
                            std::process::exit(0);
                        }
                        "create_missing_dirs" => {
                            self.create_missing_dirs = parse_or_bail!(name, value, u64) > 0;
                        }
                        "max_len" => self.max_len = Some(parse_or_bail!(name, value, usize)),
                        "len_control" => {
                            self.len_control = Some(parse_or_bail!(name, value, usize))
                        }
                        _ => {
                            self.unknown.push(arg);
                        }
                    },
                }
            } else {
                self.unknown.push(arg);
            }
        }
        Ok(self)
    }

    fn build(self, fuzzer_name: String) -> LibfuzzerOptions {
        LibfuzzerOptions {
            fuzzer_name,
            mode: self.mode.unwrap_or(LibfuzzerMode::Fuzz),
            artifact_prefix: {
                let artifact_prefix = self
                    .artifact_prefix
                    .map(ArtifactPrefix::new)
                    .unwrap_or_default();
                if self.create_missing_dirs && !artifact_prefix.dir().exists() {
                    std::fs::create_dir_all(artifact_prefix.dir()).unwrap_or_else(|_| {
                        panic!(
                            "Could not create artifact prefix directory {:?}!",
                            artifact_prefix.dir()
                        )
                    });
                }
                artifact_prefix
            },
            timeout: self.timeout.unwrap_or(Duration::from_secs(1200)),
            grimoire: self.grimoire,
            use_value_profile: self.use_value_profile.unwrap_or(false),
            unicode: self.unicode.unwrap_or(true),
            forks: self.forks,
            dict: self.dict.map(|path| {
                Tokens::from_file(path).expect("Couldn't load tokens from specified tokens file")
            }),
            dirs: {
                let dirs = self.dirs.into_iter().map(PathBuf::from).collect::<Vec<_>>();
                if self.create_missing_dirs {
                    for dir in &dirs {
                        if !dir.exists() {
                            std::fs::create_dir_all(dir)
                                .unwrap_or_else(|_| panic!("Could not create directory {dir:?}!"));
                        }
                    }
                }
                dirs
            },
            files: self.files.into_iter().map(PathBuf::from).collect(),
            ignore_crashes: self.ignore_crashes.unwrap_or_default(),
            ignore_timeouts: self.ignore_timeouts.unwrap_or_default(),
            ignore_ooms: self.ignore_ooms.unwrap_or_default(),
            rss_limit: match self.rss_limit.unwrap_or(2 << 30) {
                0 => usize::MAX,
                value => value,
            },
            malloc_limit: match self.malloc_limit.or(self.rss_limit).unwrap_or(2 << 30) {
                0 => usize::MAX,
                value => value,
            },
            dedup: self.dedup,
            shrink: self.shrink,
            skip_tracing: self.skip_tracing,
            tui: self.tui,
            runs: self.runs,
            close_fd_mask: self.close_fd_mask,
            create_missing_dirs: self.create_missing_dirs,
            max_len: {
                if self.max_len.is_none() {
                    eprintln!(
                        "INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes"
                    );
                    Some(4096)
                } else {
                    self.max_len
                }
            },
            len_control: self.len_control,
            unknown: self.unknown.into_iter().map(ToString::to_string).collect(),
        }
    }
}

#[cfg(test)]
mod test {
    use libafl::LibFuzzerParse;

    #[allow(unused)]
    #[derive(LibFuzzerParse, Debug)]
    pub struct LibFuzzerOptionsTest {
        #[libfuzzer_parse(default = "default_string".to_string())]
        pub string_with_default: String,
        #[libfuzzer_parse(default = 42)]
        pub int_with_default: usize,
        pub string_no_default: Option<String>,
        pub int_no_default: Option<usize>,
        pub path: Option<std::path::PathBuf>,
        pub rest: Vec<String>,
    }

    #[test]
    fn test_parse() {
        let opts = LibFuzzerOptionsTest::parse_libfuzzer([
            "-string_with_default=hello",
            "-int_with_default=123",
            "-string_no_default=world",
            "-int_no_default=456",
            "-path=/tmp/some/path",
            "extra1",
            "extra2",
        ]);
        assert_eq!(opts.string_with_default, "hello");
        assert_eq!(opts.int_with_default, 123);
        assert_eq!(opts.string_no_default.as_deref(), Some("world"));
        assert_eq!(opts.int_no_default, Some(456));
        assert_eq!(
            opts.path.as_deref(),
            Some(std::path::Path::new("/tmp/some/path"))
        );
        assert_eq!(opts.rest, vec!["extra1", "extra2"]);
    }
}
