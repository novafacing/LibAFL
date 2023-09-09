//! Configuration parameters for `libafl_cc`. Allows project-local, user, and global configuration
//! of `libafl_cc`

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::LLVMPass;

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Pass {}

#[derive(Deserialize, Serialize, Clone, Debug, Default)]
#[serde(default)]
/// Serializable configuration for the clang wrapper
pub struct CCWrapperConfiguration {
    /// The `cc` command being wrapped. Defaults to `clang`.
    cc: Option<String>,
    /// The `cc` command being wrapped. Defaults to `clang++`.
    cxx: Option<String>,
    /// Additional arguments to pass to the compiler on every invocation. Passed to all commands,
    /// whether linking or not.
    args: Vec<String>,
    #[serde(alias = "cc-args")]
    /// Additional arguments to pass to the compiler on every invocation. Passed only to
    /// non-linking commands.
    cc_args: Vec<String>,
    #[serde(alias = "cxx-args")]
    /// Additional arguments to pass to the compiler on every invocation. Passed only to
    /// non-linking commands, and only running in C++ mode.
    cxx_args: Vec<String>,
    /// Additional arguments to pass to the compiler on every invocation. Passed only to
    /// linking commands.
    link_args: Vec<String>,
    /// LibAFL passes to enable.
    passes: Vec<LLVMPass>,
    #[serde(alias = "pass-args")]
    /// Arguments to pass to the compiler on every invocation. Passed only when compiling with at
    /// least one LibAFL pass in `passes`.
    pass_args: Vec<String>,
    #[serde(alias = "pass-link-args")]
    /// Arguments to pass to the compiler on every invocation. Passed only when compiling with at
    /// least one LibAFL pass in `passes`. Passed only to linking commands.
    pass_link_args: Vec<String>,
    /// Profiles that should be added to this configuration. Profiles are common sets of arguments
    /// for example to enable the expected sanitizers for compiling libfuzzer compatible fuzzers
    /// with `libafl_libfuzzer`.
    #[serde(alias = "requires-libafl-arg")]
    /// Whether the `--libafl` argument must be passed to the compiler to enable this
    /// configuration. When set to true and `--libafl` is not passed to the compiler, no additional
    /// configuration is performed and arguments are passed directly to the normal compiler
    /// invocation. This is useful in some niche cases (particularly with CMake and autotools)
    /// where instrumentation and additional compilation steps need to be disabled during compiler
    /// feature checks.
    requires_libafl_arg: bool,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default)]
#[serde(default)]
pub struct ArWrapperConfiguration {
    args: Vec<String>,
    silent: bool,
    #[serde(alias = "requires-libafl-arg")]
    requires_libafl_arg: bool,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default)]
#[serde(default)]
pub struct LibtoolWrapperConfiguration {
    args: Vec<String>,
    silent: bool,
    #[serde(alias = "requires-libafl-arg")]
    requires_libafl_arg: bool,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default)]
#[serde(default)]
pub struct ToolConfiguration {
    cc: Option<CCWrapperConfiguration>,
    ar: Option<ArWrapperConfiguration>,
    libtool: Option<LibtoolWrapperConfiguration>,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Configuration {
    #[serde(alias = "tool-configuration")]
    tool_configuration: HashMap<String, ToolConfiguration>,
}

#[cfg(test)]
mod test {
    use anyhow::Result;
    use indoc::indoc;
    use toml::from_str;

    use crate::configuration::Configuration;

    #[test]
    fn test_default() -> Result<()> {
        const DEFAULT: &str = indoc! {r#"
            [tool-configuration.default.cc]
            args = []

            [tool-configuration.default.ar]
            args = []

            [tool-configuration.default.libtool]
            args = []
        "#};

        let config: Configuration = from_str(DEFAULT)?;

        println!("{config:#?}");

        Ok(())
    }
}
