use anyhow::{anyhow, bail, Result};
use clap::{
    error::{ContextKind, ContextValue, ErrorKind},
    ArgMatches, Command, CommandFactory, FromArgMatches, Parser,
};
use std::env::args;

#[derive(Debug, Clone)]
struct Known<T>
where
    T: FromArgMatches,
{
    matches: T,
    rest: Vec<String>,
}

impl<T> Known<T>
where
    T: FromArgMatches,
{
    pub fn new<I, S>(matches: ArgMatches, rest: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Ok(Self {
            matches: T::from_arg_matches(&matches)?,
            rest: rest.into_iter().map(|a| a.as_ref().to_string()).collect(),
        })
    }
}

trait ParseKnown: FromArgMatches {
    fn parse_known() -> Result<Known<Self>>;
}

impl<T> ParseKnown for T
where
    T: CommandFactory + FromArgMatches,
{
    fn parse_known() -> Result<Known<T>> {
        let command = Self::command();
        let mut rest = Vec::new();
        let mut args = args().collect::<Vec<_>>();

        loop {
            match command.clone().try_get_matches_from(&args) {
                Ok(matches) => {
                    return Known::new(matches, rest);
                }
                Err(e) if matches!(e.kind(), ErrorKind::UnknownArgument) => {
                    if let Some(ContextValue::String(v)) = e
                        .context()
                        .find_map(|(k, v)| matches!(k, ContextKind::InvalidArg).then_some(v))
                    {
                        let unknown = args
                            .iter()
                            .find(|a| a.starts_with(v))
                            .cloned()
                            .ok_or_else(|| anyhow!("No argument starts with {}", v))?;

                        if args.contains(&unknown) {
                            args.retain(|a| a != &unknown);
                            rest.push(unknown);
                        } else {
                            bail!("Got unknown argument {} but it is not in args at all.", v);
                        }
                    } else {
                        bail!("No string value found for unknown argument: {}", e);
                    }
                }
                Err(e) => bail!("Error getting matches from args '{:?}': {}", args, e),
            }
        }
    }
}

#[derive(Parser, Debug, Clone)]
#[clap(
    allow_hyphen_values = true,
    trailing_var_arg = true,
    disable_help_flag = true,
    disable_version_flag = true
)]
struct Args {
    #[arg(long)]
    libafl_no_link: bool,
    #[arg(long)]
    libafl: bool,
    #[arg(long)]
    libafl_ignore_configurations: bool,
    #[arg(long, value_delimiter = ',')]
    libafl_configurations: Vec<String>,
}

fn main() -> Result<()> {
    let args = Args::parse_known()?;
    let (args, tool_args) = (args.matches, args.rest);
    println!("{:#?}", args);
    Ok(())
}
