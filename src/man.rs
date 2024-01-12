/// Generate Unix manual pages for sq from its `clap::Command` value.
///
/// A Unix manual page is a document marked up with the
/// [troff](https://en.wikipedia.org/wiki/Troff) language. The troff
/// markup is the source code for the page, and is formatted and
/// displayed using the "man" command.
///
/// Troff is a child of the 1970s and is one of the earlier markup
/// languages. It has little resemblance to markup languages born in
/// the 21st century, such as Markdown. However, it's not actually
/// difficult, merely old, and sometimes weird. Some of the design of
/// the troff language was dictated by the constraints of 1970s
/// hardware, programming languages, and fashions in programming. Let
/// not those scare you.
///
/// The troff language supports "macros", a way to define new commands
/// based on built-in commands. There are a number of popular macro
/// packages for various purposes. One of the most popular ones for
/// manual pages is called "man", and this module generates manual
/// pages for that package. It's supported by the "man" command on all
/// Unix systems.
///
/// Note that this module doesn't aim to be a generic manual page
/// generator. The scope is specifically the Sequoia sq command.

use roff::{bold, italic, roman, Inline, Roff};
use std::path::{Path, PathBuf};

/// The "manual" the manual page is meant for. The full Unix
/// documentation is (or was) divided into separate manuals, some of
/// which don't consist of manual pages.
const MANUAL: &str = "User Commands";

/// The "source" of the manual: who produced the manual.
const SOURCE: &str = "Sequoia-PGP";

/// Text to add to the end of the "SEE ALSO" section of sq manual page.
const SEE_ALSO: &str = "For the full documentation see <https://docs.sequoia-pgp.org/sq/>.";

/// Emits a warning.
macro_rules! warn {
    {$($exp: expr),*} => {
        println!("cargo:warning={}",
                 format_args!($($exp),*));
    };
}

/// Emits a warning and exits with an error.
macro_rules! fail {
    {$($exp: expr),*} => {
        warn!($($exp),*);
        std::process::exit(1);
    };
}

/// Generate manual page.
///
/// `cmd` is a `clap::Command` that has been built to represent the sq
/// command line interface. The manual pages are generated
/// automatically from that information.
///
/// This will produce a manual page for the whole sq, and one per
/// subcommand. Each manual page knows what its filename should be.
pub fn manpages(cmd: &clap::Command) -> Vec<ManualPage> {
    let mut builder = Builder::new(cmd, "1");
    builder.date(env!("CARGO_PKG_VERSION"));
    builder.source(SOURCE);
    builder.manual(MANUAL);
    builder.build()
}

/// Build a ManualPage or several.
//
/// The main command is sq itself. It can have multiple levels of
/// subcommands, and we treat the leaves of the subcommand tree
/// specially: every leaf gets a manual page, and every intermediate
/// node gets an overview page. For example, "sq encrypt" is a leaf,
/// as is "sq key generate", but "sq key" is not.
struct Builder {
    title: String,
    section: String,
    date: Option<String>,
    source: Option<String>,
    manual: Option<String>,
    version: Option<String>,
    maincmd: Command,
}

impl Builder {
    fn new(cmd: &clap::Command, section: &str) -> Self {
        Self {
            title: cmd.get_name().into(),
            section: section.into(),
            maincmd: Command::from_command(&[], cmd),
            date: None,
            source: None,
            manual: None,
            version: Some(format!(
                "{} (sequoia-openpgp {})",
                env!("CARGO_PKG_VERSION"),
                sequoia_openpgp::VERSION,
            )),
        }
    }

    /// Set the date for the manual page. This is typically typeset in
    /// the center of the footer of the page.
    fn date(&mut self, date: &str) {
        self.date = Some(date.into());
    }

    /// Set the source of the manual page. This is typically typeset on
    /// left of the footer of the page.
    fn source(&mut self, source: &str) {
        self.source = Some(source.into());
    }

    /// Set the manual this page belongs to. This is typically typeset
    /// on the center of the header of the page.
    fn manual(&mut self, manual: &str) {
        self.manual = Some(manual.into());
    }

    /// Return a one-line summary of the command. This goes in the NAME
    /// section of the manual page.
    fn summary(about: &str) -> String {
        let line = if let Some(line) = about.lines().next() {
            line
        } else {
            ""
        };
        line.to_string()
    }

    /// Build all manual pages for sq and one for each leaf subcommand.
    fn build(&self) -> Vec<ManualPage> {
        let mut pages = vec![];
        self.maincmd.build(self, &mut pages);
        pages
    }

    /// Set the title of the page.
    fn th(&self, man: &mut ManualPage) {
        let empty = String::new();
        man.th(
            &self.title.to_uppercase(),
            &self.section.to_uppercase(),
            self.date.as_ref().unwrap_or(&empty),
            self.source.as_ref().unwrap_or(&empty),
            self.manual.as_ref().unwrap_or(&empty),
        )
    }
}

/// The command for which we generate a manual page.
//
/// We collect all the information about a command here so that it's
/// handy when we generate various parts of a manual page that includes
/// this command.
#[derive(Debug, PartialEq, Eq)]
struct Command {
    command_words: Vec<String>,
    before_help: Option<String>,
    after_help: Option<String>,
    about: Option<String>,
    long_about: Option<String>,
    options: Vec<CommandOption>,
    args: Vec<String>,
    examples: Vec<String>,
    exit_status: Vec<String>,
    subcommands: Vec<Command>,
    leaf: bool,
}

impl Command {
    /// Create a new `Command`. The command words are the part of
    /// the command line that invokes this command. For sq itself,
    /// they're `["sq"]`, but for a subcommand they might be `["sq",
    /// "key", "generate"]` for example.
    fn new(command_words: Vec<String>) -> Self {
        Self {
            command_words,
            before_help: None,
            after_help: None,
            about: None,
            long_about: None,
            options: vec![],
            args: vec![],
            examples: vec![],
            exit_status: vec![],
            subcommands: vec![],
            leaf: false,
        }
    }

    /// Return the name of the command, with command words separated by
    /// spaces. This is suitable for, say, the NAME section.
    fn name(&self) -> String {
        self.command_words.join(" ")
    }

    /// Return name of the subcommand, without the main command name.
    fn subcommand_name(&self) -> String {
        let mut words = self.command_words.clone();
        words.remove(0);
        words.join(" ")
    }

    /// Return the name of the manual page for this command. This is
    /// the command words separated by dashes. Thus "sq key generate"
    /// would return "sq-key-generate". Manual page names mustn't
    /// contain spaces, thus the dash.
    fn manpage_name(&self) -> String {
        self.command_words.join("-")
    }

    /// Return the description of the command. This is collected from
    /// the various about and help texts given to `clap`.
    fn description(&self) -> String {
        let mut desc = String::new();
        if let Some(text) = &self.before_help {
            desc.push_str(text);
            desc.push('\n');
        }

        if let Some(text) = &self.long_about {
            desc.push_str(text);
            desc.push('\n');
        } else if let Some(text) = &self.about {
            desc.push_str(text);
            desc.push('\n');
        }

        if let Some(text) = &self.after_help {
            desc.push_str(text);
            desc.push('\n');
        }
        desc
    }

    /// Add the `before_help` help text for this command.
    fn before_help(&mut self, help: &str) {
        self.before_help = Some(self.extract_all(help));
    }

    /// Add the `after_help` help text for this command.
    fn after_help(&mut self, help: &str) {
        self.after_help = Some(self.extract_all(help));
    }

    /// Add the `about` help text for this command.
    fn about(&mut self, help: &str) {
        self.about = Some(self.extract_all(help));
    }

    /// Add the `long_about` help text for this command.
    fn long_about(&mut self, help: &str) {
        self.long_about = Some(self.extract_all(help));
    }

    /// Add an option to this command.
    fn option(&mut self, opt: CommandOption) {
        self.options.push(opt);
    }

    /// Add a positional argument to this command.
    fn arg(&mut self, arg: &str) {
        self.args.push(arg.into());
    }

    /// Extracts all additional sections.
    fn extract_all(&mut self, text: &str) -> String {
        let text = self.extract_example(text);
        let text = self.extract_exit_status(&text);
        text
    }

    /// Extract examples from help text: anything that follows a line
    /// consisting of "EXAMPLES:". This is a convention specific to sq,
    /// not something that comes from `clap`.
    fn extract_example(&mut self, text: &str) -> String {
        Self::extract("EXAMPLES:\n", &mut self.examples, text)
    }

    /// Extract examples from help text: anything that follows a line
    /// consisting of "EXAMPLES:". This is a convention specific to sq,
    /// not something that comes from `clap`.
    fn extract_exit_status(&mut self, text: &str) -> String {
        Self::extract("EXIT STATUS:\n", &mut self.exit_status, text)
    }

    /// Extracts sections, like examples, putting them into `into`.
    fn extract(marker: &str, into: &mut Vec<String>, text: &str) -> String {
        if let Some(pos) = text.find(marker) {
            let (text, ex) = text.split_at(pos);
            if let Some(ex) = ex.strip_prefix(marker) {
                into.push(ex.into());
            } else {
                into.push(ex.into());
            }
            text.into()
        } else {
            text.into()
        }
    }

    /// Does this command have any options?
    fn has_options(&self) -> bool {
        !self.options.is_empty()
    }

    /// Get the list of options for this command.
    fn get_options(&self) -> Vec<CommandOption> {
        let mut opts = self.options.clone();
        opts.sort_by_cached_key(|opt| opt.sort_key());
        opts
    }

    /// Does this command have examples?
    fn has_examples(&self) -> bool {
        !self.examples.is_empty()
    }

    /// Create a new `Command` from a `clap::Command` structure.
    fn from_command(parent: &[String], cmd: &clap::Command) -> Self {
        let mut words: Vec<String> = parent.into();
        words.push(cmd.get_name().to_string());
        let mut new = Self::new(words);
        if let Some(text) = cmd.get_before_help() {
            new.before_help(&text.to_string());
        }
        if let Some(text) = cmd.get_after_help() {
            new.after_help(&text.to_string());
        }
        if let Some(text) = cmd.get_about() {
            new.about(&text.to_string());
        }
        if let Some(text) = cmd.get_long_about() {
            new.long_about(&text.to_string());
        }
        for arg in cmd.get_arguments() {
            new.option(CommandOption::from_arg(arg));
        }
        for arg in cmd.get_positionals() {
            if let Some(names) = arg.get_value_names() {
                for name in names {
                    new.arg(name);
                }
            }
        }
        let mut parent = parent.to_vec();
        parent.push(cmd.get_name().into());
        new.subcommands = cmd.get_subcommands()
            .filter(|cmd| cmd.get_name() != "help")
            .map(|cmd| Command::from_command(&parent, cmd))
            .collect();
        new.leaf = cmd.get_subcommands().count() == 0;
        new
    }

    /// Builds manpages recursively.
    fn build(&self, builder: &Builder, acc: &mut Vec<ManualPage>) {
        if self.leaf {
            acc.push(self.build_leaf_command(builder));
        } else {
            acc.push(self.build_overview_command(builder));
            for cmd in &self.subcommands {
                cmd.build(builder, acc);
            }
        }
    }

    /// Build a manual page for an intermediate (i.e. non-leaf) command.
    fn build_overview_command(&self, builder: &Builder) -> ManualPage {
        assert!(! self.leaf);
        let filename = format!("{}.{}", self.manpage_name(), builder.section);
        let mut man = ManualPage::new(PathBuf::from(filename));
        builder.th(&mut man);

        let about = &self.about.clone().unwrap();
        let summary = Builder::summary(about);
        man.name_section(&self.name(), &summary);

        man.section("SYNOPSIS");
        let bin_name = builder.maincmd.name();
        for sub in &self.subcommands {
            man.subcommand_synopsis(
                &bin_name,
                &sub.subcommand_name(),
                sub.has_options(),
                &sub.args,
                sub.leaf,
            );
        }

        man.section("DESCRIPTION");
        man.text_with_period(&self.description());

        let main_opts = builder.maincmd.has_options();
        let cmd_opts = self.has_options() && self != &builder.maincmd
            && self.get_options().iter()
            .filter(|o| ! builder.maincmd.get_options().contains(o))
            .next().is_some();

        if main_opts || cmd_opts {
            man.section("OPTIONS");
        }
        if cmd_opts {
            man.subsection("Subcommand options");
            for opt in self.get_options().iter()
                .filter(|o| ! builder.maincmd.get_options().contains(o))
            {
                man.option(opt);
            }
        }
        if main_opts {
            man.subsection("Global options");
            for opt in builder.maincmd.get_options().iter() {
                man.option(opt);
            }
        }

        if !self.subcommands.is_empty() {
            man.section("SUBCOMMANDS");

            for sub in &self.subcommands {
                let desc = sub.description();
                if !desc.is_empty() {
                    man.subsection(&sub.name());
                    man.text_with_period(&desc);
                }
            }
        }

        man.exit_status_section(self);
        man.examples_section(&self.subcommands.iter().collect::<Vec<_>>());

        man.section("SEE ALSO");
        let names: Vec<String> =
            (1..self.command_words.len())
            .map(|n| self.command_words[0..n].join("-"))
            .chain(self.subcommands.iter().map(|sub| sub.manpage_name()))
            .collect();
        man.man_page_refs(&names, &builder.section);
        man.paragraph();
        man.text(SEE_ALSO);

        man.version_section(&builder.version);

        man
    }

    /// Build a manual page for one leaf subcommand.
    fn build_leaf_command(&self, builder: &Builder) -> ManualPage {
        assert!(self.leaf);
        let filename = format!("{}.{}", self.manpage_name(), builder.section);
        let mut man = ManualPage::new(PathBuf::from(filename));
        builder.th(&mut man);

        let about = &self.about.clone().unwrap();
        let summary = Builder::summary(about);
        man.name_section(&self.name(), &summary);

        man.section("SYNOPSIS");
        let bin_name = builder.maincmd.name();
        man.subcommand_synopsis(
            &bin_name,
            &self.subcommand_name(),
            self.has_options(),
            &self.args,
            true,
        );

        man.section("DESCRIPTION");
        man.text_with_period(&self.description());

        let main_opts = builder.maincmd.has_options();
        let self_opts = self.has_options()
            && self.get_options().iter()
            .filter(|o| ! builder.maincmd.get_options().contains(o))
            .next().is_some();

        if main_opts || self_opts {
            man.section("OPTIONS");
        }
        if self_opts {
            man.subsection("Subcommand options");
            for opt in self.get_options().iter()
                .filter(|o| ! builder.maincmd.get_options().contains(o))
            {
                man.option(opt);
            }
        }
        if main_opts {
            man.subsection("Global options");
            for opt in builder.maincmd.get_options().iter() {
                man.option(opt);
            }
        }

        man.exit_status_section(self);
        man.examples_section(&[self]);

        man.section("SEE ALSO");
        let names: Vec<String> =
            (1..self.command_words.len())
            .map(|n| self.command_words[0..n].join("-"))
            .collect();
        man.man_page_refs(&names, &builder.section);
        man.paragraph();
        man.text(SEE_ALSO);

        man.version_section(&builder.version);

        man
    }
}

/// Represent a command line option for manual page generation.
//
/// This doesn't capture all the things that `clap` allows, but is
/// sufficient for what sq actually uses.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CommandOption {
    /// Index for positional arguments.
    index: Option<usize>,
    short: Option<String>,
    long: Option<String>,
    value_names: Option<Vec<String>>,
    help: Option<String>,
}

impl CommandOption {
    /// Return a key for sorting a list of options.
    ///
    /// Manual pages list options in various places, and it enables
    /// quicker lookup by readers if they lists are sorted
    /// alphabetically.  By convention, such lists are sorted by short
    /// option first, if one exists.  And, positional arguments are
    /// sorted to the bottom, and in the order they appear on the
    /// command line.
    fn sort_key(&self) -> (usize, String) {
        let mut key = String::new();
        if let Some(name) = &self.short {
            key.push_str(name.strip_prefix('-').unwrap());
            key.push(',');
        }
        if let Some(name) = &self.long {
            key.push_str(name.strip_prefix("--").unwrap());
        }
        (self.index.unwrap_or(0), key)
    }
}

impl CommandOption {
    /// Create a `CommandOption` from a `clap::Arg`.
    fn from_arg(arg: &clap::Arg) -> Self {
        let value_names = if arg.get_num_args()
            .map(|r| r == clap::builder::ValueRange::EMPTY)
            .unwrap_or(true)
        {
            None
        } else if let Some(names) = arg.get_value_names() {
            Some(names.iter().map(|name| name.to_string()).collect())
        } else {
            None
        };

        Self {
            index: arg.get_index(),
            short: arg.get_short().map(|o| format!("-{}", o)),
            long: arg.get_long().map(|o| format!("--{}", o)),
            value_names,
            help: arg.get_long_help().or(arg.get_help())
                .map(|s| s.to_string()),
        }
    }
}

/// Troff code for a manual page.
///
/// The code is in [`troff`](https://en.wikipedia.org/wiki/Troff)
/// format, as is usual for Unix manual page documentation. It's using
/// the `man` macro package for `troff`.
pub struct ManualPage {
    filename: PathBuf,
    roff: Roff,

    // Are we in code mode (emitted .nf)?
    in_code: bool,
}

impl ManualPage {
    fn new(filename: PathBuf) -> Self {
        Self {
            filename,
            roff: Roff::new(),
            in_code: false,
        }
    }

    /// Set the title of the manual page. The "TH" macro takes five
    /// arguments: name of the command; section of the manual; the date
    /// of latest update; the source of manual; and the name of the manual.
    fn th(&mut self, name: &str, section: &str, date: &str, source: &str, manual: &str) {
        self.roff
            .control("TH", [name, section, date, source, manual]);
    }

    /// Typeset the NAME section: the title, and a line with the name
    /// of the command, followed by a dash, and a one-line. The dash
    /// should be escaped with backslash, but the `roff` crate does
    /// that for us.
    fn name_section(&mut self, name: &str, summary: &str) {
        self.section("NAME");
        self.roff.text([roman(&format!("{} - {}", name, summary))]);
    }

    /// Typeset code blocks, joining adjacent blocks.
    fn code(&mut self, code: bool) {
        match (self.in_code, code) {
            (false, false) => (),
            (false, true) => {
                self.roff.control("nf", []);
                self.in_code = true;
            },
            (true, false) => {
                self.roff.control("fi", []);
                self.in_code = false;
            },
            (true, true) => (),
        }
    }

    /// Typeset the synopsis of a command. This is going to be part of
    /// the SYNOPSIS section. There are conventions for how it should
    /// be typeset. For sq, we simplify them by summarizing options
    /// into a placeholder, and only listing command words and
    /// positional arguments.
    fn subcommand_synopsis(
        &mut self,
        bin: &str,
        sub: &str,
        sub_options: bool,
        args: &[String],
        is_leaf: bool,
    ) {
        let mut line = vec![
            bold(format!("{} {}", bin, sub)),
            roman(" ["), italic("OPTIONS"), roman("] "),
        ];

        for (i, arg) in args.iter().enumerate() {
            if i > 0 || ! sub_options {
                line.push(roman(" "));
            }
            line.push(italic(arg));
        }

        if args.is_empty() {
            line.push(roman(" "));
        }

        if ! is_leaf {
            line.push(italic("SUBCOMMAND"));
        }

        self.roff.control("br", []);
        self.roff.text(line);
    }

    /// Typeset an option, for the OPTIONS section. This is typeset
    /// using "tagged paragraphs", where the first line lists the
    /// aliases of the option, and any values it may take, and the rest
    /// is indented paragraphs of text explaining what the option does.
    fn option(&mut self, opt: &CommandOption) {
        let mut line = vec![];

        if let Some(short) = &opt.short {
            line.push(bold(short));
        }
        if let Some(long) = &opt.long {
            if opt.short.is_some() {
                line.push(roman(", "));
            }
            line.push(bold(long));
        }

        if let Some(values) = &opt.value_names {
            if (opt.short.is_some() || opt.long.is_some())
                && values.len() == 1
            {
                line.push(roman("="));
                line.push(italic(&values[0]));
            } else {
                for value in values {
                    line.push(roman(" "));
                    line.push(italic(value));
                }
            }
        }

        self.tagged_paragraph(line, &opt.help);
    }

    /// Typeset an EXIT STATUS section, if available.
    fn exit_status_section(&mut self, c: &Command) {
        if c.exit_status.is_empty() {
            return;
        }

        self.section("EXIT STATUS");
        for chunk in &c.exit_status {
            self.text(&chunk);
        }
    }

    /// Typeset an EXAMPLES section, if a command has examples.
    fn examples_section(&mut self, subs: &[&Command]) {
        let leaves = subs.iter().filter(|s| s.leaf).collect::<Vec<_>>();
        if !leaves.iter().any(|leaf| leaf.has_examples()) {
            return;
        }

        self.section("EXAMPLES");
        let mut need_para = false;
        let need_subsections = leaves.len() > 1;
        for leaf in leaves.iter() {
            if need_para {
                self.paragraph();
                need_para = false;
            }

            if !leaf.examples.is_empty() {
                if need_subsections {
                    self.subsection(&leaf.name());
                    need_para = false;
                }

                for ex in leaf.examples.iter() {
                    // Was the last line a continuation?
                    let mut continuation = false;

                    // Was the last line part of the description?
                    let mut description = false;

                    for line in ex.lines() {
                        if ! continuation
                            && ! (description && line.starts_with("#"))
                        {
                            self.paragraph();
                        }

                        const TARGET_LINE_LENGTH: usize = 78;
                        const RS_INDENTATION: usize = 7;
                        const EXAMPLE_COMMAND_MAX_WIDTH: usize =
                            TARGET_LINE_LENGTH - 2 * RS_INDENTATION;
                        const EXAMPLE_CONTINUATION_MAX_WIDTH: usize =
                            TARGET_LINE_LENGTH - 3 * RS_INDENTATION;

                        if let Some(line) = line.strip_prefix("# ") {
                            self.code(false);
                            self.roff.text([roman(line)]);
                        } else if let Some(line) = line.strip_prefix("$ ") {
                            let line = line.trim();
                            if line.len() > EXAMPLE_COMMAND_MAX_WIDTH {
                                warn!("Command in example exceeds {} chars:",
                                      EXAMPLE_COMMAND_MAX_WIDTH);
                                fail!("{}", line);
                            }
                            self.code(true);
                            self.roff.control("RS", []);
                            self.roff.text([roman(line)]);
                            self.roff.control("RE", []);
                        } else if continuation {
                            let line = line.trim();
                            if line.len() > EXAMPLE_CONTINUATION_MAX_WIDTH {
                                warn!("Continuation in example exceeds {} chars:",
                                      EXAMPLE_CONTINUATION_MAX_WIDTH);
                                fail!("{}", line);
                            }
                            self.code(true);
                            self.roff.control("RS", []);
                            self.roff.control("RS", []);
                            self.roff.text([roman(line)]);
                            self.roff.control("RE", []);
                            self.roff.control("RE", []);
                        } else {
                            self.code(false);
                            self.roff.text([roman(line)]);
                        }

                        // Update continuation for the next loop iteration.
                        continuation = line.ends_with("\\");

                        // Update description for the next loop iteration.
                        description = line.starts_with("#");

                        // We emitted at least one example, make sure
                        // to add a new paragraph before going to the
                        // next command.
                        need_para = true;
                    }
                }

                self.code(false);
            }
        }
    }

    /// Typeset the VERSION section, if the main command has a version
    /// set.
    fn version_section(&mut self, version: &Option<String>) {
        if let Some(v) = version {
            self.section("VERSION");
            self.roff.text([roman(v)]);
        }
    }

    /// Start a new section with the SH troff command.
    fn section(&mut self, heading: &str) {
        self.roff.control("SH", [heading]);
    }

    /// Start a new subsection with the SS troff command.
    fn subsection(&mut self, heading: &str) {
        self.roff.control("SS", [heading]);
    }

    /// Start a new paragraph with the PP troff command.
    fn paragraph(&mut self) {
        self.roff.control("PP", []);
    }

    /// Start a tagged paragraph with th TP troff command.
    ///
    /// This command takes the line after the command and typesets it,
    /// and the line after that starts an indented paragraph.
    ///
    /// Additionally, if `text` is given, it is rendered after the
    /// `line`, indenting it.
    fn tagged_paragraph(&mut self, line: Vec<Inline>, text: &Option<String>) {
        self.roff.control("TP", []);
        self.roff.text(line);

        if let Some(text) = text {
            let mut paras = text.split("\n\n");
            if let Some(first) = paras.next() {
                self.roff.text([roman(first)]);
            }
            for para in paras {
                self.roff.control("IP", []);
                self.roff.text([roman(para)]);
            }
        }
    }

    /// Typeset a list of references to manual pages, suitable for the
    /// SEE ALSO section. Manual page references are, by convention,
    /// typeset with the name of manual page in bold, and the section
    /// of the page in normal ("roman") font, enclosed in parentheses.
    /// The references are separated by commas, in normal font.
    fn man_page_refs(&mut self, names: &[String], section: &str) {
        let mut line = vec![];
        for name in names.iter() {
            if !line.is_empty() {
                line.push(roman(", "));
            }
            line.push(bold(name));
            line.push(roman("("));
            line.push(roman(section));
            line.push(roman(")"));
        }
        line.push(roman("."));

        self.roff.control("nh", []);
        self.roff.text(line);
        self.roff.control("hy", []);
    }

    /// Typeset normal text consisting of paragraphs. Paragraphs are
    /// separated by an empty line. All but the first paragraph are
    /// preceded by the troff paragraph command. The first one is not,
    /// to avoid unwanted empty lines in the output.
    fn text(&mut self, text: &str) {
        let mut paras = text.split("\n\n");
        if let Some(first) = paras.next() {
            self.roff.text([roman(first)]);
        }
        for para in paras {
            self.paragraph();
            self.roff.text([roman(para)]);
        }
    }

    /// Like [`ManualPage::text`], but add a period, if missing, to the end of
    /// the first paragraph. In `clap` about texts, the first line
    /// conventionally doesn't end in a period, but in manual pages,
    /// when that text is used in a DESCRIPTION section, it should have
    /// a period.
    fn text_with_period(&mut self, text: &str) {
        let mut paras = text.split("\n\n");
        if let Some(first) = paras.next() {
            let first = if let Some(prefix) = first.strip_suffix(".\n") {
                format!("{}.", prefix)
            } else if let Some(prefix) = first.strip_suffix('\n') {
                format!("{}.", prefix)
            } else if first.ends_with('.') {
                first.to_string()
            } else {
                format!("{}.", first)
            };
            self.roff.text([roman(first)]);
        }
        for para in paras {
            self.paragraph();
            self.roff.text([roman(para)]);
        }
    }

    /// What should the filename be, on disk, for this manual page?
    pub fn filename(&self) -> &Path {
        &self.filename
    }

    /// Return the `troff` source code for the manual page.
    pub fn troff_source(&self) -> String {
        self.roff.render()
    }
}
