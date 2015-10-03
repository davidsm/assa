extern crate sodiumoxide;
extern crate rustc_serialize;
extern crate clap;

mod crypto;
mod serialize;
mod password;


fn do_get(account: &str) {
    unimplemented!();
}

fn do_new(account: &str) {
    unimplemented!();
}

fn do_change(account: &str) {
    unimplemented!();
}

fn do_delete(account: &str) {
    unimplemented!();
}

fn main() {
    let cmd_get = clap::SubCommand::with_name("get")
        .about("Get the stored password for an account")
        .arg(clap::Arg::with_name("ACCOUNT")
             .help("Name of account entry to get password for")
             .required(true)
             .index(1));

    let cmd_new = clap::SubCommand::with_name("new")
        .about("Create a new account entry")
        .arg(clap::Arg::with_name("ACCOUNT")
             .help("Name of account entry to create")
             .required(true)
             .index(1));

    let cmd_change = clap::SubCommand::with_name("change")
        .about("Change stored password for an account")
        .arg(clap::Arg::with_name("ACCOUNT")
             .help("Name of account to change")
             .required(true)
             .index(1));

    let cmd_delete = clap::SubCommand::with_name("delete")
        .about("Delete an account and its associated password")
        .arg(clap::Arg::with_name("ACCOUNT")
             .help("Name of account to delete")
             .required(true)
             .index(1));

    let app_matches = clap::App::new("assa")
        .version("0.1.0")
        .about("Command-line password manager")
        .setting(clap::AppSettings::GlobalVersion)
        .setting(clap::AppSettings::SubcommandRequiredElseHelp)
        .subcommand(cmd_get)
        .subcommand(cmd_new)
        .subcommand(cmd_change)
        .subcommand(cmd_delete)
        .get_matches();

    match app_matches.subcommand() {
        ("get", Some(matches)) => do_get(matches.value_of("ACCOUNT").unwrap()),
        ("new", Some(matches)) => do_new(matches.value_of("ACCOUNT").unwrap()),
        ("change", Some(matches)) => do_change(matches.value_of("ACCOUNT").unwrap()),
        ("delete", Some(matches)) => do_delete(matches.value_of("ACCOUNT").unwrap()),
        (_, _) => unreachable!() // Subcommands are required by clap, so should not reach this point
    }

}
