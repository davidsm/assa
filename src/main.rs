extern crate sodiumoxide;
extern crate rustc_serialize;
extern crate clap;
extern crate rpassword;

use std::env;
use std::process;
use std::path::PathBuf;
use std::io::{Read, Write};
use std::io;
use std::fs::File;

mod crypto;
mod serialize;
mod password;


fn do_get(account: &str, password_file_path: &PathBuf) {
    let account_map = handle_read_result(read_password_file(password_file_path));
    let password_data = match serialize::get_password_data_for(account, &account_map) {
        Ok(pwdata) => pwdata,
        Err(serialize::AccountError::AccountNotFound) => {
            println!("Account not found");
            process::exit(1);
        },
        Err(_) => {
            println!("Something went wrong. Beats me what");
            process::exit(1);
        }
    };
    let master_password = prompt_for_password();
    let decrypted_password = match crypto::get_decrypted_password(&master_password,
                                                                  password_data) {
        Ok(pw) => pw,
        Err(_) => {
            println!("Wrong master password");
            process::exit(1);
        }
    };
    println!("Password for {} is {}", account, decrypted_password);
}

fn do_new(account: &str, password_file_path: &PathBuf) {
    let account_map = handle_read_result(read_password_file(password_file_path));
    let master_password = prompt_for_password();
    let plaintext_password = password::generate_password();
    let password_data = match crypto::create_encrypted_password(&plaintext_password,
                                                                &master_password) {
        Ok(pwdata) => pwdata,
        Err(_) => {
            // When fixing error handling in crypto, update this
            println!("Something went wrong. Beats me what");
            process::exit(1);
        }
    };

    // TODO: Handle error
    let output = serialize::add_account(account, password_data, &account_map).unwrap();

    // TODO: Handle error
    write_password_file(password_file_path, &output);
    println!("Password {} saved for {}", plaintext_password, account);
}

fn do_change(account: &str, password_file_path: &PathBuf) {
    unimplemented!();
}

fn do_delete(account: &str, password_file_path: &PathBuf) {
    unimplemented!();
}

fn prompt_for_password() -> String {
    println!("Enter master password:");
    match rpassword::read_password() {
        Ok(password) => {
            if password.len() > 0 { return password }
            else {
                println!("No password entered");
                process::exit(1);
            }
        },
        Err(_) => {
            println!("Failed to read password");
            process::exit(1);
        }
    }
    println!("");
}

fn read_password_file(path: &PathBuf) -> io::Result<String> {
    let mut f = try!(File::open(path));
    let mut output = String::new();
    try!(f.read_to_string(&mut output));
    Ok(output)
}

// Convenience function for handling results from reading
// the password file. Exits program on unexpected errors
fn handle_read_result(res: io::Result<String>) -> String {
    match res {
        Ok(content) => content,
        Err(err) => {
            match err.kind() {
                io::ErrorKind::NotFound => {
                    println!("Password file doesn't exist. Creating a new file");
                    "{}".to_string()
                },
                _ => {
                    println!("Error reading from password file");
                    process::exit(1);
                }
            }
        }
    }
}

fn write_password_file(path: &PathBuf, content: &str) -> io::Result<()> {
    // TODO: Consider setting mode bits to some decent value
    let mut f = try!(File::create(path));
    try!(f.write_all(content.as_bytes()));
    Ok(())
}

fn default_password_file() -> Option<PathBuf> {
    let mut pwfile_path = match env::home_dir() {
        Some(path) => path,
        None => { return None; }
    };
    pwfile_path.push(".assa-passwords");
    Some(pwfile_path)
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
        .arg(clap::Arg::with_name("PASSWORDFILE")
             .short("p")
             .long("password-file")
             .help("File where passwords are/will be stored. Default is ~/.assa-passwords")
             .takes_value(true)
             .global(true))
        .subcommand(cmd_get)
        .subcommand(cmd_new)
        .subcommand(cmd_change)
        .subcommand(cmd_delete)
        .get_matches();

    let password_file_path = match app_matches.value_of("PASSWORDFILE")
        .map(|s| { PathBuf::from(s) })
        .or_else(default_password_file) {
            Some(p) => p,
            None => {
                println!("Password file not provided and could not determine home folder");
                process::exit(1);
            }
        };

    match app_matches.subcommand() {
        ("get", Some(matches)) => do_get(matches.value_of("ACCOUNT").unwrap(),
                                         &password_file_path),
        ("new", Some(matches)) => do_new(matches.value_of("ACCOUNT").unwrap(),
                                         &password_file_path),
        ("change", Some(matches)) => do_change(matches.value_of("ACCOUNT").unwrap(),
                                               &password_file_path),
        ("delete", Some(matches)) => do_delete(matches.value_of("ACCOUNT").unwrap(),
                                               &password_file_path),
        (_, _) => unreachable!() // Subcommands are required by clap, so should not reach this point
    }

}
