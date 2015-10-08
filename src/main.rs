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

enum Confirmation {
    Yes,
    No
}

fn do_get(account: &str, password_file_path: &PathBuf) -> Result<(), &'static str> {
    let account_map = try!(read_password_file(password_file_path));
    let hashed_account_name = crypto::hash_account_name(account);
    let password_data = match serialize::get_password_data_for(&hashed_account_name,
                                                               &account_map) {
        Ok(pwdata) => pwdata,
        Err(serialize::AccountError::AccountNotFound) => {
            return Err("Account not found");
        },
        Err(_) => {
            return Err("Something went wrong. Beats me what");
        }
    };
    let master_password = try!(prompt_for_password(false));
    let decrypted_password = try!(crypto::get_decrypted_password(&master_password,
                                                                password_data)
                                  .or(Err("Wrong master password")));

    println!("Password for {} is {}", account, decrypted_password);
    Ok(())
}

fn do_new(account: &str, password_file_path: &PathBuf) -> Result<(), &'static str> {
    let account_map = try!(read_password_file(password_file_path));
    let master_password = try!(prompt_for_password(true));
    let plaintext_password = password::generate_password();
    let password_data = try!(crypto::create_encrypted_password(&plaintext_password,
                                                               &master_password)
                             .or(Err("Something went wrong. Beats me what")));

    let hashed_account_name = crypto::hash_account_name(account);

    let output = match serialize::add_account(&hashed_account_name, password_data,
                                              &account_map) {
        Ok(data) => data,
        Err(serialize::AccountError::AccountAlreadyExists) => {
            return Err("Account already exists");
        }
        Err(_) => {
            return Err("Something went wrong. Beats me what");
        }
    };

    try!(write_password_file(password_file_path, &output));
    println!("Password {} saved for {}", plaintext_password, account);
    Ok(())
}

fn do_change(account: &str, password_file_path: &PathBuf) -> Result<(), &'static str> {
    let account_map = try!(read_password_file(password_file_path));
    let master_password = try!(prompt_for_password(true));
    let plaintext_password = password::generate_password();
    let password_data = try!(crypto::create_encrypted_password(&plaintext_password,
                                                               &master_password)
                             .or(Err("Something went wrong. Beats me what")));

    let hashed_account_name = crypto::hash_account_name(account);

    let output = match serialize::change_account(&hashed_account_name, password_data,
                                                 &account_map) {
        Ok(data) => data,
        Err(serialize::AccountError::AccountNotFound) => {
            return Err("Account doesn't exist");
        }
        Err(_) => {
            return Err("Something went wrong. Beats me what");
        }
    };

    try!(write_password_file(password_file_path, &output));
    println!("Password changed to {} for {}", plaintext_password, account);
    Ok(())
}

fn do_delete(account: &str, password_file_path: &PathBuf) -> Result<(), &'static str> {
    let account_map = try!(read_password_file(password_file_path));
    let confirmation = try!(prompt_for_confirmation("Really delete account?"));

    let hashed_account_name = crypto::hash_account_name(account);

    match confirmation {
        Confirmation::Yes => {
            let output = match serialize::remove_account(&hashed_account_name,
                                                         &account_map) {
                Ok(data) => data,
                Err(serialize::AccountError::AccountNotFound) => {
                    return Err("Account doesn't exist");
                },
                Err(_) => {
                    return Err("Something went wrong. Beats me what");
                }
            };
            try!(write_password_file(password_file_path, &output));
            println!("Account deleted");
        }
        Confirmation::No => {}
    }
    Ok(())
}

fn prompt_for_password(repeat: bool) -> Result<String, &'static str> {
    println!("Enter master password:");
    let pw1 = try!(read_password());
    if repeat {
        println!("Repeat master password:");
        let pw2 = try!(read_password());
        if pw1 == pw2 {
            Ok(pw1)
        }
        else {
            Err("Passwords do not match")
        }
    }
    else {
        Ok(pw1)
    }
}

fn read_password() -> Result<String, &'static str> {
    match rpassword::read_password() {
        Ok(password) => {
            if password.len() > 0 { Ok(password) }
            else {
                Err("No password entered")
            }
        },
        Err(_) => {
            Err("Failed to read password")
        }
    }
}

fn prompt_for_confirmation(question: &str) -> Result<Confirmation, &'static str> {
    println!("{}", question);
    let mut confirmation = String::new();
    try!(io::stdin().read_line(&mut confirmation).or(Err("Failed to read from stdin")));
    match confirmation.to_lowercase().trim() {
        "yes" | "y" => Ok(Confirmation::Yes),
        "no" | "n" => Ok(Confirmation::No),
        _ => Err("Please answer yes or no")
    }

}

fn read_password_file(path: &PathBuf) -> Result<String, &'static str> {
    File::open(path).or(Err("Failed to open password file"))
        .and_then(|mut f| {
            let mut output = String::new();
            match f.read_to_string(&mut output) {
                Ok(_) => Ok(output),
                Err(err) => {
                    match err.kind() {
                        io::ErrorKind::NotFound => {
                            println!("Password file doesn't exist. Creating a new file");
                            Ok("{}".to_string())
                        },
                        _ => {
                            Err("Error reading from password file")
                        }
                    }
                }
            }
        })
}

fn write_password_file(path: &PathBuf, content: &str) -> Result<(), &'static str> {
    // TODO: Consider setting mode bits to some decent value
    File::create(path)
        .or(Err("Failed to open file for writing"))
        .and_then(|mut f| {
            f.write_all(content.as_bytes())
                .or(Err("Failed to write to file"))
                .and(Ok(()))
        })
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
        .version(env!("CARGO_PKG_VERSION"))
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

    let result = match app_matches.subcommand() {
        ("get", Some(matches)) => do_get(matches.value_of("ACCOUNT").unwrap(),
                                         &password_file_path),
        ("new", Some(matches)) => do_new(matches.value_of("ACCOUNT").unwrap(),
                                         &password_file_path),
        ("change", Some(matches)) => do_change(matches.value_of("ACCOUNT").unwrap(),
                                               &password_file_path),
        ("delete", Some(matches)) => do_delete(matches.value_of("ACCOUNT").unwrap(),
                                               &password_file_path),
        (_, _) => unreachable!() // Subcommands are required by clap, so should not reach this point
    };

    match result {
        Err(msg) => {
            println!("{}", msg);
            process::exit(1);
        },
        Ok(_) => {}
    }

}
