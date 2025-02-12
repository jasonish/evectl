// SPDX-FileCopyrightText: (C) 2023 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use std::{
    io::{BufRead, BufReader, Read},
    process::Stdio,
    thread,
};

use clap::Parser;
use regex::Regex;

use crate::context::Context;

#[derive(Parser, Debug)]
pub(crate) struct LogArgs {
    #[arg(short, long, help = "Follow log output")]
    follow: bool,
}

pub(crate) fn logs(ctx: &Context, args: LogArgs) {
    let containers = [
        crate::suricata::container_name(ctx),
        crate::evebox::server::container_name(ctx),
        crate::evebox::agent::container_name(ctx),
        crate::elastic::container_name(ctx),
    ];
    let max_container_name_len = containers.iter().map(|s| s.len()).max().unwrap_or(0);
    let mut handles = vec![];

    for container in containers {
        let container = container.clone();
        let mut command = ctx.manager.command();
        command.arg("logs");
        command.arg("--timestamps");
        if args.follow {
            command.arg("--follow");
        }
        command.arg(container.clone());
        let handle = thread::spawn(move || {
            match command
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
            {
                Ok(mut output) => {
                    let mut handles = vec![];

                    let stdout = output.stdout.take().unwrap();

                    let label = container.clone();
                    let handle = thread::spawn(move || {
                        log_line_printer(
                            format!("{:width$} | stdout", &label, width = max_container_name_len),
                            stdout,
                        );
                    });
                    handles.push(handle);

                    let stderr = output.stderr.take().unwrap();
                    let label = container.clone();
                    let handle = thread::spawn(move || {
                        log_line_printer(
                            format!("{:width$} | stderr", label, width = max_container_name_len),
                            stderr,
                        );
                    });
                    handles.push(handle);

                    for handle in handles {
                        let _ = handle.join();
                    }
                }
                Err(err) => {
                    panic!("{}", err);
                }
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.join();
    }
}

fn log_line_printer<R: Read + Sync + Send + 'static>(prefix: String, output: R) {
    let evebox_ts_pattern = r".....\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}.....";
    let re = Regex::new(evebox_ts_pattern).unwrap();

    let reader = BufReader::new(output).lines();
    for line in reader {
        if let Ok(line) = line {
            let line = re.replace_all(&line, "");
            println!("{} | {}", prefix, line);
        } else {
            return;
        }
    }
}
