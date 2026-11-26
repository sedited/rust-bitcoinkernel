//! Conformance handler for the Rust Bitcoin Kernel bindings.
//!
//! Implements the JSON-over-stdio protocol of the
//! [kernel-bindings-spec](https://github.com/stringintech/kernel-bindings-spec)
//! conformance suite: one request per line on stdin, one response per line on stdout.

use std::io::{self, BufRead, Write};
use std::process::ExitCode;

use crate::{
    error::Error,
    execute::{execute, Output},
    registry::Registry,
    request::Request,
    response::Response,
};

mod chainstate;
mod error;
mod execute;
mod registry;
mod request;
mod response;

fn main() -> ExitCode {
    // Returning (rather than `process::exit`) drops the registry, which frees all
    // kernel objects and removes temporary directories, also on error.
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("{msg}");
            ExitCode::FAILURE
        }
    }
}

/// Handles requests until stdin is closed, or until a protocol error.
fn run() -> Result<(), String> {
    let mut registry = Registry::default();
    let mut stdout = io::stdout().lock();

    for line in io::stdin().lock().lines() {
        let line = line.map_err(|e| format!("error reading stdin: {e}"))?;
        let resp = handle(&mut registry, &line)?;
        send_response(&mut stdout, &resp).map_err(|e| format!("error writing response: {e}"))?;
    }
    Ok(())
}

/// Parses and executes one request line, storing any object it produces.
///
/// Returns the response for the runner, or a message for a protocol error.
fn handle(registry: &mut Registry, line: &str) -> Result<Response, String> {
    let req: Request = serde_json::from_str(line).map_err(|e| describe_parse_error(line, e))?;

    match execute(req.method, registry) {
        Ok(Output::Object(obj)) => {
            let ref_ = req
                .ref_
                .ok_or_else(|| format!("request {}: ref field is required", req.id))?;
            registry.store(ref_.clone(), obj);
            Ok(Response::with_ref(ref_))
        }
        Ok(Output::Value(value)) => Ok(Response::success(value)),
        Ok(Output::Unit) => Ok(Response::empty()),
        Err(Error::Kernel) => Ok(Response::empty_error()),
        Err(Error::Code(code_type, member)) => Ok(Response::error_code(code_type, member)),
        Err(Error::Protocol(msg)) => Err(format!("request {}: {msg}", req.id)),
    }
}

/// Builds an error message for a request that failed to parse, including its
/// `id` and `method` when the line is at least valid JSON.
fn describe_parse_error(line: &str, err: serde_json::Error) -> String {
    let value: serde_json::Value = serde_json::from_str(line).unwrap_or_default();
    let field = |name| value.get(name).and_then(|v| v.as_str()).unwrap_or("?");
    format!(
        "invalid request (id {}, method {}): {err}",
        field("id"),
        field("method")
    )
}

fn send_response(out: &mut impl Write, resp: &Response) -> io::Result<()> {
    serde_json::to_writer(&mut *out, resp)?;
    out.write_all(b"\n")?;
    out.flush()
}
