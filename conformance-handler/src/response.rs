//! Responses written to stdout.
//!
//! See <https://github.com/stringintech/kernel-bindings-spec/blob/main/docs/handler-spec.md>.

use serde::Serialize;
use serde_json::{json, Value};

/// A response written to stdout.
///
/// `result` is always serialized (as `null` when empty); `error` is omitted on success.
#[derive(Debug, Serialize)]
pub struct Response {
    result: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<Value>,
}

impl Response {
    pub fn success(result: Value) -> Response {
        Response {
            result,
            error: None,
        }
    }

    pub fn with_ref(ref_: String) -> Response {
        Response::success(json!({ "ref": ref_ }))
    }

    pub fn empty() -> Response {
        Response::success(Value::Null)
    }

    pub fn empty_error() -> Response {
        Response {
            result: Value::Null,
            error: Some(json!({})),
        }
    }

    pub fn error_code(code_type: &str, member: &str) -> Response {
        Response {
            result: Value::Null,
            error: Some(json!({ "code": { "type": code_type, "member":member } })),
        }
    }
}
