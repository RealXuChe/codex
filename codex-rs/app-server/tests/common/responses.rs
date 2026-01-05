use serde_json::json;
use std::path::Path;

fn sse(events: Vec<serde_json::Value>) -> anyhow::Result<String> {
    let mut out = String::new();
    for event in events {
        out.push_str(&format!("data: {}\n\n", serde_json::to_string(&event)?));
    }
    Ok(out)
}

pub fn create_shell_command_sse_response(
    command: Vec<String>,
    workdir: Option<&Path>,
    timeout_ms: Option<u64>,
    call_id: &str,
) -> anyhow::Result<String> {
    let command_str = shlex::try_join(command.iter().map(String::as_str))?;
    let tool_call_arguments = serde_json::to_string(&json!({
        "command": command_str,
        "workdir": workdir.map(|w| w.to_string_lossy()),
        "timeout_ms": timeout_ms
    }))?;

    sse(vec![
        json!({"type":"response.created","response":{}}),
        json!({
            "type":"response.output_item.done",
            "item": {
                "type":"function_call",
                "call_id": call_id,
                "name":"shell_command",
                "arguments": tool_call_arguments
            }
        }),
        json!({"type":"response.completed","response":{"id": format!("resp-{call_id}")}}),
    ])
}

pub fn create_final_assistant_message_sse_response(message: &str) -> anyhow::Result<String> {
    sse(vec![
        json!({"type":"response.created","response":{}}),
        json!({
            "type":"response.output_item.done",
            "item": {
                "type":"message",
                "role":"assistant",
                "content":[{"type":"output_text","text": message}]
            }
        }),
        json!({"type":"response.completed","response":{"id":"resp-final"}}),
    ])
}

pub fn create_apply_patch_sse_response(
    patch_content: &str,
    call_id: &str,
) -> anyhow::Result<String> {
    let command = format!("apply_patch <<'EOF'\n{patch_content}\nEOF");
    let tool_call_arguments = serde_json::to_string(&json!({
        "command": command
    }))?;
    sse(vec![
        json!({"type":"response.created","response":{}}),
        json!({
            "type":"response.output_item.done",
            "item": {
                "type":"function_call",
                "call_id": call_id,
                "name":"shell_command",
                "arguments": tool_call_arguments
            }
        }),
        json!({"type":"response.completed","response":{"id": format!("resp-{call_id}")}}),
    ])
}

pub fn create_exec_command_sse_response(call_id: &str) -> anyhow::Result<String> {
    let (cmd, args) = if cfg!(windows) {
        ("cmd.exe", vec!["/d", "/c", "echo hi"])
    } else {
        ("/bin/sh", vec!["-c", "echo hi"])
    };
    let command = std::iter::once(cmd.to_string())
        .chain(args.into_iter().map(str::to_string))
        .collect::<Vec<_>>();
    let tool_call_arguments = serde_json::to_string(&json!({
        "cmd": command.join(" "),
        "yield_time_ms": 500
    }))?;
    sse(vec![
        json!({"type":"response.created","response":{}}),
        json!({
            "type":"response.output_item.done",
            "item": {
                "type":"function_call",
                "call_id": call_id,
                "name":"exec_command",
                "arguments": tool_call_arguments
            }
        }),
        json!({"type":"response.completed","response":{"id": format!("resp-{call_id}")}}),
    ])
}
