use codex_core::protocol::EventMsg;
use codex_core::protocol::Op;
use codex_protocol::user_input::UserInput;
use core_test_support::responses::ev_assistant_message;
use core_test_support::responses::ev_completed;
use core_test_support::responses::ev_response_created;
use core_test_support::responses::mount_sse_sequence;
use core_test_support::responses::sse;
use core_test_support::responses::start_mock_server;
use core_test_support::test_codex::test_codex;
use core_test_support::wait_for_event;
use pretty_assertions::assert_eq;
use serde_json::Value;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn continue_starts_new_turn_without_new_user_message() {
    let first_body = sse(vec![
        ev_response_created("resp-1"),
        ev_assistant_message("msg-1", "done"),
        ev_completed("resp-1"),
    ]);
    let second_body = sse(vec![
        ev_response_created("resp-2"),
        ev_assistant_message("msg-2", "continued"),
        ev_completed("resp-2"),
    ]);

    let server = start_mock_server().await;
    let response_mock = mount_sse_sequence(&server, vec![first_body, second_body]).await;

    let codex = test_codex()
        .with_model("gpt-5.1")
        .build(&server)
        .await
        .unwrap()
        .codex;

    codex
        .submit(Op::UserInput {
            items: vec![UserInput::Text { text: "hi".into() }],
        })
        .await
        .unwrap();

    wait_for_event(&codex, |ev| matches!(ev, EventMsg::TaskComplete(_))).await;

    codex.submit(Op::Continue).await.unwrap();

    wait_for_event(&codex, |ev| matches!(ev, EventMsg::TaskComplete(_))).await;

    let requests = response_mock.requests();
    assert!(
        requests.len() == 2,
        "expected two calls to the responses API, got {}",
        requests.len()
    );

    let first_user_messages = requests[0].message_input_texts("user");
    let second_user_messages = requests[1].message_input_texts("user");
    assert!(
        first_user_messages.iter().any(|text| text == "hi"),
        "expected first request to contain the user prompt"
    );
    assert_eq!(
        second_user_messages, first_user_messages,
        "expected Op::Continue to avoid appending a new user message"
    );

    let input = requests[1].input();
    let last = input
        .last()
        .expect("second request input must not be empty");
    assert_eq!(
        last.get("type").and_then(Value::as_str),
        Some("message"),
        "expected last input item to remain a message"
    );
    assert_eq!(
        last.get("role").and_then(Value::as_str),
        Some("assistant"),
        "expected Op::Continue not to append a user message"
    );
}
