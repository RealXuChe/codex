//! Verifies that stream retries drop the last provisional (lag-1) item.

use codex_core::protocol::EventMsg;
use codex_core::protocol::Op;
use codex_protocol::user_input::UserInput;
use core_test_support::responses::ev_assistant_message;
use core_test_support::responses::ev_completed;
use core_test_support::responses::ev_response_created;
use core_test_support::responses::ev_shell_command_call;
use core_test_support::responses::mount_sse_sequence;
use core_test_support::responses::sse;
use core_test_support::responses::start_mock_server;
use core_test_support::test_codex::test_codex;
use core_test_support::wait_for_event;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retry_drops_last_done_item_until_next_boundary() {
    let server = start_mock_server().await;
    let response_mock = mount_sse_sequence(
        &server,
        vec![
            sse(vec![
                ev_response_created("resp-1"),
                ev_assistant_message("msg-1", "one"),
                ev_assistant_message("msg-2", "two"),
            ]),
            sse(vec![ev_response_created("resp-2"), ev_completed("resp-2")]),
        ],
    )
    .await;

    let codex = test_codex()
        .with_config(|config| {
            config.model_provider.request_max_retries = Some(0);
            config.model_provider.stream_max_retries = Some(0);
        })
        .build(&server)
        .await
        .unwrap()
        .codex;

    codex
        .submit(Op::UserInput {
            items: vec![UserInput::Text {
                text: "hello".into(),
            }],
        })
        .await
        .unwrap();

    wait_for_event(&codex, |event| matches!(event, EventMsg::TaskComplete(_))).await;

    let requests = response_mock.requests();
    assert_eq!(
        requests.len(),
        2,
        "expected two calls to the responses API, got {}",
        requests.len()
    );

    let assistant_texts = requests[1].message_input_texts("assistant");
    assert!(
        assistant_texts.iter().any(|text| text.contains("one")),
        "expected committed item to appear in retry request; assistant texts: {assistant_texts:?}"
    );
    assert!(
        !assistant_texts.iter().any(|text| text.contains("two")),
        "expected tail item to be dropped on retry; assistant texts: {assistant_texts:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retry_drops_tail_tool_call() {
    let call_id = "call-tail";

    let server = start_mock_server().await;
    let response_mock = mount_sse_sequence(
        &server,
        vec![
            sse(vec![
                ev_response_created("resp-1"),
                ev_shell_command_call(call_id, "echo hi"),
            ]),
            sse(vec![ev_response_created("resp-2"), ev_completed("resp-2")]),
        ],
    )
    .await;

    let codex = test_codex()
        .with_config(|config| {
            config.model_provider.request_max_retries = Some(0);
            config.model_provider.stream_max_retries = Some(0);
        })
        .build(&server)
        .await
        .unwrap()
        .codex;

    codex
        .submit(Op::UserInput {
            items: vec![UserInput::Text {
                text: "hello".into(),
            }],
        })
        .await
        .unwrap();

    wait_for_event(&codex, |event| matches!(event, EventMsg::TaskComplete(_))).await;

    let requests = response_mock.requests();
    assert_eq!(
        requests.len(),
        2,
        "expected two calls to the responses API, got {}",
        requests.len()
    );

    assert!(
        !requests[1].has_function_call(call_id),
        "expected tail tool call to be dropped from retry request"
    );
    assert!(
        requests[1].function_call_output_text(call_id).is_none(),
        "expected tail tool call to not be executed on retry"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn continue_starts_new_turn_without_new_user_message() {
    let server = start_mock_server().await;
    let response_mock = mount_sse_sequence(
        &server,
        vec![
            sse(vec![
                ev_response_created("resp-1"),
                ev_assistant_message("msg-1", "done"),
                ev_completed("resp-1"),
            ]),
            sse(vec![ev_response_created("resp-2"), ev_completed("resp-2")]),
        ],
    )
    .await;

    let codex = test_codex().build(&server).await.unwrap().codex;

    codex
        .submit(Op::UserInput {
            items: vec![UserInput::Text {
                text: "hello".into(),
            }],
        })
        .await
        .unwrap();
    wait_for_event(&codex, |event| matches!(event, EventMsg::TaskComplete(_))).await;

    codex.submit(Op::Continue).await.unwrap();
    wait_for_event(&codex, |event| matches!(event, EventMsg::TaskComplete(_))).await;

    let requests = response_mock.requests();
    assert_eq!(
        requests.len(),
        2,
        "expected two calls to the responses API, got {}",
        requests.len()
    );

    let user_texts = requests[1].message_input_texts("user");
    let hello_count = user_texts.iter().filter(|text| *text == "hello").count();
    assert_eq!(
        hello_count, 1,
        "expected /continue to avoid adding a second user message; user texts: {user_texts:?}"
    );
}
