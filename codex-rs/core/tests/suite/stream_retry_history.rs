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

/// When a stream disconnect triggers a retry, the failed attempt's output must not be committed
/// into history/rollout. This test verifies the next user turn does not include discarded output.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stream_retry_does_not_commit_failed_attempt_output() {
    let discarded = "discarded_attempt_output_text__do_not_commit";
    let committed = "committed_output_text__should_be_in_history";

    // Attempt #1: emits an assistant message, then the stream ends without a `response.completed`.
    let attempt1 = sse(vec![
        ev_response_created("resp-1"),
        ev_assistant_message("msg-1", discarded),
    ]);

    // Attempt #2: successful completion with a different assistant message.
    let attempt2 = sse(vec![
        ev_response_created("resp-2"),
        ev_assistant_message("msg-2", committed),
        ev_completed("resp-2"),
    ]);

    // Next user turn: any valid response is fine.
    let next_turn = sse(vec![ev_response_created("resp-3"), ev_completed("resp-3")]);

    let server = start_mock_server().await;
    let response_mock = mount_sse_sequence(&server, vec![attempt1, attempt2, next_turn]).await;

    let codex = test_codex()
        .with_model("gpt-5.1")
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
    wait_for_event(&codex, |ev| matches!(ev, EventMsg::TaskComplete(_))).await;

    codex
        .submit(Op::UserInput {
            items: vec![UserInput::Text {
                text: "next".into(),
            }],
        })
        .await
        .unwrap();
    wait_for_event(&codex, |ev| matches!(ev, EventMsg::TaskComplete(_))).await;

    let requests = response_mock.requests();
    assert_eq!(
        requests.len(),
        3,
        "expected 2 attempts + 1 follow-up turn request"
    );

    let third_request_body = requests[2].body_json().to_string();
    assert!(
        third_request_body.contains(committed),
        "expected committed output to be present in the next turn's request"
    );
    assert!(
        !third_request_body.contains(discarded),
        "expected discarded attempt output to be absent from the next turn's request"
    );
}
