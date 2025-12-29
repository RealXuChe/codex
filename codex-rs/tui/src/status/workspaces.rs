use super::rate_limits::RateLimitSnapshotDisplay;
use super::rate_limits::StatusRateLimitData;
use super::rate_limits::StatusRateLimitRow;
use super::rate_limits::StatusRateLimitValue;
use super::rate_limits::compose_rate_limit_data;
use super::rate_limits::format_status_limit_summary;
use super::rate_limits::render_status_limit_progress_bar;
use crate::history_cell::PlainHistoryCell;
use chrono::DateTime;
use chrono::Local;
use ratatui::style::Stylize;
use ratatui::text::Line;
use ratatui::text::Span;

#[derive(Debug, Clone)]
pub(crate) struct WorkspaceStatusEntry {
    pub id: u32,
    pub name: Option<String>,
    pub is_active: bool,
    pub rate_limits: Option<RateLimitSnapshotDisplay>,
    pub unusable_message: Option<String>,
    pub fetch_error: Option<String>,
}

pub(crate) fn new_multi_workspace_status_output(
    workspaces: Vec<WorkspaceStatusEntry>,
    now: DateTime<Local>,
) -> PlainHistoryCell {
    let mut lines: Vec<Line<'static>> = Vec::new();

    lines.push("Workspaces".bold().into());

    if workspaces.is_empty() {
        lines.push("  (no stored ChatGPT credentials)".dim().into());
        return PlainHistoryCell::new(lines);
    }

    for (idx, entry) in workspaces.into_iter().enumerate() {
        if idx > 0 {
            lines.push(Line::from(""));
        }

        let name = entry.name.unwrap_or_else(|| "<unnamed>".to_string());
        let active_marker = if entry.is_active {
            "★".cyan().bold()
        } else {
            " ".dim()
        };
        lines.push(Line::from(vec![
            "• ".dim(),
            active_marker,
            " ".into(),
            format!("#{id} ", id = entry.id).into(),
            name.into(),
        ]));

        if let Some(err) = entry.fetch_error {
            lines.push(vec!["  Limits: ".into(), err.dim()].into());
        } else {
            let data = compose_rate_limit_data(entry.rate_limits.as_ref(), now);
            push_rate_limit_lines(&mut lines, data);
        }

        if let Some(message) = entry.unusable_message {
            lines.push(vec![format!("■ {message}").red()].into());
        }
    }

    PlainHistoryCell::new(lines)
}

fn push_rate_limit_lines(lines: &mut Vec<Line<'static>>, data: StatusRateLimitData) {
    match data {
        StatusRateLimitData::Available(rows) => {
            if rows.is_empty() {
                lines.push(vec!["  Limits: ".into(), "data not available yet".dim()].into());
            } else {
                push_rate_limit_rows(lines, &rows);
            }
        }
        StatusRateLimitData::Stale(rows) => {
            if rows.is_empty() {
                lines.push(vec!["  Limits: ".into(), "data not available yet".dim()].into());
            } else {
                push_rate_limit_rows(lines, &rows);
                lines.push(
                    vec![
                        "  Warning: ".into(),
                        "limits may be stale - start new turn to refresh.".dim(),
                    ]
                    .into(),
                );
            }
        }
        StatusRateLimitData::Missing => {
            lines.push(vec!["  Limits: ".into(), "data not available yet".dim()].into());
        }
    }
}

fn push_rate_limit_rows(lines: &mut Vec<Line<'static>>, rows: &[StatusRateLimitRow]) {
    for row in rows {
        match &row.value {
            StatusRateLimitValue::Window {
                percent_used,
                resets_at,
            } => {
                let percent_remaining = (100.0 - percent_used).clamp(0.0, 100.0);
                let mut spans: Vec<Span<'static>> = Vec::new();
                spans.push(Span::from("  "));
                spans.push(Span::from(format!("{}: ", row.label)));
                spans.push(Span::from(render_status_limit_progress_bar(
                    percent_remaining,
                )));
                spans.push(Span::from(" "));
                spans.push(Span::from(format_status_limit_summary(percent_remaining)));
                if let Some(resets_at) = resets_at.as_ref() {
                    spans.push(Span::from(" ").dim());
                    spans.push(Span::from(format!("(resets {resets_at})")).dim());
                }
                lines.push(Line::from(spans));
            }
            StatusRateLimitValue::Text(text) => {
                lines.push(
                    vec![
                        "  ".into(),
                        format!("{}: ", row.label).into(),
                        text.clone().into(),
                    ]
                    .into(),
                );
            }
        }
    }
}
