use super::audit::Undo;
use crate::{App, Result, locale::AdminAudit};
use serde_json::Value;
use sqlx::PgConnection;
use std::collections::HashMap;
use uuid::Uuid;
pub fn label<'a>(labels: &'a HashMap<String, String>, key: &str, fallback: &'a str) -> &'a str {
    labels.get(key).map(String::as_str).unwrap_or(fallback)
}
pub fn action_label<'a>(t: &'a AdminAudit, action: &str) -> &'a str {
    label(&t.actions, action, &t.unknown)
}
fn line(lines: &mut Vec<String>, name: &str, value: impl std::fmt::Display) {
    lines.push(format!("{name}: {value}"));
}
fn short_text(value: &str) -> String {
    let safe = value
        .chars()
        .filter(|c| !matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'))
        .collect::<String>();
    let single_line = safe.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut chars = single_line.chars();
    let mut result: String = chars.by_ref().take(72).collect();
    if chars.next().is_some() {
        result.push('…');
    }
    result
}
pub fn limit_message(message: &str) -> String {
    if message.encode_utf16().count() <= 4096 {
        return message.to_owned();
    }
    let mut remaining: usize = 4095;
    let mut result: String = message
        .chars()
        .take_while(|c| match remaining.checked_sub(c.len_utf16()) {
            Some(left) => {
                remaining = left;
                true
            }
            None => false,
        })
        .collect();
    result.push('…');
    result
}
fn value(t: &AdminAudit, field: &str, entry: &Value) -> String {
    match entry {
        Value::Bool(enabled) => {
            let key = if *enabled { "enabled" } else { "disabled" };
            label(&t.values, key, key).into()
        }
        Value::String(text) if !text.trim().is_empty() => match field {
            "username" => format!("@{}", short_text(text)),
            "display_name" | "bio" => format!("«{}»", short_text(text)),
            _ => label(&t.values, text, text).into(),
        },
        _ => label(&t.values, "empty", "—").into(),
    }
}
fn permissions(t: &AdminAudit, list: &Value, other: &Value) -> String {
    list.as_array()
        .into_iter()
        .flatten()
        .filter(|permission| {
            !other
                .as_array()
                .is_some_and(|items| items.contains(permission))
        })
        .filter_map(Value::as_str)
        .map(|permission| label(&t.permissions, permission, permission))
        .collect::<Vec<_>>()
        .join(", ")
}
fn differences(
    t: &AdminAudit,
    lines: &mut Vec<String>,
    action: &str,
    undo: Option<&Undo>,
    reversed: bool,
) {
    let Some(Undo::Changes(changes)) = undo else {
        return;
    };
    for change in changes {
        let (before, after) = if reversed {
            (&change.after, &change.before)
        } else {
            (&change.before, &change.after)
        };
        match action {
            "profile" => {
                for field in [
                    "display_name",
                    "username",
                    "bio",
                    "theme",
                    "wall_access",
                    "like_access",
                    "message_access",
                    "show_online",
                ] {
                    if before[field] != after[field] {
                        line(
                            lines,
                            label(&t.fields, field, field),
                            format_args!(
                                "{} → {}",
                                value(t, field, &before[field]),
                                value(t, field, &after[field])
                            ),
                        );
                    }
                }
                for key in [
                    "all", "sound", "messages", "follow", "wall", "like", "reply", "mention",
                ] {
                    let previous = before["notice_preferences"][key]
                        .as_bool()
                        .unwrap_or(key != "sound");
                    let current = after["notice_preferences"][key]
                        .as_bool()
                        .unwrap_or(key != "sound");
                    if previous != current {
                        let field = format!("notice_{key}");
                        line(
                            lines,
                            label(&t.fields, &field, key),
                            value(t, &field, &Value::Bool(current)),
                        );
                    }
                }
            }
            "roles" => {
                let previous = &before["permissions"];
                let current = &after["permissions"];
                for (key, list, other) in [
                    ("granted", current, previous),
                    ("revoked", previous, current),
                ] {
                    let names = permissions(t, list, other);
                    if !names.is_empty() {
                        line(lines, label(&t.messages, key, key), names);
                    }
                }
            }
            "badge" => outcome(
                t,
                lines,
                if after["verified"] == true {
                    "badge_granted"
                } else {
                    "badge_revoked"
                },
            ),
            "avatar" | "banner" => {
                let key = match action {
                    "avatar" if after["avatar_hidden"] == true => "avatar_hidden",
                    "avatar" if after["avatar_object_id"] != before["avatar_object_id"] => {
                        if reversed && after["avatar_object_id"].is_null() {
                            "avatar_removed"
                        } else if reversed {
                            "avatar_restored"
                        } else if before["avatar_object_id"].is_null() {
                            "avatar_uploaded"
                        } else {
                            "avatar_replaced"
                        }
                    }
                    "avatar" => "avatar_visible",
                    _ if after["banner_hidden"] == true => "banner_hidden",
                    _ => "banner_visible",
                };
                outcome(t, lines, key);
            }
            _ => {}
        }
    }
}
fn outcome(t: &AdminAudit, lines: &mut Vec<String>, key: &str) {
    if let Some(message) = t.messages.get(key) {
        lines.push(message.to_owned());
    }
}
pub async fn describe(
    db: &mut PgConnection,
    app: &App,
    action: &str,
    target: Option<Uuid>,
    details: &Value,
    undo: Option<&Undo>,
    reversed: bool,
) -> Result<String> {
    let t = &app.0.translations.admin_bot().audit;
    let mut lines = Vec::new();
    if reversed {
        line(
            &mut lines,
            label(&t.messages, "original_action", &t.action),
            action_label(t, action),
        );
    }
    let mut kind = details["kind"].as_str().unwrap_or("account");
    let mut object_id = target;
    let mut part = details["part"].as_i64();
    let mut reason = None;
    let report: Option<(String, Uuid, i16, String)>;
    if let Some(report_id) = target.filter(|_| action == "report_review") {
        line(&mut lines, label(&t.fields, "report", &t.target), report_id);
        report =
            sqlx::query_as("SELECT target_kind,target_id,part,reason FROM reports WHERE id=$1")
                .bind(report_id)
                .fetch_optional(&mut *db)
                .await?;
        if let Some((target_kind, id, index, why)) = &report {
            kind = target_kind;
            object_id = Some(*id);
            part = Some(i64::from(*index));
            reason = Some(why.as_str());
        } else {
            object_id = None;
        }
    }
    if let Some(id) = object_id {
        match action {
            "restart" | "env" => line(&mut lines, label(&t.fields, "job", &t.target), id),
            "undo" => line(
                &mut lines,
                label(&t.fields, "original_event", &t.target),
                id,
            ),
            _ => {
                let is_post = matches!(kind, "post" | "comment" | "attachment" | "poll");
                let query = if is_post {
                    "SELECT a.username,p.reply_to FROM posts p JOIN accounts a ON a.id=p.author_id WHERE p.id=$1"
                } else {
                    "SELECT username,NULL::uuid FROM accounts WHERE id=$1"
                };
                let subject: Option<(Option<String>, Option<Uuid>)> = sqlx::query_as(query)
                    .bind(id)
                    .fetch_optional(&mut *db)
                    .await?;
                let kind_label = label(&t.values, kind, kind);
                let detail = subject
                    .as_ref()
                    .and_then(|(name, _)| name.as_ref())
                    .map_or_else(
                        || format!("{kind_label} · {id}"),
                        |name| format!("{kind_label} · @{} · {id}", short_text(name)),
                    );
                line(&mut lines, &t.target, detail);
                if let Some(parent) = subject.and_then(|(_, parent)| parent) {
                    line(
                        &mut lines,
                        label(&t.fields, "parent_post", &t.target),
                        parent,
                    );
                }
            }
        }
    }
    if let Some(part) = part.filter(|&part| (0..4).contains(&part)) {
        line(&mut lines, label(&t.details, "part", "part"), part + 1);
    }
    if let Some(reason) = reason {
        line(
            &mut lines,
            label(&t.fields, "reason", "reason"),
            label(&t.values, reason, reason),
        );
    }
    differences(t, &mut lines, action, undo, reversed);
    if let Some(Undo::Alias(change)) = undo {
        let (before, after) = if reversed { (&change.after, &change.before) } else { (&change.before, &change.after) };
        for (field, alias) in [("previous_username", before), ("new_username", after)] {
            if let Some(alias) = alias {
                line(&mut lines, label(&t.fields, field, &t.target), format_args!("@{}", short_text(&alias.username)));
            }
        }
    }
    match action {
        "remove" => outcome(
            t,
            &mut lines,
            match (kind, reversed) {
                ("avatar", false) => "avatar_hidden",
                ("avatar", true) => "avatar_visible",
                ("banner", false) => "banner_hidden",
                ("banner", true) => "banner_visible",
                (_, true) => "restored",
                _ => "removed",
            },
        ),
        "report_review" => {
            let decision = if reversed {
                "pending"
            } else {
                details["state"].as_str().unwrap_or_default()
            };
            line(
                &mut lines,
                label(&t.details, "state", "state"),
                label(&t.values, decision, decision),
            );
            if details["remove"] == true {
                outcome(t, &mut lines, if reversed { "restored" } else { "removed" });
            } else if !reversed {
                outcome(t, &mut lines, "kept");
            }
        }
        "restart" => {
            if let Some(service) = details["service"].as_str() {
                line(
                    &mut lines,
                    label(&t.details, "service", "service"),
                    label(&t.values, service, service),
                );
            }
            outcome(t, &mut lines, "restart_queued");
        }
        "env" => {
            if let Some(key) = details["key"].as_str() {
                line(&mut lines, label(&t.details, "key", "key"), short_text(key));
            }
            outcome(
                t,
                &mut lines,
                if reversed {
                    "env_restore_queued"
                } else if details["cleared"] == true {
                    "env_clear_queued"
                } else {
                    "env_queued"
                },
            );
        }
        "sessions" => {
            outcome(
                t,
                &mut lines,
                if details["session"].is_string() {
                    "one_session"
                } else {
                    "all_sessions"
                },
            );
            if let Some(id) = details["session"].as_str() {
                line(
                    &mut lines,
                    label(&t.fields, "session", "session"),
                    short_text(id),
                );
            }
        }
        "email" | "phone" | "telegram" | "password" => {
            let state = if details["same_value"] == true {
                "unchanged"
            } else if reversed {
                "restored"
            } else {
                "updated"
            };
            let key = format!("{action}_{state}");
            outcome(t, &mut lines, &key);
        }
        "totp" => {
            outcome(
                t,
                &mut lines,
                if details["same_value"] == true {
                    "totp_already_disabled"
                } else {
                    "totp_disabled"
                },
            );
            if let Some(count) = details["recovery_count"].as_u64() {
                line(
                    &mut lines,
                    label(&t.fields, "recovery_count", "recovery_count"),
                    count,
                );
            }
        }
        "roles" if undo.is_none() => {
            let names = permissions(t, &details["permissions"], &Value::Null);
            if !names.is_empty() {
                line(
                    &mut lines,
                    label(&t.details, "permissions", "permissions"),
                    names,
                );
            }
        }
        _ => {}
    }
    if !reversed && let Some(count) = details["count"].as_u64() {
        line(
            &mut lines,
            label(&t.fields, "session_count", "count"),
            count,
        );
    }
    Ok(lines.join("\n"))
}
