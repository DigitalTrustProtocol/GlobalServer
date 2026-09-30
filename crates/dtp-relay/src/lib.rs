//! `dtp-relay`: a minimal Nostr client for the Sync Server (decision GS-D2:
//! own minimal client for now; `rust-nostr` can replace it).
//!
//! - [`backfill`]: `until`-paginated REQ that stops at a page shorter than
//!   the limit;
//! - [`live`]: a long-lived REQ that forwards every event;
//! - [`Pusher`]: connects to a resolver, answers the NIP-42 challenge with the
//!   writer key, and pushes `EVENT`s with a pending-`OK` window.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use anyhow::{Context, bail};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

use dtp_model::{Event, KIND_AUTH, Keys};

pub type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Held kinds and the NIP-09 deletions that target them.
pub fn held_filters(since: Option<u64>, until: Option<u64>, limit: Option<usize>) -> Vec<Value> {
    let mut stmt = json!({ "kinds": [32009, 32014, 10011] });
    let mut dels = json!({ "kinds": [5], "#k": ["32009", "32014", "10011"] });
    for f in [&mut stmt, &mut dels] {
        if let Some(s) = since {
            f["since"] = json!(s);
        }
        if let Some(u) = until {
            f["until"] = json!(u);
        }
        if let Some(l) = limit {
            f["limit"] = json!(l);
        }
    }
    vec![stmt, dels]
}

/// A server → client frame.
#[derive(Clone, Debug, PartialEq)]
pub enum RelayMsg {
    Event {
        sub: String,
        event: Box<Event>,
    },
    Eose(String),
    Closed(String, String),
    Notice(String),
    Ok {
        id: String,
        accepted: bool,
        message: String,
    },
    Auth(String),
    Other(Value),
}

pub fn parse_relay(text: &str) -> Option<RelayMsg> {
    let v: Value = serde_json::from_str(text).ok()?;
    let a = v.as_array()?;
    let s = |i: usize| a.get(i).and_then(Value::as_str).unwrap_or("").to_string();
    Some(match a.first()?.as_str()? {
        "EVENT" => RelayMsg::Event {
            sub: s(1),
            event: Box::new(Event::from_value(a.get(2)?).ok()?),
        },
        "EOSE" => RelayMsg::Eose(s(1)),
        "CLOSED" => RelayMsg::Closed(s(1), s(2)),
        "NOTICE" => RelayMsg::Notice(s(1)),
        "OK" => RelayMsg::Ok {
            id: s(1),
            accepted: a.get(2).and_then(Value::as_bool).unwrap_or(false),
            message: s(3),
        },
        "AUTH" => RelayMsg::Auth(s(1)),
        _ => RelayMsg::Other(v.clone()),
    })
}

pub async fn connect(url: &str) -> anyhow::Result<Socket> {
    let (ws, _) = tokio::time::timeout(
        Duration::from_secs(10),
        tokio_tungstenite::connect_async(url),
    )
    .await
    .context("connect timeout")?
    .with_context(|| format!("connect {url}"))?;
    Ok(ws)
}

async fn send(ws: &mut Socket, v: Value) -> anyhow::Result<()> {
    ws.send(Message::Text(v.to_string().into())).await?;
    Ok(())
}

async fn next_msg(ws: &mut Socket, timeout: Duration) -> anyhow::Result<Option<RelayMsg>> {
    loop {
        let Some(msg) = tokio::time::timeout(timeout, ws.next())
            .await
            .context("relay timeout")?
        else {
            return Ok(None);
        };
        match msg? {
            Message::Text(t) => {
                if let Some(m) = parse_relay(t.as_str()) {
                    return Ok(Some(m));
                }
            }
            Message::Ping(p) => ws.send(Message::Pong(p)).await?,
            Message::Close(_) => return Ok(None),
            _ => {}
        }
    }
}

/// One REQ until EOSE; returns the events.
pub async fn fetch(
    url: &str,
    filters: Vec<Value>,
    timeout: Duration,
) -> anyhow::Result<Vec<Event>> {
    let mut ws = connect(url).await?;
    let mut req = vec![json!("REQ"), json!("dtp-fetch")];
    req.extend(filters);
    send(&mut ws, Value::Array(req)).await?;
    let mut out = Vec::new();
    while let Some(msg) = next_msg(&mut ws, timeout).await? {
        match msg {
            RelayMsg::Event { event, .. } => out.push(*event),
            RelayMsg::Eose(_) => break,
            RelayMsg::Closed(_, m) => bail!("relay closed the request: {m}"),
            _ => {}
        }
    }
    let _ = send(&mut ws, json!(["CLOSE", "dtp-fetch"])).await;
    let _ = ws.close(None).await;
    Ok(out)
}

/// `until`-paginated backfill of the held kinds, newest first.
pub async fn backfill(
    url: &str,
    since: Option<u64>,
    page: usize,
    max_pages: usize,
    timeout: Duration,
) -> anyhow::Result<Vec<Event>> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    let mut until: Option<u64> = None;
    for _ in 0..max_pages {
        let batch = fetch(url, held_filters(since, until, Some(page)), timeout).await?;
        let full = batch.len() >= page;
        let mut oldest: Option<u64> = None;
        let mut fresh = 0;
        for e in batch {
            oldest = Some(oldest.map_or(e.created_at, |o| o.min(e.created_at)));
            if seen.insert(e.id.clone()) {
                fresh += 1;
                out.push(e);
            }
        }
        // `until` is inclusive, so the boundary second comes back on the next
        // page. A full page with nothing new steps past that second.
        let next = match (full, oldest) {
            (true, Some(o)) if fresh > 0 => o,
            (true, Some(o)) if o > 0 => o - 1,
            _ => break,
        };
        if since.is_some_and(|s| next < s) {
            break;
        }
        until = Some(next);
    }
    Ok(out)
}

/// Live subscription: forwards events until the socket closes.
pub async fn live(url: &str, since: u64, tx: mpsc::Sender<Event>) -> anyhow::Result<()> {
    let mut ws = connect(url).await?;
    let mut req = vec![json!("REQ"), json!("dtp-live")];
    req.extend(held_filters(Some(since), None, None));
    send(&mut ws, Value::Array(req)).await?;
    loop {
        match next_msg(&mut ws, Duration::from_secs(120)).await {
            Ok(Some(RelayMsg::Event { event, .. })) => {
                if tx.send(*event).await.is_err() {
                    return Ok(());
                }
            }
            Ok(Some(RelayMsg::Closed(_, m))) => bail!("relay closed the subscription: {m}"),
            Ok(Some(_)) => {}
            Ok(None) => return Ok(()),
            Err(e) if e.to_string().contains("timeout") => {
                // Keep idle subscriptions alive.
                ws.send(Message::Ping(Vec::new().into())).await?;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Pushes events into one resolver as an authenticated writer.
pub struct Pusher {
    ws: Socket,
    pub url: String,
    pub window: usize,
}

/// `OK` tallies.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PushStats {
    pub accepted: u64,
    pub duplicate: u64,
    pub rejected: HashMap<String, u64>,
}

impl PushStats {
    pub fn record(&mut self, accepted: bool, message: &str) {
        if accepted && message.starts_with("duplicate:") {
            self.duplicate += 1;
        } else if accepted {
            self.accepted += 1;
        } else {
            let prefix = message.split(':').next().unwrap_or("error").to_string();
            *self.rejected.entry(prefix).or_default() += 1;
        }
    }
}

impl Pusher {
    /// Connects and authenticates with NIP-42.
    pub async fn connect(url: &str, keys: &Keys) -> anyhow::Result<Pusher> {
        let mut ws = connect(url).await?;
        let challenge = match next_msg(&mut ws, Duration::from_secs(5)).await? {
            Some(RelayMsg::Auth(c)) => c,
            other => bail!("expected an AUTH challenge, got {other:?}"),
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let auth = keys.sign_event(
            now,
            KIND_AUTH,
            vec![
                vec!["relay".into(), url.into()],
                vec!["challenge".into(), challenge],
            ],
            "",
        );
        send(&mut ws, json!(["AUTH", auth])).await?;
        loop {
            match next_msg(&mut ws, Duration::from_secs(10)).await? {
                Some(RelayMsg::Ok {
                    id,
                    accepted,
                    message,
                }) if id == auth.id => {
                    if !accepted {
                        bail!("AUTH refused: {message}");
                    }
                    break;
                }
                Some(_) => {}
                None => bail!("closed during AUTH"),
            }
        }
        Ok(Pusher {
            ws,
            url: url.to_string(),
            window: 500,
        })
    }

    /// Pushes events with at most `window` pending `OK`s; returns the
    /// `(id, accepted, message)` answers.
    pub async fn push(&mut self, events: &[Event]) -> anyhow::Result<Vec<(String, bool, String)>> {
        let mut answers = Vec::with_capacity(events.len());
        let mut pending: HashSet<String> = HashSet::new();
        let mut iter = events.iter();
        loop {
            while pending.len() < self.window {
                let Some(e) = iter.next() else { break };
                pending.insert(e.id.clone());
                send(&mut self.ws, json!(["EVENT", e])).await?;
            }
            if pending.is_empty() {
                break;
            }
            match next_msg(&mut self.ws, Duration::from_secs(30)).await? {
                Some(RelayMsg::Ok {
                    id,
                    accepted,
                    message,
                }) if pending.remove(&id) => {
                    answers.push((id, accepted, message));
                }
                Some(_) => {}
                None => bail!("resolver closed the connection"),
            }
        }
        Ok(answers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_frames_and_filters() {
        assert_eq!(
            parse_relay(r#"["EOSE","s"]"#),
            Some(RelayMsg::Eose("s".into()))
        );
        assert!(matches!(
            parse_relay(r#"["OK","x",true,""]"#),
            Some(RelayMsg::Ok { accepted: true, .. })
        ));
        assert_eq!(
            parse_relay(r#"["AUTH","c"]"#),
            Some(RelayMsg::Auth("c".into()))
        );
        let f = held_filters(Some(10), Some(20), Some(5));
        assert_eq!(f[0]["kinds"], json!([32009, 32014, 10011]));
        assert_eq!(f[1]["#k"], json!(["32009", "32014", "10011"]));
        assert_eq!(f[1]["until"], 20);
        let mut s = PushStats::default();
        s.record(true, "");
        s.record(true, "duplicate: x");
        s.record(false, "blocked: kind");
        assert_eq!((s.accepted, s.duplicate, s.rejected["blocked"]), (1, 1, 1));
    }
}
