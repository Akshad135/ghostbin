use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{
        State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use futures::{SinkExt, StreamExt};
use serde_json::json;

use super::util::{api_error, require_owner};
use crate::auth;
use crate::state::AppState;

fn same_origin(headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(header::ORIGIN).and_then(|value| value.to_str().ok()) else {
        return true;
    };
    let Some(host) = headers.get(header::HOST).and_then(|value| value.to_str().ok()) else {
        return false;
    };
    origin == format!("http://{host}") || origin == format!("https://{host}")
}

/// GET /api/events — notification-only WebSocket.
pub async fn handle_events(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if let Err(response) = require_owner(&state, &headers).await {
        return response;
    }
    if !same_origin(&headers) {
        return api_error(
            StatusCode::FORBIDDEN,
            "ORIGIN_REJECTED",
            "Cross-origin WebSocket rejected",
        );
    }

    let task_headers = headers.clone();
    ws.on_upgrade(move |socket| handle_socket(socket, state, task_headers))
        .into_response()
}

async fn handle_socket(socket: WebSocket, state: Arc<AppState>, headers: HeaderMap) {
    let mut events = state.ws_sender.subscribe();
    let (mut sender, mut receiver) = socket.split();
    let mut session_check = tokio::time::interval(Duration::from_secs(30));

    let connected = json!({ "type": "connected" }).to_string();
    if sender.send(Message::Text(connected.into())).await.is_err() {
        return;
    }

    loop {
        tokio::select! {
            event = events.recv() => {
                match event {
                    Ok(message) => {
                        if sender.send(Message::Text(message.into())).await.is_err() {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        let resync = json!({ "type": "resync" }).to_string();
                        if sender.send(Message::Text(resync.into())).await.is_err() {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
            message = receiver.next() => {
                match message {
                    Some(Ok(Message::Text(text))) if text.as_str() == "ping" => {
                        if sender.send(Message::Text("pong".into())).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(_)) => break,
                    _ => {}
                }
            }
            _ = session_check.tick() => {
                if !auth::is_authenticated(&state.db, &headers).await {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn websocket_origin_must_match_host() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "paste.example".parse().unwrap());
        headers.insert(header::ORIGIN, "https://paste.example".parse().unwrap());
        assert!(same_origin(&headers));
        headers.insert(header::ORIGIN, "https://evil.example".parse().unwrap());
        assert!(!same_origin(&headers));
        headers.remove(header::ORIGIN);
        assert!(same_origin(&headers));
    }
}
