//! Security headers applied to every response (plan §9).
//!
//! The CSP allows `wasm-unsafe-eval` because the Argon2id KDF (hash-wasm)
//! runs client-side, and `unsafe-inline` styles because syntax-highlight
//! tokens carry per-token inline colors. Fonts are self-hosted, so everything
//! else falls back to `default-src 'self'`.

use axum::extract::Request;
use axum::http::{HeaderName, HeaderValue, header};
use axum::middleware::Next;
use axum::response::Response;
use std::sync::Arc;

/// A security header name/value pair, built once at startup.
#[derive(Clone)]
pub struct SecurityHeaders {
    headers: Arc<Vec<(HeaderName, HeaderValue)>>,
}

/// Build the header set from configuration.
///
/// `hsts_enabled` adds `Strict-Transport-Security`; set `HSTS_ENABLED=1`
/// only when the app is served over TLS (directly or behind a proxy that
/// terminates TLS), otherwise browsers refuse plain-HTTP fallback.
pub fn build_security_headers(hsts_enabled: bool) -> SecurityHeaders {
    let csp = "default-src 'self'; \
               script-src 'self' 'wasm-unsafe-eval'; \
               style-src 'self' 'unsafe-inline'; \
               img-src 'self' blob: data:; \
               connect-src 'self'; \
               object-src 'none'; \
               base-uri 'none'; \
               frame-ancestors 'none'; \
               form-action 'self'";

    let mut headers: Vec<(HeaderName, HeaderValue)> = vec![
        (
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(csp),
        ),
        (header::REFERRER_POLICY, HeaderValue::from_static("no-referrer")),
        (
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ),
        (
            header::HeaderName::from_static("permissions-policy"),
            HeaderValue::from_static(
                "camera=(), microphone=(), geolocation=(), payment=(), usb=(), bluetooth=(), serial=()",
            ),
        ),
        (
            header::HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        ),
    ];

    if hsts_enabled {
        headers.push((
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        ));
    }

    SecurityHeaders {
        headers: Arc::new(headers),
    }
}

/// Middleware: set each security header unless the handler already set it
/// (e.g. route-specific `nosniff` on file downloads).
pub async fn apply_security_headers(
    security: SecurityHeaders,
    request: Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    for (name, value) in security.headers.iter() {
        if !response.headers().contains_key(name) {
            response.headers_mut().insert(name.clone(), value.clone());
        }
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::StatusCode;
    use axum::routing::get;
    use axum::Router;
    use tower::util::ServiceExt;

    async fn ok() -> StatusCode {
        StatusCode::OK
    }

    #[tokio::test]
    async fn sets_security_headers_on_responses() {
        let security = build_security_headers(false);
        let app = Router::new()
            .route("/", get(ok))
            .layer(axum::middleware::from_fn(move |req, next| {
                apply_security_headers(security.clone(), req, next)
            }));

        let response = app
            .oneshot(axum::http::Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers();
        assert!(headers.contains_key(header::CONTENT_SECURITY_POLICY));
        assert_eq!(
            headers.get(header::REFERRER_POLICY).unwrap(),
            "no-referrer"
        );
        assert_eq!(
            headers.get(header::X_CONTENT_TYPE_OPTIONS).unwrap(),
            "nosniff"
        );
        assert!(headers.contains_key("permissions-policy"));
        assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
        assert!(!headers.contains_key(header::STRICT_TRANSPORT_SECURITY));
        let csp = headers
            .get(header::CONTENT_SECURITY_POLICY)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(csp.contains("default-src 'self'"));
        assert!(csp.contains("wasm-unsafe-eval"));
        assert!(csp.contains("frame-ancestors 'none'"));
    }

    #[tokio::test]
    async fn hsts_only_when_enabled() {
        let security = build_security_headers(true);
        let app = Router::new()
            .route("/", get(ok))
            .layer(axum::middleware::from_fn(move |req, next| {
                apply_security_headers(security.clone(), req, next)
            }));

        let response = app
            .oneshot(axum::http::Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(
            response.headers().get(header::STRICT_TRANSPORT_SECURITY).unwrap(),
            "max-age=31536000; includeSubDomains"
        );
    }

    #[tokio::test]
    async fn does_not_override_handler_headers() {
        let security = build_security_headers(false);
        let app = Router::new()
            .route(
                "/",
                get(|| async {
                    let mut response = Response::new(Body::empty());
                    response.headers_mut().insert(
                        header::X_CONTENT_TYPE_OPTIONS,
                        HeaderValue::from_static("nosniff-handler"),
                    );
                    response
                }),
            )
            .layer(axum::middleware::from_fn(move |req, next| {
                apply_security_headers(security.clone(), req, next)
            }));

        let response = app
            .oneshot(axum::http::Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(
            response.headers().get(header::X_CONTENT_TYPE_OPTIONS).unwrap(),
            "nosniff-handler"
        );
    }
}
