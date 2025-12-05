use actix_web::{
    Error,
    body::MessageBody,
    dev::{ServiceRequest, ServiceResponse},
    http,
    middleware::Next,
    mime,
};

use crate::error::Error as AuthError;

pub async fn requests_filters(
    req: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    // pre-processing
    let header = req
        .headers()
        .get("content-type")
        .or_else(|| req.headers().get("Content-Type"))
        .and_then(|v| v.to_str().ok());

    if let Some(content_type) = header {
        if req.path() == "/password/reset" && content_type != mime::TEXT_HTML_UTF_8 {
            return Err(AuthError::UnsupportedMediaType(
                "Only text/html supported for this endpoint".into(),
            )
            .into());
        }

        if req.method() == http::Method::POST && content_type != mime::APPLICATION_JSON {
            return Err(
                AuthError::UnsupportedMediaType("Only application/json supported".into()).into(),
            );
        }
    }

    next.call(req).await
    // post-processing
}
