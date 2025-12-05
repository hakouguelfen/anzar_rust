use actix_web::{
    body::MessageBody,
    dev::{ServiceRequest, ServiceResponse},
};
use tracing::{Span, Subscriber, subscriber::set_global_default};
use tracing_actix_web::{DefaultRootSpanBuilder, RootSpanBuilder};
use tracing_bunyan_formatter::{BunyanFormattingLayer, JsonStorageLayer};
use tracing_log::LogTracer;
use tracing_subscriber::{EnvFilter, Registry, fmt::MakeWriter, layer::SubscriberExt};

pub fn get_subscriber<Sink>(
    name: &str,
    env_filter: String,
    sink: Sink,
) -> impl Subscriber + Send + Sync
where
    Sink: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(env_filter));
    let formatting_layer = BunyanFormattingLayer::new(name.into(), sink);
    Registry::default()
        .with(env_filter)
        .with(JsonStorageLayer)
        .with(formatting_layer)
}

pub fn init_subscriber(subscriber: impl Subscriber + Send + Sync) {
    LogTracer::init().expect("Failed to set logger");
    set_global_default(subscriber).expect("Failed to set subscriber");
}

pub struct CustomRootSpanBuilder;

impl RootSpanBuilder for CustomRootSpanBuilder {
    fn on_request_start(request: &ServiceRequest) -> Span {
        // We rely on the Default builder for the standard HTTP fields
        let root_span = DefaultRootSpanBuilder::on_request_start(request);

        // We ask tracing to add these fields to the span, but leave them Empty for now.
        // We will fill them inside our handlers.
        tracing::info_span!(parent: root_span, "request",
            user.id = tracing::field::Empty,
            user.email = tracing::field::Empty,
            login.attempted = tracing::field::Empty
        )
    }

    fn on_request_end<B>(span: Span, outcome: &Result<ServiceResponse<B>, actix_web::Error>)
    where
        B: MessageBody,
    {
        // Capture the standard HTTP status logic
        DefaultRootSpanBuilder::on_request_end(span, outcome);
    }
}
