use std::sync::Arc;

use api::midware;
use axum:: ServiceExt;
use tower::Layer;





mod api;
#[derive(Debug)]
pub struct AppState {
    pub secret : Arc<String>
}


#[tokio::main(flavor = "multi_thread", worker_threads = 5)]
async fn main() {
    let app_state = Arc::new(AppState {
        secret : Arc::new(String::from("secret"))
    });

    let midware = axum::middleware::from_fn(midware);

    let app = api::create_router(&app_state);

    let app_with_layer = midware.layer(app);

    let addr = tokio::net::TcpListener::bind("127.0.0.1:9092").await.unwrap();
    axum::serve(addr, app_with_layer.into_make_service()).await.unwrap();
}
