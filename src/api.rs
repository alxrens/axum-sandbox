use axum::{body::Body, extract::Request, http::StatusCode, middleware::Next, response::{IntoResponse, Response}, routing::{get, post}, Json, Router};
use bytes::Bytes;
use chrono::Local;
use axum::extract::Multipart;
use jsonwebtoken::{decode, DecodingKey, EncodingKey, TokenData, Validation};
use serde_json::json;
use tokio::{fs::File, io::AsyncWriteExt};
use crate::AppState;
use std::sync::Arc;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Clone)]
pub struct Claims {
    pub sub : String,
    pub exp : i64
}
impl Claims {
    pub fn new(sub : String, exp : i64) -> String {
        let claims = Claims { sub, exp };

        jsonwebtoken::encode(&jsonwebtoken::Header::default(), &claims, &EncodingKey::from_secret("secret".as_bytes())).unwrap()
    }
}

static TIME : i64 =60 * 60 * 24 * 360 * 7;

pub async fn midware( mut req : Request<Body>, next : Next) -> Response {
    let uri = req.uri();
    let whitelist = vec!["/login"];

    if whitelist.contains(&uri.path()) {
        return next.run(req).await
    }

    let auth_header = req.headers().get("Authorization").and_then(|h| h.to_str().ok());
    if let Some(auth_value) = auth_header {
        if let Some(token) = auth_value.strip_prefix("Bearer ") {
            let decoding_key = DecodingKey::from_secret("secret".as_bytes());
            let validation = Validation::default();
            match decode::<Claims>(token, &decoding_key, &validation) {
                Ok(TokenData { claims, ..}) => {
                    req.extensions_mut().insert(claims);
                    
                    //on the next handler use this one bellow
                    // let claims = req.extensions().get::<Claims>().unwrap();
                    
                    return next.run(req).await
                },
                Err(e) => {
                    println!("{:?}", e);
                    return (StatusCode::UNAUTHORIZED, Json(json!({ "message": "Invalid token" }))).into_response()
                }
            }
        } else {
            return (StatusCode::BAD_REQUEST, Json(json!({ "message": "Missing token" }))).into_response()
        }
    } else {
        return (StatusCode::BAD_REQUEST, Json(json!({ "message": "Missing header" }))).into_response()
    }
}


async fn protected_route() -> String {
    "you just accesed a protected route".to_string()
}


async fn login() -> Response {
    let exp = Local::now().timestamp() as i64 + TIME;
    let token = Claims::new(String::from("test"), exp).to_string();
    (StatusCode::OK, Json(json!({ "status" : StatusCode::OK.as_u16() ,"message": "Succesfully login", "token" : token}))).into_response()
}

async fn root() -> Response{
    (StatusCode::OK, Json(json!({ "status" : StatusCode::OK.as_u16() ,"message": "healthy"}))).into_response()
}

#[derive(Debug,Serialize, Deserialize)]
pub struct Payload {
    pub name : String,
    pub age : i32
}

async fn posttest(Json(payload): Json<Payload>) -> Response{
    (StatusCode::CREATED, Json(json!({ "status" : StatusCode::CREATED.as_u16() ,"message": "data received", "data" : payload}))).into_response()
}

async fn upload_file(mut multipart : Multipart) -> Response {
    while let Some(field) = multipart.next_field().await.unwrap() {
        let filename = field.file_name().unwrap_or("unknown").to_string();

        let data : Bytes = field.bytes().await.unwrap().clone();

        let mut file = File::create(format!("./file/{}", filename)).await.unwrap();

        file.write_all(&data).await.unwrap();
    }

    (StatusCode::CREATED, Json(json!({ "status" : StatusCode::CREATED.as_u16() ,"message": "data received"}))).into_response()
}


pub fn create_router(state : &Arc<AppState>) -> Router {
    Router::new()
        .route("/protected", get(protected_route))
        .route("/login", get(login))
        .route("/posttest", post(posttest))
        .route("/", get(root))
        .route("/upload", post(upload_file))
        .with_state(state.clone())
}