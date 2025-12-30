//! Backend analysis server for deep JavaScript analysis

use axum::{
    extract::{Json, Query},
    http::StatusCode,
    routing::{get, post},
    Router,
};
use jsnabber_core::{ExecutionLimits, ExecutionResult, Sandbox};
use serde::{Deserialize, Serialize};
use tower_http::services::ServeDir;

#[derive(Debug, Deserialize)]
pub struct AnalyzeRequest {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub tier: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct FetchQuery {
    pub url: String,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

async fn analyze_handler(
    Json(payload): Json<AnalyzeRequest>,
) -> Result<Json<ExecutionResult>, (StatusCode, String)> {
    // Get code either directly or by fetching URL
    let code = if let Some(c) = payload.code {
        c
    } else if let Some(url) = payload.url {
        // Fetch the URL
        reqwest::get(&url)
            .await
            .map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("Failed to fetch URL: {}", e),
                )
            })?
            .text()
            .await
            .map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("Failed to read response: {}", e),
                )
            })?
    } else {
        return Err((
            StatusCode::BAD_REQUEST,
            "Either 'code' or 'url' must be provided".to_string(),
        ));
    };

    let limits = match payload.tier.as_deref() {
        Some("edge") => ExecutionLimits::edge(),
        Some("backend") => ExecutionLimits::backend(),
        _ => ExecutionLimits::backend(),
    };

    let sandbox = Sandbox::new(limits).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to create sandbox: {}", e),
        )
    })?;

    let result = sandbox.execute(&code).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Execution error: {}", e),
        )
    })?;

    Ok(Json(result))
}

async fn fetch_handler(Query(params): Query<FetchQuery>) -> Result<String, (StatusCode, String)> {
    // Fetch URL
    let response = reqwest::get(&params.url).await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Failed to fetch URL: {}", e),
        )
    })?;

    // Get text
    let text = response.text().await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Failed to read response: {}", e),
        )
    })?;

    Ok(text)
}

async fn health_handler() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/api/analyze", post(analyze_handler))
        .route("/api/fetch", get(fetch_handler))
        .fallback_service(ServeDir::new("../../public"));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("Failed to bind to port 3000");

    println!("🚀 JSNabber Server running at http://0.0.0.0:3000");
    println!("� Open http://127.0.0.1:3000 in your browser");
    println!("\n📝 API Endpoints:");
    println!("   GET  /health        - Health check");
    println!("   POST /api/analyze   - Analyze JavaScript code");
    println!("   GET  /api/fetch     - Fetch remote JavaScript");

    axum::serve(listener, app)
        .await
        .expect("Server failed to start");
}
