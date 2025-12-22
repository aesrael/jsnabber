//! Backend analysis server for deep JavaScript analysis

use axum::{
    extract::Json,
    http::StatusCode,
    routing::{get, post},
    Router,
};
use jsnabber_core::{ExecutionLimits, ExecutionResult, Sandbox};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct AnalyzeRequest {
    pub code: String,
    #[serde(default)]
    pub tier: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AnalyzeResponse {
    pub success: bool,
    pub result: ExecutionResult,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

async fn analyze_handler(
    Json(payload): Json<AnalyzeRequest>,
) -> Result<Json<AnalyzeResponse>, (StatusCode, String)> {
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

    match sandbox.execute(&payload.code) {
        Ok(result) => Ok(Json(AnalyzeResponse {
            success: true,
            result,
            error: None,
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Execution error: {}", e),
        )),
    }
}

async fn health_handler() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

async fn root_handler() -> &'static str {
    r#"JSNabber Analysis API
=====================

Available Endpoints:
- GET  /        : This help message
- GET  /health  : Server health and version
- POST /analyze : Analyze JavaScript code

Example Usage:
curl -X POST http://localhost:8080/analyze \
  -H "Content-Type: application/json" \
  -d '{"code": "2 + 2", "tier": "edge"}'"#
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let app = Router::new()
        .route("/", get(root_handler))
        .route("/health", get(health_handler))
        .route("/analyze", post(analyze_handler));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080")
        .await
        .expect("Failed to bind to port 8080");

    println!("🚀 JSNabber Server running on http://0.0.0.0:8080");
    println!("📝 Endpoints:");
    println!("   GET  /         - API information");
    println!("   GET  /health   - Health check");
    println!("   POST /analyze  - Analyze JavaScript code");

    axum::serve(listener, app)
        .await
        .expect("Server failed to start");
}
