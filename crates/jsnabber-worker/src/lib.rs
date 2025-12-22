use jsnabber_core::{Classification, ExecutionLimits, Sandbox};
use serde::{Deserialize, Serialize};
use worker::*;

/// Request body for analyzing JavaScript code
#[derive(Debug, Deserialize)]
pub struct AnalyzeRequest {
    /// The JavaScript code to analyze (optional if url is provided)
    pub code: Option<String>,
    /// The URL to fetch code from (optional if code is provided)
    pub url: Option<String>,
}

/// Response body for worker results
#[derive(Debug, Serialize)]
pub struct WorkerResponse {
    pub success: bool,
    pub classification: Classification,
    pub message: String,
    pub instructions: u64,
    pub time_ms: u64,
}

#[event(fetch)]
async fn main(req: Request, _env: Env, _ctx: Context) -> Result<Response> {
    // Only allow POST
    if req.method() != Method::Post {
        return Response::error("Method Not Allowed", 405);
    }

    let mut req = req;
    let payload = match req.json::<AnalyzeRequest>().await {
        Ok(p) => p,
        Err(_) => return Response::error("Invalid JSON body", 400),
    };

    // Get code from payload or fetch from URL
    let code = if let Some(c) = payload.code {
        c
    } else if let Some(u) = payload.url {
        match Fetch::Url(u.parse()?).send().await {
            Ok(mut resp) => resp.text().await?,
            Err(_) => return Response::error("Failed to fetch script from URL", 502),
        }
    } else {
        return Response::error("Either 'code' or 'url' must be provided", 400);
    };

    // Initialize sandbox with edge limits
    let sandbox = match Sandbox::new(ExecutionLimits::edge()) {
        Ok(s) => s,
        Err(e) => return Response::error(format!("Sandbox init error: {}", e), 500),
    };

    // Execute
    match sandbox.execute(&code) {
        Ok(result) => {
            let features = result.features;
            let message = match features.classification {
                Classification::Malicious => "ALERT: Malicious script detected. Blocking.",
                Classification::Suspicious => {
                    "WARNING: Suspicious behavior detected. Flagging for deep analysis."
                }
                Classification::Benign => "INFO: No suspicious behavior detected.",
                Classification::Inconclusive => "INFO: Analysis inconclusive (limits hit).",
            };

            Response::from_json(&WorkerResponse {
                success: result.completed,
                classification: features.classification,
                message: message.to_string(),
                instructions: result.instruction_count,
                time_ms: result.execution_time_ms,
            })
        }
        Err(e) => Response::error(format!("Execution failed: {}", e), 500),
    }
}
