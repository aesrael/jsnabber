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
    pub features: jsnabber_core::features::BehavioralFeatures,
}

const DIAGNOSTIC_UI: &str = include_str!("../../../public/index.html");

#[event(fetch)]
async fn main(req: Request, _env: Env, _ctx: Context) -> Result<Response> {
    let router = Router::new();

    router
        .get("/", |_, _| Response::from_html(DIAGNOSTIC_UI))
        .get_async("/api/fetch", |req, _| async move {
            let url = req.url()?;
            let target_url = url
                .query_pairs()
                .find(|(k, _)| k == "url")
                .map(|(_, v)| v.to_string())
                .ok_or_else(|| worker::Error::from("Missing 'url' query parameter"))?;

            let headers = Headers::new();
            headers.set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36").ok();

            let request = Request::new_with_init(
                &target_url,
                &RequestInit {
                    method: Method::Get,
                    headers,
                    ..Default::default()
                },
            )
            .map_err(|e| worker::Error::from(e.to_string()))?;

            match Fetch::Request(request).send().await {
                Ok(mut resp) => {
                    let text = resp.text().await?;
                    Response::ok(text)
                }
                Err(e) => Response::error(format!("Failed to fetch URL: {}", e), 502),
            }
        })
        .post_async("/api/analyze", |mut req, _| async move {
            let payload = match req.json::<AnalyzeRequest>().await {
                Ok(p) => p,
                Err(_) => return Response::error("Invalid JSON body", 400),
            };

            // Get code from payload (frontend handles fetching now, so we mostly expect code)
            let code = if let Some(c) = payload.code {
                c
            } else if let Some(u) = payload.url {
                // Keep this fallback just in case
                match Fetch::Url(u.parse().map_err(|_| worker::Error::from("Invalid URL"))?)
                    .send()
                    .await
                {
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
                        classification: features.classification.clone(),
                        message: message.to_string(),
                        instructions: result.instruction_count,
                        time_ms: result.execution_time_ms,
                        features,
                    })
                }
                Err(e) => Response::error(format!("Execution failed: {}", e), 500),
            }
        })
        .run(req, _env)
        .await
}
