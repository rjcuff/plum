use anyhow::Result;
use flate2::read::GzDecoder;
use reqwest::Client;
use std::io::Read;
use tar::Archive;

pub struct JsFile {
    pub path: String,
    pub content: String,
}

pub async fn fetch_and_scan(client: &Client, tarball_url: &str) -> Result<Vec<JsFile>> {
    let bytes = client
        .get(tarball_url)
        .send()
        .await?
        .bytes()
        .await?;

    let cursor = std::io::Cursor::new(bytes);
    let gz = GzDecoder::new(cursor);
    let mut archive = Archive::new(gz);

    let mut js_files = Vec::new();

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_string_lossy().to_string();

        if !path.ends_with(".js") {
            continue;
        }

        let mut content = String::new();
        if entry.read_to_string(&mut content).is_ok() {
            js_files.push(JsFile { path, content });
        }
    }

    Ok(js_files)
}
