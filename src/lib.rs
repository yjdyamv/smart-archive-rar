//! RAR5 archive creation for the Smart Archive VS Code extension.
//!
//! Wraps the pure-Rust `rar5` library (codeberg.org/yjdyamv/rar-rs fork) behind
//! a minimal napi-rs API: create a RAR5 archive from disk paths and/or byte
//! buffers, with optional AES-256 password encryption, multi-volume output,
//! progress reporting, and size-bomb guards.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use napi::bindgen_prelude::*;
use napi::threadsafe_function::{ThreadsafeFunction, ThreadsafeFunctionCallMode};
use napi_derive::napi;

/// Maximum per-file size read into memory by the rar5 library (4 GiB).
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// Maximum total input size across all entries (32 GiB).
const MAX_TOTAL_BYTES: u64 = 32 * 1024 * 1024 * 1024;

#[napi(object)]
pub struct EntryInput {
  /// "file" | "dir" | "bytes"
  pub kind: String,
  /// Filesystem path for "file" and "dir" entries.
  pub path: Option<String>,
  /// Archive entry name. For "file"/"dir" defaults to the basename, for
  /// "bytes" it is required.
  pub name: Option<String>,
  /// Byte payload for "bytes" entries.
  pub data: Option<Buffer>,
}

#[napi(object)]
pub struct CreateArchiveOptions {
  pub out_path: String,
  pub entries: Vec<EntryInput>,
  /// Compression level 0..=5 (default 3).
  pub level: Option<u32>,
  /// Optional AES-256 password (file-level encryption).
  pub password: Option<String>,
  /// Also encrypt the archive structure (file names) — RAR5 header
  /// encryption. Requires `password`; incompatible with multi-volume.
  pub encrypt_headers: Option<bool>,
  /// Add a WinRAR-compatible inline recovery record protecting this percent
  /// (0-100) of the archive. Incompatible with multi-volume.
  pub recovery_percent: Option<u8>,
  /// Volume size in bytes; when set, produces multi-volume archives
  /// (`name.part1.rar`, ...).
  pub volume_size: Option<i64>,
  /// Reject the operation when the summed input size exceeds this.
  pub max_total_bytes: Option<i64>,
}

#[napi(object)]
pub struct ProgressData {
  pub done: f64,
  pub total: f64,
}

#[napi(object)]
pub struct CreateResult {
  /// Paths of all files produced (single archive or volumes).
  pub files: Vec<String>,
}

struct PlannedEntry {
  kind: String,
  path: Option<PathBuf>,
  name: String,
  data: Option<Vec<u8>>,
}

pub struct CreateArchiveTask {
  opts: CreateArchiveOptions,
  progress: Option<ThreadsafeFunction<ProgressData, ()>>,
}

fn plan_entries(opts: &CreateArchiveOptions) -> Result<Vec<PlannedEntry>> {
  let mut planned = Vec::with_capacity(opts.entries.len());
  for e in &opts.entries {
    match e.kind.as_str() {
      "file" => {
        let path = e
          .path
          .as_ref()
          .ok_or_else(|| Error::new(Status::InvalidArg, "file entry missing `path`"))?;
        let path = PathBuf::from(path);
        let meta = fs::metadata(&path).map_err(|err| {
          Error::new(
            Status::InvalidArg,
            format!("cannot stat {}: {err}", path.display()),
          )
        })?;
        if !meta.is_file() {
          return Err(Error::new(
            Status::InvalidArg,
            format!("{} is not a file", path.display()),
          ));
        }
        if meta.len() > MAX_FILE_BYTES {
          return Err(Error::new(
            Status::InvalidArg,
            format!(
              "{} is {:.1} GiB, rar5 supports files up to 4 GiB",
              path.display(),
              meta.len() as f64 / (1 << 30) as f64
            ),
          ));
        }
        planned.push(PlannedEntry {
          kind: "file".into(),
          name: e.name.clone().unwrap_or_else(|| basename(&path)),
          path: Some(path),
          data: None,
        });
      }
      "dir" => {
        let path = e
          .path
          .as_ref()
          .ok_or_else(|| Error::new(Status::InvalidArg, "dir entry missing `path`"))?;
        let path = PathBuf::from(path);
        if !path.is_dir() {
          return Err(Error::new(
            Status::InvalidArg,
            format!("{} is not a directory", path.display()),
          ));
        }
        planned.push(PlannedEntry {
          kind: "dir".into(),
          name: e.name.clone().unwrap_or_else(|| basename(&path)),
          path: Some(path),
          data: None,
        });
      }
      "bytes" => {
        let data = e
          .data
          .as_ref()
          .ok_or_else(|| Error::new(Status::InvalidArg, "bytes entry missing `data`"))?
          .as_ref()
          .to_vec();
        if data.len() as u64 > MAX_FILE_BYTES {
          return Err(Error::new(Status::InvalidArg, "bytes entry exceeds 4 GiB"));
        }
        let name = e
          .name
          .clone()
          .ok_or_else(|| Error::new(Status::InvalidArg, "bytes entry missing `name`"))?;
        planned.push(PlannedEntry {
          kind: "bytes".into(),
          name,
          path: None,
          data: Some(data),
        });
      }
      other => {
        return Err(Error::new(
          Status::InvalidArg,
          format!("unknown entry kind: {other}"),
        ));
      }
    }
  }
  if planned.is_empty() {
    return Err(Error::new(Status::InvalidArg, "no entries to archive"));
  }
  Ok(planned)
}

fn entry_size(e: &PlannedEntry) -> Result<u64> {
  match e.kind.as_str() {
    "bytes" => Ok(e.data.as_ref().map(|d| d.len() as u64).unwrap_or(0)),
    "file" => {
      let meta = fs::metadata(e.path.as_ref().expect("file path")).map_err(|err| {
        Error::new(
          Status::GenericFailure,
          format!("stat {}: {err}", e.path.as_ref().unwrap().display()),
        )
      })?;
      Ok(meta.len())
    }
    "dir" => dir_size(e.path.as_ref().expect("dir path")),
    _ => Ok(0),
  }
}

fn dir_size(path: &Path) -> Result<u64> {
  let mut total = 0u64;
  let mut stack = vec![path.to_path_buf()];
  while let Some(dir) = stack.pop() {
    for entry in fs::read_dir(&dir).map_err(|err| {
      Error::new(
        Status::GenericFailure,
        format!("read_dir {}: {err}", dir.display()),
      )
    })? {
      let entry = entry.map_err(|err| {
        Error::new(
          Status::GenericFailure,
          format!("read_dir {}: {err}", dir.display()),
        )
      })?;
      let p = entry.path();
      if p.is_dir() {
        stack.push(p);
      } else if let Ok(meta) = p.metadata() {
        total += meta.len();
      }
    }
  }
  Ok(total)
}

fn basename(path: &Path) -> String {
  path
    .file_name()
    .map(|n| n.to_string_lossy().into_owned())
    .unwrap_or_default()
}

fn to_napi_error(err: rar5::RarError) -> Error {
  Error::new(Status::GenericFailure, format!("rar5: {err}"))
}

#[napi]
impl Task for CreateArchiveTask {
  type Output = CreateResult;
  type JsValue = CreateResult;

  fn compute(&mut self) -> Result<Self::Output> {
    let planned = plan_entries(&self.opts)?;
    let total_bytes: u64 = planned.iter().try_fold(0u64, |acc, e| {
      let s = entry_size(e)?;
      let next = acc.saturating_add(s);
      if next > MAX_TOTAL_BYTES {
        return Err(Error::new(
          Status::InvalidArg,
          "total input size exceeds 32 GiB limit",
        ));
      }
      Ok(next)
    })?;

    if let Some(limit) = self.opts.max_total_bytes {
      if total_bytes > limit as u64 {
        return Err(Error::new(
          Status::InvalidArg,
          format!(
            "total input size {:.1} MiB exceeds limit {:.1} MiB",
            total_bytes as f64 / 1048576.0,
            limit as f64 / 1048576.0
          ),
        ));
      }
    }

    let level = self.opts.level.unwrap_or(3).min(5) as u8;
    let out = Path::new(&self.opts.out_path);
    if let Some(parent) = out.parent() {
      fs::create_dir_all(parent)
        .map_err(|err| Error::new(Status::GenericFailure, format!("mkdir: {err}")))?;
    }

    let rec = self.opts.recovery_percent.unwrap_or(0).min(100);
    let rec = if rec == 0 { None } else { Some(rec) };
    let mut archive = if let Some(size) = self.opts.volume_size {
      rar5::RarArchive::create_multivolume(out, size as u64).map_err(to_napi_error)?
    } else if let Some(pw) = self.opts.password.as_deref() {
      match (self.opts.encrypt_headers.unwrap_or(false), rec) {
        (true, Some(pct)) => rar5::RarArchive::create_with_password_headers_recovery(out, pw, pct)
          .map_err(to_napi_error)?,
        (true, None) => {
          rar5::RarArchive::create_with_password_headers(out, pw).map_err(to_napi_error)?
        }
        (false, Some(pct)) => {
          rar5::RarArchive::create_with_password_recovery(out, pw, pct).map_err(to_napi_error)?
        }
        (false, None) => rar5::RarArchive::create_with_password(out, pw).map_err(to_napi_error)?,
      }
    } else if let Some(pct) = rec {
      rar5::RarArchive::create_with_recovery(out, pct).map_err(to_napi_error)?
    } else {
      rar5::RarArchive::create(out).map_err(to_napi_error)?
    };

    if let Some(tsfn) = self.progress.take() {
      let tsfn = Arc::new(tsfn);
      let cb_tsfn = tsfn.clone();
      let processed = Arc::new(AtomicU64::new(0));
      let emit = processed.clone();
      archive.set_progress_callback(Some(Box::new(move |done, _file_total| {
        let overall = emit.load(Ordering::Relaxed) + done;
        let _ = cb_tsfn.call(
          Ok(ProgressData {
            done: overall as f64,
            total: total_bytes as f64,
          }),
          ThreadsafeFunctionCallMode::NonBlocking,
        );
      })));
      for e in &planned {
        let size = entry_size(e)?;
        archive_add(&mut archive, e, level)?;
        processed.fetch_add(size, Ordering::Relaxed);
      }
      // Guarantee the terminal 100% event. Delivery is asynchronous, so the
      // JS side may still observe it a tick after the promise resolves.
      let _ = tsfn.call(
        Ok(ProgressData {
          done: total_bytes as f64,
          total: total_bytes as f64,
        }),
        ThreadsafeFunctionCallMode::Blocking,
      );
    } else {
      for e in &planned {
        archive_add(&mut archive, e, level)?;
      }
    }

    archive.close().map_err(to_napi_error)?;
    drop(archive);

    let mut files = rar5::discover_volumes(out)
      .into_iter()
      .map(|p| p.to_string_lossy().into_owned())
      .collect::<Vec<_>>();
    files.sort();
    files.dedup();

    Ok(CreateResult { files })
  }

  fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
    Ok(output)
  }
}

/// Repair a damaged RAR5 archive using its inline recovery record.
///
/// Reads `input_path`, rebuilds any damaged data shards from the `{RB}`
/// parity shards and writes the repaired archive to `output_path`.
#[napi]
pub fn repair_archive(input_path: String, output_path: String) -> Result<()> {
  let input = fs::read(&input_path).map_err(|err| {
    Error::new(
      Status::GenericFailure,
      format!("read {}: {err}", input_path),
    )
  })?;
  let repaired = rar5::recovery::rar5::repair_inline_recovery_archive(&input)
    .map_err(|err| Error::new(Status::GenericFailure, format!("repair failed: {err}")))?;
  fs::write(&output_path, &repaired).map_err(|err| {
    Error::new(
      Status::GenericFailure,
      format!("write {}: {err}", output_path),
    )
  })?;
  Ok(())
}

fn archive_add(archive: &mut rar5::RarArchive, e: &PlannedEntry, level: u8) -> Result<()> {
  match e.kind.as_str() {
    "file" => {
      let path = e.path.as_ref().expect("file path");
      if e.name.is_empty() {
        archive.add(path, level).map_err(to_napi_error)
      } else {
        archive.add_as(path, &e.name, level).map_err(to_napi_error)
      }
    }
    "dir" => {
      // Directory entry only — callers that apply exclusion filtering
      // enumerate children themselves and add them as "file" entries, so
      // recursion here would bypass their filters.
      let path = e.path.as_ref().expect("dir path");
      archive
        .add_directory_only(path, &e.name)
        .map_err(to_napi_error)
    }
    "bytes" => {
      let data = e.data.as_ref().expect("bytes data");
      archive
        .add_bytes(&e.name, data, level)
        .map_err(to_napi_error)
    }
    _ => Ok(()),
  }
}

/// Create a RAR5 archive from the given entries.
#[napi]
pub fn create_archive(
  opts: CreateArchiveOptions,
  on_progress: Option<ThreadsafeFunction<ProgressData, ()>>,
  signal: Option<AbortSignal>,
) -> AsyncTask<CreateArchiveTask> {
  AsyncTask::with_optional_signal(
    CreateArchiveTask {
      opts,
      progress: on_progress,
    },
    signal,
  )
}
