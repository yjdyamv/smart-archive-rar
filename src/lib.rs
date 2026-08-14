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
  /// Create this many `.rev` recovery volumes (WinRAR `-rv`); auto-capped
  /// at the actual data volume count. Requires `volume_size`.
  pub recovery_volume_count: Option<u32>,
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

fn plan_entries(entries: &[EntryInput]) -> Result<Vec<PlannedEntry>> {
  let mut planned = Vec::with_capacity(entries.len());
  for e in entries {
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
    // Directory entries write only a header — their children arrive as
    // explicit file entries, so counting the tree again would double-count
    // the progress denominator (and the 32 GiB budget).
    "dir" => Ok(0),
    _ => Ok(0),
  }
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

fn build_batch(planned: &[PlannedEntry], level: u8) -> Vec<rar5::BatchEntry<'_>> {
  let mut batch: Vec<rar5::BatchEntry<'_>> = Vec::with_capacity(planned.len());
  for e in planned {
    match e.kind.as_str() {
      "file" => {
        let path = e.path.as_ref().expect("file path");
        batch.push(rar5::BatchEntry::File {
          path,
          name: if e.name.is_empty() {
            None
          } else {
            Some(&e.name)
          },
          level,
        });
      }
      "dir" => {
        let path = e.path.as_ref().expect("dir path");
        batch.push(rar5::BatchEntry::Directory {
          path,
          name: Some(&e.name),
        });
      }
      "bytes" => {
        let data = e.data.as_ref().expect("bytes data");
        batch.push(rar5::BatchEntry::Bytes {
          name: &e.name,
          data,
          level,
        });
      }
      _ => {}
    }
  }
  batch
}

fn write_batch(
  archive: &mut rar5::RarArchive,
  batch: &[rar5::BatchEntry<'_>],
  total_bytes: u64,
  progress: Option<ThreadsafeFunction<ProgressData, ()>>,
) -> Result<()> {
  let terminal = progress.map(Arc::new);
  if let Some(tsfn) = terminal.as_ref() {
    let cb_tsfn = tsfn.clone();
    let emitted = Arc::new(AtomicU64::new(0));
    let emit = emitted.clone();
    let last_done = Arc::new(AtomicU64::new(0));
    let last = last_done.clone();
    archive.set_progress_callback(Some(Box::new(move |done, _file_total| {
      if done == 0 {
        // rar-rs starts every member with a (0, file_total) event; reset
        // the per-file baseline so only the delta is accumulated.
        last.store(0, Ordering::Relaxed);
      }
      let prev = last.swap(done, Ordering::Relaxed);
      let delta = done.saturating_sub(prev);
      let overall = emit.fetch_add(delta, Ordering::Relaxed) + delta;
      let _ = cb_tsfn.call(
        Ok(ProgressData {
          done: overall.min(total_bytes) as f64,
          total: total_bytes as f64,
        }),
        ThreadsafeFunctionCallMode::NonBlocking,
      );
    })));
    archive.add_batch(batch).map_err(to_napi_error)?;
  } else {
    archive.add_batch(batch).map_err(to_napi_error)?;
  }

  archive.close().map_err(to_napi_error)?;

  if let Some(tsfn) = terminal {
    // Terminal 100% event after the archive is fully closed (including
    // recovery records and volume finalization). Delivery is asynchronous,
    // so the JS side may still observe it a tick after the promise
    // resolves.
    let _ = tsfn.call(
      Ok(ProgressData {
        done: total_bytes as f64,
        total: total_bytes as f64,
      }),
      ThreadsafeFunctionCallMode::Blocking,
    );
  }
  Ok(())
}

#[napi]
impl Task for CreateArchiveTask {
  type Output = CreateResult;
  type JsValue = CreateResult;

  fn compute(&mut self) -> Result<Self::Output> {
    let planned = plan_entries(&self.opts.entries)?;
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
    let batch = build_batch(&planned, level);
    let out = Path::new(&self.opts.out_path);
    if let Some(parent) = out.parent() {
      fs::create_dir_all(parent)
        .map_err(|err| Error::new(Status::GenericFailure, format!("mkdir: {err}")))?;
    }

    let rec = self.opts.recovery_percent.unwrap_or(0).min(100);
    let rec = if rec == 0 { None } else { Some(rec) };
    let rev_count = self.opts.recovery_volume_count.unwrap_or(0);
    let password = self.opts.password.as_deref().filter(|p| !p.is_empty());
    let mut archive = if let Some(size) = self.opts.volume_size {
      if rev_count > 0 {
        if let Some(pw) = password {
          rar5::RarArchive::create_multivolume_with_recovery_count_and_password(
            out,
            size as u64,
            rev_count,
            pw,
          )
          .map_err(to_napi_error)?
        } else {
          rar5::RarArchive::create_multivolume_with_recovery_count(out, size as u64, rev_count)
            .map_err(to_napi_error)?
        }
      } else if let Some(pw) = password {
        if self.opts.encrypt_headers.unwrap_or(false) {
          // Header encryption for volume sets: every volume carries the
          // plaintext encryption header and all blocks are encrypted
          // (WinRAR -hp equivalent).
          rar5::RarArchive::create_multivolume_with_password_headers(out, size as u64, pw)
            .map_err(to_napi_error)?
        } else {
          rar5::RarArchive::create_multivolume_with_password(out, size as u64, pw)
            .map_err(to_napi_error)?
        }
      } else {
        rar5::RarArchive::create_multivolume(out, size as u64).map_err(to_napi_error)?
      }
    } else if let Some(pw) = password {
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

    write_batch(&mut archive, &batch, total_bytes, self.progress.take())?;
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
  let repaired = rar5::repair_archive(&input)
    .map_err(|err| Error::new(Status::GenericFailure, format!("repair failed: {err}")))?;
  fs::write(&output_path, &repaired).map_err(|err| {
    Error::new(
      Status::GenericFailure,
      format!("write {}: {err}", output_path),
    )
  })?;
  Ok(())
}

/// Rebuild missing volumes of a multi-volume RAR5 set from its `.rev`
/// recovery volumes (like WinRAR `rc`).
///
/// `first_volume` is the path of `name.part1.rar`; every missing volume is
/// reconstructed from the `.rev` parity volumes into the same directory.
/// Returns the paths of all volumes produced.
#[napi]
pub fn rebuild_missing_volumes(first_volume: String) -> Result<Vec<String>> {
  let paths = rar5::rebuild_missing_volumes(Path::new(&first_volume))
    .map_err(|err| Error::new(Status::GenericFailure, format!("rebuild failed: {err}")))?;
  Ok(
    paths
      .into_iter()
      .map(|p| p.to_string_lossy().into_owned())
      .collect(),
  )
}

#[napi(object)]
pub struct AppendArchiveOptions {
  /// Existing RAR5 archive to append to (single-volume only).
  pub archive_path: String,
  pub entries: Vec<EntryInput>,
  /// Compression level 0..=5 (default 3).
  pub level: Option<u32>,
  /// Password of the existing archive (needed when its content is
  /// encrypted so the solid chain can be extended).
  pub password: Option<String>,
}

pub struct AppendArchiveTask {
  opts: AppendArchiveOptions,
  progress: Option<ThreadsafeFunction<ProgressData, ()>>,
}

#[napi]
impl Task for AppendArchiveTask {
  type Output = CreateResult;
  type JsValue = CreateResult;

  fn compute(&mut self) -> Result<Self::Output> {
    let planned = plan_entries(&self.opts.entries)?;
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

    let level = self.opts.level.unwrap_or(3).min(5) as u8;
    let batch = build_batch(&planned, level);
    let mut archive = match self.opts.password.as_deref() {
      Some(pw) if !pw.is_empty() => {
        rar5::RarArchive::open_append_with_password(&self.opts.archive_path, pw)
          .map_err(to_napi_error)?
      }
      _ => rar5::RarArchive::open_append(&self.opts.archive_path).map_err(to_napi_error)?,
    };

    write_batch(&mut archive, &batch, total_bytes, self.progress.take())?;
    drop(archive);

    let mut files = rar5::discover_volumes(Path::new(&self.opts.archive_path))
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

/// Append entries to an existing RAR5 archive without rebuilding it.
///
/// Existing members are preserved verbatim (never recompressed); only the
/// trailing quick-open/recovery/end blocks are truncated and rewritten.
/// Recovery records are regenerated over the whole archive. Multi-volume
/// archives are not supported (matching the official `rar` CLI).
#[napi]
pub fn append_entries(
  opts: AppendArchiveOptions,
  on_progress: Option<ThreadsafeFunction<ProgressData, ()>>,
  signal: Option<AbortSignal>,
) -> AsyncTask<AppendArchiveTask> {
  AsyncTask::with_optional_signal(
    AppendArchiveTask {
      opts,
      progress: on_progress,
    },
    signal,
  )
}

/// Delete members from a RAR5 archive without rebuilding it.
///
/// Non-solid archives are rewritten surgically: kept members are copied
/// verbatim, never recompressed (like the official `rar d`). Solid chains
/// that lose a member are recompressed from the chain start only. For
/// multi-volume archives, kept payloads are re-split at the volume size
/// limit and `.rev` recovery volumes are regenerated.
///
/// Fails when any requested name is not present, or when the archive is
/// locked. Returns the number of deleted members.
#[napi]
pub fn delete_entries(
  archive_path: String,
  names: Vec<String>,
  password: Option<String>,
) -> Result<u32> {
  let mut archive = match password.as_deref() {
    Some(pw) if !pw.is_empty() => {
      rar5::RarArchive::open_with_password(&archive_path, pw).map_err(to_napi_error)?
    }
    _ => rar5::RarArchive::open(&archive_path).map_err(to_napi_error)?,
  };
  let refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
  let count = archive.delete(&refs).map_err(to_napi_error)?;
  Ok(count as u32)
}

/// List the member names of a RAR5 archive.
#[napi]
pub fn list_entries(archive_path: String, password: Option<String>) -> Result<Vec<String>> {
  let archive = match password.as_deref() {
    Some(pw) if !pw.is_empty() => {
      rar5::RarArchive::open_with_password(&archive_path, pw).map_err(to_napi_error)?
    }
    _ => rar5::RarArchive::open(&archive_path).map_err(to_napi_error)?,
  };
  Ok(
    archive
      .namelist()
      .into_iter()
      .map(|name| name.to_string())
      .collect(),
  )
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
