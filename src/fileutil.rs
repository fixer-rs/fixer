use crate::session::session_id::SessionID;
use simple_error::SimpleResult;
use std::{io::ErrorKind, os::unix::prelude::PermissionsExt, sync::Arc};
use tokio::{
    fs::{metadata, remove_file as rm, File, OpenOptions},
    io::AsyncWriteExt,
};

pub fn session_id_filename_prefix(s: &Arc<SessionID>) -> String {
    let mut sender = vec![s.sender_comp_id.as_str()];
    if !s.sender_sub_id.is_empty() {
        sender.push(s.sender_sub_id.as_str());
    }
    if !s.sender_location_id.is_empty() {
        sender.push(s.sender_location_id.as_str());
    }

    let mut target = vec![s.target_comp_id.as_str()];
    if !s.target_sub_id.is_empty() {
        target.push(s.target_sub_id.as_str());
    }
    if !s.target_location_id.is_empty() {
        target.push(s.target_location_id.as_str());
    }

    let sender_str = &sender.join("_");
    let target_str = &target.join("_");

    let mut fname = vec![s.begin_string.as_str(), sender_str, target_str];

    if !s.qualifier.is_empty() {
        fname.push(s.qualifier.as_str());
    }

    fname.join("-")
}

// close_file behaves like Close, except that no error is returned if the file does not exist.
pub async fn close_file(file_option: Option<File>) -> SimpleResult<()> {
    if let Some(mut file) = file_option {
        if let Err(err) = file.flush().await {
            if err.kind() == ErrorKind::NotFound {
                return Ok(());
            }
            return Err(simple_error!("close {}", err));
        }
    }

    Ok(())
}

// remove_file behaves like os.Remove, except that no error is returned if the file does not exist.
pub async fn remove_file(fname: &str) -> SimpleResult<()> {
    if let Err(err) = rm(fname).await {
        if err.kind() == ErrorKind::NotFound {
            return Ok(());
        }
        return Err(simple_error!("remove {}", err));
    };
    Ok(())
}

// open_or_create_file opens a file for reading and writing, creating it if necessary.
pub async fn open_or_create_file(fname: &str, perm: u32) -> SimpleResult<File> {
    match OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(fname)
        .await
    {
        Ok(file) => {
            let md = metadata(fname).await.map_err(|err| {
                simple_error!(
                    "error opening or creating file: {}: {}",
                    fname,
                    err.to_string(),
                )
            })?;
            md.permissions().set_mode(perm);
            Ok(file)
        }
        Err(err) => Err(simple_error!(
            "error opening or creating file: {}: {}",
            fname,
            err.to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        fileutil::{open_or_create_file, session_id_filename_prefix},
        session::session_id::SessionID,
    };
    use std::env::temp_dir;
    use std::io::ErrorKind;
    use std::path::Path;
    use std::process::id;
    use std::sync::Arc;
    use tokio::fs::metadata;

    async fn require_not_file_exists(fname: &str) {
        let md_result = metadata(fname).await;
        assert!(md_result.is_err());
        if let Err(err) = md_result {
            assert_eq!(err.kind(), ErrorKind::NotFound)
        }
    }
    async fn require_file_exists(fname: &str) {
        let md_result = metadata(fname).await;
        assert!(md_result.is_ok());
    }

    #[test]
    fn test_session_id_filename_minimally_qualified_session_id() {
        // When the session ID is
        let session_id = Arc::new(SessionID {
            begin_string: "FIX.4.4".to_string(),
            sender_comp_id: "SENDER".to_string(),
            target_comp_id: "TARGET".to_string(),
            ..Default::default()
        });

        // Then the filename should be
        assert_eq!(
            "FIX.4.4-SENDER-TARGET",
            session_id_filename_prefix(&session_id)
        );
    }

    #[test]
    fn test_session_id_filename_fully_qualified_session_id() {
        // When the session ID is
        let session_id = Arc::new(SessionID {
            begin_string: "FIX.4.4".to_string(),
            sender_comp_id: "A".to_string(),
            sender_sub_id: "B".to_string(),
            sender_location_id: "C".to_string(),
            target_comp_id: "D".to_string(),
            target_sub_id: "E".to_string(),
            target_location_id: "F".to_string(),
            qualifier: "G".to_string(),
        });

        // Then the filename should be
        assert_eq!(
            "FIX.4.4-A_B_C-D_E_F-G",
            session_id_filename_prefix(&session_id)
        );
    }

    #[tokio::test]
    async fn test_open_or_create_file() {
        // When the file doesn't exist yet
        let fpath = Path::new(&temp_dir()).join(format!("TestOpenOrCreateFile-{}", id()));
        let fname = fpath.to_str().unwrap();
        require_not_file_exists(fname).await;

        // Then it should be created
        let f_result = open_or_create_file(fname, 0o664).await;
        assert!(f_result.is_ok());
        require_file_exists(fname).await;
        let f = f_result.unwrap();
        drop(f);

        // Then it should be opened
        let f_result = open_or_create_file(fname, 0o664).await;
        assert!(f_result.is_ok());
        let f = f_result.unwrap();
        drop(f);
    }
}
