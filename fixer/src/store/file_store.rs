use crate::{
    config::{DYNAMIC_SESSIONS, FILE_STORE_PATH, FILE_STORE_SYNC},
    fileutil::{close_file, open_or_create_file, remove_file, session_id_filename_prefix},
    session::session_id::SessionID,
    session::settings::SessionSettings,
    settings::Settings,
    store::{
        MemoryStore, MessageStoreEnum, MessageStoreFactoryEnum, MessageStoreFactoryTrait,
        MessageStoreTrait,
    },
};
use jiff::{Timestamp, tz::TimeZone};
use simple_error::{SimpleError, SimpleResult};
use sscanf::sscanf;
use std::{io::SeekFrom, os::unix::prelude::PermissionsExt, path::Path, sync::Arc};
use tokio::{
    fs::{self, File},
    io::{AsyncBufReadExt, AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader},
    sync::Mutex,
};

const TIMESTAMP_FORMAT: &str = "%Y-%m-%dT%H:%M:%S%.f%:z";

struct IndividualFile {
    file_name: String,
    file: Option<File>,
}

impl IndividualFile {
    async fn set_seq_num(&mut self, seq_num: isize) -> SimpleResult<()> {
        let _ = self.file.as_mut().unwrap().rewind().await;

        // Right-align the number in a 19-byte buffer, padded with spaces.
        let mut buf = [b' '; 19];
        let mut tmp = Vec::new();
        let _ = itoap::write(&mut tmp, seq_num);
        buf[19 - tmp.len()..].copy_from_slice(&tmp);

        self.file
            .as_mut()
            .unwrap()
            .write(&buf)
            .await
            .map_err(|err| simple_error!("unable to write to file: {}: {}", self.file_name, err))?;

        self.file
            .as_mut()
            .unwrap()
            .flush()
            .await
            .map_err(|err| simple_error!("unable to flush file: {}: {}", self.file_name, err))
    }
}

pub struct FileStore {
    #[allow(dead_code)]
    // stored for parity; may be used by future extensions
    session_id: Arc<SessionID>,
    cache: MemoryStore,
    body_file: IndividualFile,
    header_file: IndividualFile,
    session_file: IndividualFile,
    sender_seq_nums_file: IndividualFile,
    target_seq_nums_file: IndividualFile,
    file_sync: bool,
}

impl MessageStoreTrait for FileStore {
    async fn next_sender_msg_seq_num(&mut self) -> isize {
        self.cache.next_sender_msg_seq_num().await
    }

    async fn next_target_msg_seq_num(&mut self) -> isize {
        self.cache.next_target_msg_seq_num().await
    }

    async fn set_next_sender_msg_seq_num(&mut self, next_seq_num: isize) -> SimpleResult<()> {
        map_err_with!(
            self.sender_seq_nums_file.set_seq_num(next_seq_num).await,
            "file"
        )?;
        self.cache.set_next_sender_msg_seq_num(next_seq_num).await
    }

    async fn set_next_target_msg_seq_num(&mut self, next_seq_num: isize) -> SimpleResult<()> {
        map_err_with!(
            self.target_seq_nums_file.set_seq_num(next_seq_num).await,
            "file"
        )?;
        self.cache.set_next_target_msg_seq_num(next_seq_num).await
    }

    async fn incr_next_sender_msg_seq_num(&mut self) -> SimpleResult<()> {
        let next = self.cache.next_sender_msg_seq_num().await + 1;
        map_err_with!(self.set_next_sender_msg_seq_num(next).await, "file")?;
        Ok(())
    }

    async fn incr_next_target_msg_seq_num(&mut self) -> SimpleResult<()> {
        let next = self.cache.next_target_msg_seq_num().await + 1;
        map_err_with!(self.set_next_target_msg_seq_num(next).await, "file")?;
        Ok(())
    }

    async fn creation_time(&self) -> Timestamp {
        self.cache.creation_time().await
    }

    async fn save_message(&mut self, seq_num: isize, msg: Vec<u8>) -> SimpleResult<()> {
        let offset = self
            .body_file
            .file
            .as_mut()
            .unwrap()
            .seek(SeekFrom::End(0))
            .await
            .map_err(|err| {
                simple_error!(
                    "unable to seek to end of file: {}: {}",
                    &self.body_file.file_name,
                    &err,
                )
            })?;

        self.header_file
            .file
            .as_mut()
            .unwrap()
            .seek(SeekFrom::End(0))
            .await
            .map_err(|err| {
                simple_error!(
                    "unable to seek to end of file: {}: {}",
                    &self.header_file.file_name,
                    &err
                )
            })?;

        // Build header line without format! allocation.
        let mut hdr_buf = Vec::with_capacity(48);
        let _ = itoap::write(&mut hdr_buf, seq_num);
        hdr_buf.push(b',');
        let _ = itoap::write(&mut hdr_buf, offset);
        hdr_buf.push(b',');
        let _ = itoap::write(&mut hdr_buf, msg.len());
        hdr_buf.push(b'\n');

        self.header_file
            .file
            .as_mut()
            .unwrap()
            .write(&hdr_buf)
            .await
            .map_err(|err| {
                simple_error!(
                    "unable to write to file: {}: {}",
                    &self.header_file.file_name,
                    &err
                )
            })?;

        self.body_file
            .file
            .as_mut()
            .unwrap()
            .write(&msg)
            .await
            .map_err(|err| {
                simple_error!(
                    "unable to write to file: {}: {}",
                    &self.body_file.file_name,
                    &err
                )
            })?;

        if self.file_sync {
            self.sync_body_and_header_files().await?;
        }

        Ok(())
    }

    async fn save_message_and_incr_next_sender_msg_seq_num(
        &mut self,
        seq_num: isize,
        msg: Vec<u8>,
    ) -> SimpleResult<()> {
        self.save_message(seq_num, msg).await?;
        self.incr_next_sender_msg_seq_num().await
    }

    async fn iterate_messages(
        &mut self,
        begin_seq_num: isize,
        end_seq_num: isize,
        cb: &mut (dyn FnMut(&[u8]) -> SimpleResult<()> + Send),
    ) -> SimpleResult<()> {
        // Flush files to ensure all written data is visible to readers.
        self.sync_body_and_header_files().await?;

        // Open separate read-only file handles to avoid conflicts with writers,
        // matching Go's deadlock-avoidance pattern from c93c8d9c.
        let mut body_file = File::open(&self.body_file.file_name)
            .await
            .map_err(|err| {
                simple_error!(
                    "unable to open file: {}: {}",
                    &self.body_file.file_name,
                    &err
                )
            })?;
        let header_file = File::open(&self.header_file.file_name)
            .await
            .map_err(|err| {
                simple_error!(
                    "unable to open file: {}: {}",
                    &self.header_file.file_name,
                    &err
                )
            })?;

        // Collect matching entries from the header file.
        let buf_reader = BufReader::new(header_file);
        let mut lines = buf_reader.lines();
        let mut entries: Vec<(isize, u64, usize)> = Vec::new();

        while let Ok(Some(line)) = lines.next_line().await {
            let Some((seq_num, offset, size)) = sscanf!(&line, "{isize},{u64},{usize}") else {
                continue;
            };
            if seq_num < begin_seq_num || seq_num > end_seq_num {
                continue;
            }
            entries.push((seq_num, offset, size));
        }

        // Sort by sequence number to ensure ordered iteration.
        entries.sort_by_key(|(seq_num, _, _)| *seq_num);

        if entries.is_empty() {
            return Ok(());
        }

        // Bulk read: compute the contiguous range covering all entries,
        // read it in one I/O operation, then slice out individual messages.
        let first_offset = entries.iter().map(|(_, o, _)| *o).min().unwrap();
        let last_end = entries.iter().map(|(_, o, s)| *o + *s as u64).max().unwrap();
        #[allow(clippy::cast_possible_truncation)]
        let bulk_size = (last_end - first_offset) as usize;

        body_file
            .seek(SeekFrom::Start(first_offset))
            .await
            .map_err(|err| {
                simple_error!(
                    "unable to seek in file: {}: {}",
                    &self.body_file.file_name,
                    &err
                )
            })?;
        let mut bulk_buf = vec![0u8; bulk_size];
        body_file
            .read_exact(&mut bulk_buf)
            .await
            .map_err(|err| {
                simple_error!(
                    "unable to read from file: {}: {}",
                    &self.body_file.file_name,
                    &err
                )
            })?;

        for (_, offset, size) in &entries {
            #[allow(clippy::cast_possible_truncation)]
            let start = (*offset - first_offset) as usize;
            cb(&bulk_buf[start..start + size])?;
        }
        Ok(())
    }

    async fn get_messages(
        &mut self,
        begin_seq_num: isize,
        end_seq_num: isize,
    ) -> SimpleResult<Vec<Vec<u8>>> {
        let mut msgs = vec![];
        self.iterate_messages(begin_seq_num, end_seq_num, &mut |m| {
            msgs.push(m.to_vec());
            Ok(())
        })
        .await?;
        Ok(msgs)
    }

    async fn refresh(&mut self) -> SimpleResult<()> {
        map_err_with!(self.cache.reset().await, "cache reset")?;

        self.close().await?;

        let creation_time_populated = self.populate_cache().await?;

        // Reopen all files for read/write access in parallel.
        let (body, header, session, sender, target) = tokio::try_join!(
            open_or_create_file(&self.body_file.file_name, 0o660),
            open_or_create_file(&self.header_file.file_name, 0o660),
            open_or_create_file(&self.session_file.file_name, 0o660),
            open_or_create_file(&self.sender_seq_nums_file.file_name, 0o660),
            open_or_create_file(&self.target_seq_nums_file.file_name, 0o660),
        )?;
        self.body_file.file = Some(body);
        self.header_file.file = Some(header);
        self.session_file.file = Some(session);
        self.sender_seq_nums_file.file = Some(sender);
        self.target_seq_nums_file.file = Some(target);

        if !creation_time_populated {
            self.set_session().await?;
        }

        let next_sender = self.next_sender_msg_seq_num().await;
        map_err_with!(
            self.set_next_sender_msg_seq_num(next_sender).await,
            "set next sender"
        )?;

        let next_target = self.next_target_msg_seq_num().await;
        map_err_with!(
            self.set_next_target_msg_seq_num(next_target).await,
            "set next target"
        )?;

        Ok(())
    }

    async fn reset(&mut self) -> SimpleResult<()> {
        map_err_with!(self.cache.reset().await, "cache reset")?;

        map_err_with!(self.close().await, "close")?;

        // Remove all files in parallel.
        let _ = self.body_file.file.take();
        let _ = self.header_file.file.take();
        let _ = self.session_file.file.take();
        let _ = self.sender_seq_nums_file.file.take();
        let _ = self.target_seq_nums_file.file.take();
        tokio::try_join!(
            remove_file(&self.body_file.file_name),
            remove_file(&self.header_file.file_name),
            remove_file(&self.session_file.file_name),
            remove_file(&self.sender_seq_nums_file.file_name),
            remove_file(&self.target_seq_nums_file.file_name),
        )?;

        self.refresh().await
    }

    async fn close(&mut self) -> SimpleResult<()> {
        let body = self.body_file.file.take();
        let header = self.header_file.file.take();
        let session = self.session_file.file.take();
        let sender = self.sender_seq_nums_file.file.take();
        let target = self.target_seq_nums_file.file.take();
        tokio::try_join!(
            close_file(body),
            close_file(header),
            close_file(session),
            close_file(sender),
            close_file(target),
        )?;
        Ok(())
    }
}

impl FileStore {
    pub async fn new(
        session_id: Arc<SessionID>,
        dirname: String,
        file_sync: bool,
    ) -> SimpleResult<Self> {
        fs::create_dir_all(&dirname)
            .await
            .map_err(|_| simple_error!("cannot create store directory: {}", dirname))?;
        let metadata = fs::metadata(&dirname)
            .await
            .map_err(|_| simple_error!("cannot get store directory metadata: {}", dirname))?;
        metadata.permissions().set_mode(0o511);

        let session_prefix = session_id_filename_prefix(&session_id);

        let body_path = Path::new(&dirname).join(format!("{}.{}", &session_prefix, "body"));
        let body_name = &body_path.as_os_str().to_str().unwrap();
        let body_file = open_or_create_file(body_name, 0o660).await?;
        let header_path = Path::new(&dirname).join(format!("{}.{}", &session_prefix, "header"));
        let header_name = &header_path.as_os_str().to_str().unwrap();
        let header_file = open_or_create_file(header_name, 0o660).await?;
        let session_path = Path::new(&dirname).join(format!("{}.{}", &session_prefix, "session"));
        let session_name = &session_path.as_os_str().to_str().unwrap();
        let session_file = open_or_create_file(session_name, 0o660).await?;
        let sender_seq_nums_path =
            Path::new(&dirname).join(format!("{}.{}", &session_prefix, "senderseqnums"));
        let sender_seq_nums_name = &sender_seq_nums_path.as_os_str().to_str().unwrap();
        let sender_seq_nums_file = open_or_create_file(sender_seq_nums_name, 0o660).await?;
        let target_seq_nums_path =
            Path::new(&dirname).join(format!("{}.{}", &session_prefix, "targetseqnums"));
        let target_seq_nums_name = &target_seq_nums_path.as_os_str().to_str().unwrap();
        let target_seq_nums_file = open_or_create_file(target_seq_nums_name, 0o660).await?;

        let mut store = FileStore {
            session_id,
            cache: MemoryStore::default(),
            body_file: IndividualFile {
                file_name: body_name.to_string(),
                file: Some(body_file),
            },
            header_file: IndividualFile {
                file_name: header_name.to_string(),
                file: Some(header_file),
            },
            session_file: IndividualFile {
                file_name: session_name.to_string(),
                file: Some(session_file),
            },
            sender_seq_nums_file: IndividualFile {
                file_name: sender_seq_nums_name.to_string(),
                file: Some(sender_seq_nums_file),
            },
            target_seq_nums_file: IndividualFile {
                file_name: target_seq_nums_name.to_string(),
                file: Some(target_seq_nums_file),
            },
            file_sync,
        };

        store.refresh().await?;

        Ok(store)
    }

    async fn populate_cache(&mut self) -> SimpleResult<bool> {
        let mut creation_time_populated = false;

        if let Ok(mut file) = File::open(&self.session_file.file_name).await {
            let mut time_bytes: Vec<u8> = Vec::new();
            if file.read_to_end(&mut time_bytes).await.is_ok() {
                if let Ok(input_str) = std::str::from_utf8(&time_bytes) {
                    if let Ok(time) = jiff::Zoned::strptime(TIMESTAMP_FORMAT, input_str.trim()) {
                        self.cache.creation_time = time.timestamp();
                        creation_time_populated = true;
                    }
                }
            }
        }

        if let Ok(mut file) = File::open(&self.sender_seq_nums_file.file_name).await {
            let mut sender_seq_num_bytes: Vec<u8> = Vec::with_capacity(19);
            if file.read_to_end(&mut sender_seq_num_bytes).await.is_ok() {
                if let Ok(sender_seq_num_str) = std::str::from_utf8(&sender_seq_num_bytes) {
                    if let Ok(sender_seq_num) =
                        atoi_simd::parse::<isize, false, false>(sender_seq_num_str.trim().as_bytes())
                    {
                        map_err_with!(
                            self.cache.set_next_sender_msg_seq_num(sender_seq_num).await,
                            "cache set next target"
                        )?;
                    }
                }
            }
        }

        if let Ok(mut file) = File::open(&self.target_seq_nums_file.file_name).await {
            let mut target_seq_num_bytes: Vec<u8> = Vec::with_capacity(19);
            if file.read_to_end(&mut target_seq_num_bytes).await.is_ok() {
                if let Ok(target_seq_num_str) = std::str::from_utf8(&target_seq_num_bytes) {
                    if let Ok(target_seq_num) =
                        atoi_simd::parse::<isize, false, false>(target_seq_num_str.trim().as_bytes())
                    {
                        map_err_with!(
                            self.cache.set_next_target_msg_seq_num(target_seq_num).await,
                            "cache set next target"
                        )?;
                    }
                }
            }
        }

        Ok(creation_time_populated)
    }

    async fn set_session(&mut self) -> SimpleResult<()> {
        self.session_file
            .file
            .as_mut()
            .unwrap()
            .seek(SeekFrom::Start(0))
            .await
            .map_err(|err| {
                simple_error!(
                    "unable to rewind file: {}: {}",
                    &self.session_file.file_name,
                    &err,
                )
            })?;

        let data = self
            .cache
            .creation_time
            .to_zoned(TimeZone::UTC)
            .strftime(TIMESTAMP_FORMAT)
            .to_string();

        self.session_file
            .file
            .as_mut()
            .unwrap()
            .write(data.as_bytes())
            .await
            .map_err(|err| {
                simple_error!(
                    "unable to write to file: {}: {}",
                    &self.session_file.file_name,
                    &err
                )
            })?;

        if self.file_sync {
            self.session_file
                .file
                .as_mut()
                .unwrap()
                .flush()
                .await
                .map_err(|err| {
                    simple_error!(
                        "unable to flush file: {}: {}",
                        &self.session_file.file_name,
                        &err
                    )
                })?;
        }
        Ok(())
    }

    async fn sync_body_and_header_files(&mut self) -> SimpleResult<()> {
        self.body_file
            .file
            .as_mut()
            .unwrap()
            .flush()
            .await
            .map_err(|err| {
                simple_error!(
                    "unable to flush file: {}: {}",
                    &self.body_file.file_name,
                    &err
                )
            })?;
        self.header_file
            .file
            .as_mut()
            .unwrap()
            .flush()
            .await
            .map_err(|err| {
                simple_error!(
                    "unable to flush file: {}: {}",
                    &self.header_file.file_name,
                    &err
                )
            })
    }

}

#[derive(Clone)]
pub struct FileStoreFactory {
    settings: Arc<Mutex<Settings>>,
}

impl MessageStoreFactoryTrait for FileStoreFactory {
    async fn create(&self, session_id: Arc<SessionID>) -> SimpleResult<MessageStoreEnum> {
        let (global_settings, session_settings_map) = {
            let mut lock = self.settings.lock().await;
            let gs = lock.global_settings().await.unwrap();
            let ss = lock.session_settings().await;
            (gs, ss)
        };

        let dynamic_sessions = global_settings
            .bool_setting(DYNAMIC_SESSIONS)
            .unwrap_or(false);

        if let Some(session_settings_pair) = session_settings_map.get(&session_id) {
            let session_settings = session_settings_pair.value();
            return create_file_store(session_id, session_settings).await;
        }
        if dynamic_sessions {
            return create_file_store(session_id, &global_settings).await;
        }
        Err(simple_error!(
            "unknown session: {}",
            &session_id.to_string()
        ))
    }
}

async fn create_file_store(
    session_id: Arc<SessionID>,
    session_settings: &SessionSettings,
) -> SimpleResult<MessageStoreEnum> {
    let dirname = session_settings
        .setting(FILE_STORE_PATH)
        .map_err(SimpleError::from)?;

    let fsync = if session_settings.has_setting(FILE_STORE_SYNC) {
        session_settings
            .bool_setting(FILE_STORE_SYNC)
            .map_err(SimpleError::from)?
    } else {
        true
    };

    Ok(MessageStoreEnum::FileStore(
        FileStore::new(session_id, dirname, fsync).await?,
    ))
}

impl FileStoreFactory {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(settings: Arc<Mutex<Settings>>) -> MessageStoreFactoryEnum {
        MessageStoreFactoryEnum::FileStoreFactory(FileStoreFactory { settings })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        session::session_id::SessionID,
        settings::Settings,
        store::{
            MessageStoreEnum, MessageStoreFactoryTrait, MessageStoreTrait,
            file_store::FileStoreFactory, tests::MessageStoreTestSuite,
        },
    };
    use jiff::Timestamp;
    use std::{env::temp_dir, path::Path, process::id, sync::Arc};
    use tokio::sync::Mutex;

    // FileStoreTestSuite runs all tests in the MessageStoreTestSuite against the FileStore implementation.
    struct FileStoreTestSuite<S: MessageStoreTrait> {
        suite: MessageStoreTestSuite<S>,
        #[allow(dead_code)] // stored for test cleanup
        file_store_root_path: String,
    }

    async fn setup_test() -> FileStoreTestSuite<MessageStoreEnum> {
        let path = Path::new(&temp_dir()).join(format!("FileStoreTestSuite-{}", id()));
        let file_store_path = path.join(format!("{}", Timestamp::now().as_nanosecond()));
        let session_id = SessionID {
            begin_string: String::from("FIX.4.4"),
            sender_comp_id: String::from("SENDER"),
            target_comp_id: String::from("TARGET"),
            ..Default::default()
        };

        // create settings
        let cfg_str = format!(
            r"
[DEFAULT]
FileStorePath={}

[SESSION]
BeginString={}
SenderCompID={}
TargetCompID={}",
            file_store_path.to_str().unwrap(),
            session_id.begin_string,
            session_id.sender_comp_id,
            session_id.target_comp_id
        );

        let cfg = cfg_str.as_bytes();
        let s_result = Settings::parse(cfg).await;
        assert!(s_result.is_ok());
        let settings = s_result.unwrap();

        // create store
        let factory = FileStoreFactory::new(Arc::new(Mutex::new(settings)));
        let store_result = factory.create(Arc::new(session_id.clone())).await;
        assert!(store_result.is_ok());
        let store = store_result.unwrap();

        FileStoreTestSuite {
            suite: MessageStoreTestSuite { msg_store: store },
            file_store_root_path: path.to_str().unwrap().to_string(),
        }
    }

    #[tokio::test]
    async fn test_file_store_test_suite() {
        let mut s = setup_test().await;
        s.suite
            .test_message_store_set_next_msg_seq_num_refresh_incr_next_msg_seq_num()
            .await;
        let _ = s.suite.msg_store.close().await;
        let mut s = setup_test().await;
        s.suite.test_message_store_reset().await;
        let _ = s.suite.msg_store.close().await;
        let mut s = setup_test().await;
        s.suite.test_message_store_save_message_get_message().await;
        let _ = s.suite.msg_store.close().await;
        let mut s = setup_test().await;
        s.suite
            .test_message_store_save_message_and_increment_get_message()
            .await;
        let _ = s.suite.msg_store.close().await;
        let mut s = setup_test().await;
        s.suite.test_message_store_get_messages_empty_store().await;
        let _ = s.suite.msg_store.close().await;
        let mut s = setup_test().await;
        s.suite
            .test_message_store_get_messages_various_ranges()
            .await;
        let _ = s.suite.msg_store.close().await;
        let mut s = setup_test().await;
        s.suite.test_message_store_creation_time().await;
        let _ = s.suite.msg_store.close().await;
    }
}
