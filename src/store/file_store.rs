use crate::{
    config::{DYNAMIC_SESSIONS, FILE_STORE_PATH, FILE_STORE_SYNC},
    fileutil::{close_file, open_or_create_file, remove_file, session_id_filename_prefix},
    session::session_id::SessionID,
    settings::Settings,
    store::{
        MemoryStore, MessageStoreEnum, MessageStoreFactoryEnum, MessageStoreFactoryTrait,
        MessageStoreTrait,
    },
};
use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use simple_error::SimpleResult;
// TODO: check windows os
use sscanf::sscanf;
use std::{
    collections::HashMap, io::SeekFrom, os::unix::prelude::PermissionsExt, path::Path, sync::Arc,
};
use tokio::{
    fs::{self, File},
    io::{AsyncBufReadExt, AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader},
    sync::Mutex,
};

const TIMESTAMP_FORMAT: &str = "%Y-%m-%dT%H:%M:%S%.f%:z";

struct MsgDef {
    offset: u64,
    size: usize,
}

struct IndividualFile {
    file_name: String,
    file: Option<File>,
}

impl IndividualFile {
    async fn set_seq_num(&mut self, seq_num: isize) -> SimpleResult<()> {
        let _ = self.file.as_mut().unwrap().rewind().await;

        self.file
            .as_mut()
            .unwrap()
            .write(format!("{:19}", seq_num).as_bytes())
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
    session_id: Arc<SessionID>,
    cache: MemoryStore,
    offsets: HashMap<isize, MsgDef>,
    body_file: IndividualFile,
    header_file: IndividualFile,
    session_file: IndividualFile,
    sender_seq_nums_file: IndividualFile,
    target_seq_nums_file: IndividualFile,
    file_sync: bool,
}

#[async_trait]
impl MessageStoreTrait for FileStore {
    async fn next_sender_msg_seq_num(&mut self) -> isize {
        self.cache.next_sender_msg_seq_num().await
    }

    async fn next_target_msg_seq_num(&mut self) -> isize {
        self.cache.next_target_msg_seq_num().await
    }

    async fn set_next_sender_msg_seq_num(&mut self, next_seq_num: isize) -> SimpleResult<()> {
        map_err_with!(
            self.cache.set_next_sender_msg_seq_num(next_seq_num).await,
            "cache"
        )?;
        Ok(self.sender_seq_nums_file.set_seq_num(next_seq_num).await?)
    }

    async fn set_next_target_msg_seq_num(&mut self, next_seq_num: isize) -> SimpleResult<()> {
        map_err_with!(
            self.cache.set_next_target_msg_seq_num(next_seq_num).await,
            "cache"
        )?;
        Ok(self.target_seq_nums_file.set_seq_num(next_seq_num).await?)
    }

    async fn incr_next_sender_msg_seq_num(&mut self) -> SimpleResult<()> {
        map_err_with!(self.cache.incr_next_sender_msg_seq_num().await, "cache")?;
        Ok(self
            .sender_seq_nums_file
            .set_seq_num(self.cache.next_sender_msg_seq_num().await)
            .await?)
    }

    async fn incr_next_target_msg_seq_num(&mut self) -> SimpleResult<()> {
        map_err_with!(self.cache.incr_next_target_msg_seq_num().await, "cache")?;
        Ok(self
            .target_seq_nums_file
            .set_seq_num(self.cache.next_target_msg_seq_num().await)
            .await?)
    }

    async fn creation_time(&self) -> DateTime<Utc> {
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

        self.header_file
            .file
            .as_mut()
            .unwrap()
            .write(format!("{},{},{}\n", seq_num, offset, msg.len()).as_bytes())
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
                })?;
        }

        self.offsets.insert(
            seq_num,
            MsgDef {
                offset,
                size: msg.len(),
            },
        );

        Ok(())
    }

    async fn save_message_and_incr_next_sender_msg_seq_num(
        &mut self,
        seq_num: isize,
        msg: Vec<u8>,
    ) -> SimpleResult<()> {
        self.save_message(seq_num, msg).await?;
        Ok(self.incr_next_sender_msg_seq_num().await?)
    }

    async fn get_messages(
        &mut self,
        begin_seq_num: isize,
        end_seq_num: isize,
    ) -> SimpleResult<Vec<Vec<u8>>> {
        let mut msgs = vec![];
        for seq_num in begin_seq_num..=end_seq_num {
            let (m, found) = self.get_message(seq_num).await?;
            if found {
                msgs.push(m);
            }
        }

        Ok(msgs)
    }

    async fn refresh(&mut self) -> SimpleResult<()> {
        map_err_with!(self.cache.reset().await, "cache reset")?;

        self.close().await?;

        let creation_time_populated = self.populate_cache().await?;

        // TODO: consider wrapping these in lock / mutexes to avoid writing to non existent file
        self.body_file.file = Some(open_or_create_file(&self.body_file.file_name, 0o660).await?);

        self.header_file.file =
            Some(open_or_create_file(&self.header_file.file_name, 0o660).await?);

        self.session_file.file =
            Some(open_or_create_file(&self.session_file.file_name, 0o660).await?);

        self.sender_seq_nums_file.file =
            Some(open_or_create_file(&self.sender_seq_nums_file.file_name, 0o660).await?);

        self.target_seq_nums_file.file =
            Some(open_or_create_file(&self.target_seq_nums_file.file_name, 0o660).await?);

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

        // TODO: consider wrapping these in lock / mutexes to avoid writing to non existent file
        let _ = self.body_file.file.take();
        remove_file(&self.body_file.file_name).await?;
        let _ = self.header_file.file.take();
        remove_file(&self.header_file.file_name).await?;
        let _ = self.session_file.file.take();
        remove_file(&self.session_file.file_name).await?;
        let _ = self.sender_seq_nums_file.file.take();
        remove_file(&self.sender_seq_nums_file.file_name).await?;
        let _ = self.target_seq_nums_file.file.take();
        remove_file(&self.target_seq_nums_file.file_name).await?;

        self.refresh().await
    }

    async fn close(&mut self) -> SimpleResult<()> {
        let file_option = self.body_file.file.take();
        close_file(file_option).await?;
        let file_option = self.header_file.file.take();
        close_file(file_option).await?;
        let file_option = self.session_file.file.take();
        close_file(file_option).await?;
        let file_option = self.sender_seq_nums_file.file.take();
        close_file(file_option).await?;
        let file_option = self.target_seq_nums_file.file.take();
        close_file(file_option).await?;
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
            offsets: hashmap! {},
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
        if let Ok(file) = File::open(&self.header_file.file_name).await {
            let buf_reader = BufReader::new(file);
            let mut lines = buf_reader.lines();

            while let Ok(Some(line)) = lines.next_line().await {
                if let Ok(scan_result) = sscanf!(&line, "{isize},{u64},{usize}") {
                    self.offsets.insert(
                        scan_result.0,
                        MsgDef {
                            offset: scan_result.1,
                            size: scan_result.2,
                        },
                    );
                }
            }
        }

        if let Ok(mut file) = File::open(&self.session_file.file_name).await {
            let mut time_bytes: Vec<u8> = Vec::new();
            if file.read_to_end(&mut time_bytes).await.is_ok() {
                let input_str = String::from_utf8_lossy(&time_bytes).to_string();
                if let Ok(time) = Utc.datetime_from_str(&input_str, TIMESTAMP_FORMAT) {
                    self.cache.creation_time = time;
                    creation_time_populated = true;
                }
            }
        }

        if let Ok(mut file) = File::open(&self.sender_seq_nums_file.file_name).await {
            let mut sender_seq_num_bytes: Vec<u8> = Vec::with_capacity(19);
            if file.read_to_end(&mut sender_seq_num_bytes).await.is_ok() {
                let sender_seq_num_string = String::from_utf8_lossy(&sender_seq_num_bytes);
                let sender_seq_num_str = sender_seq_num_string.trim();
                if let Ok(sender_seq_num) = atoi_simd::parse::<isize>(sender_seq_num_str.as_bytes())
                {
                    map_err_with!(
                        self.cache.set_next_sender_msg_seq_num(sender_seq_num).await,
                        "cache set next target"
                    )?;
                }
            }
        }

        if let Ok(mut file) = File::open(&self.target_seq_nums_file.file_name).await {
            let mut target_seq_num_bytes: Vec<u8> = Vec::with_capacity(19);
            if file.read_to_end(&mut target_seq_num_bytes).await.is_ok() {
                let target_seq_num_string = String::from_utf8_lossy(&target_seq_num_bytes);
                let target_seq_num_str = target_seq_num_string.trim();
                if let Ok(target_seq_num) = atoi_simd::parse::<isize>(target_seq_num_str.as_bytes())
                {
                    map_err_with!(
                        self.cache.set_next_target_msg_seq_num(target_seq_num).await,
                        "cache set next target"
                    )?;
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
            .format(TIMESTAMP_FORMAT)
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

    async fn get_message(&mut self, seq_num: isize) -> SimpleResult<(Vec<u8>, bool)> {
        let msg_info_option = self.offsets.get(&seq_num);
        match msg_info_option {
            None => Ok((vec![], false)),
            Some(msg_info) => {
                self.body_file
                    .file
                    .as_mut()
                    .unwrap()
                    .seek(SeekFrom::Start(msg_info.offset))
                    .await
                    .map_err(|err| {
                        simple_error!(
                            "unable to read from file: {}: {}",
                            &self.body_file.file_name,
                            &err,
                        )
                    })?;
                let mut result = vec![0u8; msg_info.size];
                self.body_file
                    .file
                    .as_mut()
                    .unwrap()
                    .read_exact(&mut result)
                    .await
                    .map_err(|err| {
                        simple_error!(
                            "unable to read from file: {}: {}",
                            &self.body_file.file_name,
                            &err,
                        )
                    })?;
                Ok((result, true))
            }
        }
    }
}

pub struct FileStoreFactory {
    settings: Arc<Mutex<Settings>>,
}

#[async_trait]
impl MessageStoreFactoryTrait for FileStoreFactory {
    async fn create(&self, session_id: Arc<SessionID>) -> SimpleResult<MessageStoreEnum> {
        let mut lock = self.settings.lock().await;
        let global_lock = lock.global_settings().await;
        let global_settings_wrapper = global_lock.read().await;
        let global_settings = global_settings_wrapper.as_ref().unwrap();

        let dynamic_sessions = global_settings
            .bool_setting(DYNAMIC_SESSIONS)
            .unwrap_or(false);

        let session_settings_wrapper = lock.session_settings().await;
        let session_settings_option = session_settings_wrapper.get(&session_id);
        let session_settings = match session_settings_option {
            Some(session_settings) => session_settings,
            None => {
                if dynamic_sessions {
                    global_settings
                } else {
                    return Err(simple_error!(
                        "unknown session: {}",
                        &session_id.to_string()
                    ));
                }
            }
        };

        let dirname = session_settings
            .setting(FILE_STORE_PATH)
            .map_err(|err| simple_error!("{}", &err))?;

        let fsync = if session_settings.has_setting(FILE_STORE_SYNC) {
            session_settings
                .bool_setting(FILE_STORE_SYNC)
                .map_err(|err| simple_error!("{}", &err))?
        } else {
            true
        };
        Ok(MessageStoreEnum::FileStore(
            FileStore::new(session_id, dirname, fsync).await?,
        ))
    }
}

impl FileStoreFactory {
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
            file_store::FileStoreFactory, tests::MessageStoreTestSuite, MessageStoreEnum,
            MessageStoreFactoryTrait, MessageStoreTrait,
        },
    };
    use chrono::Utc;
    use std::{env::temp_dir, path::Path, process::id, sync::Arc};
    use tokio::sync::Mutex;

    // FileStoreTestSuite runs all tests in the MessageStoreTestSuite against the FileStore implementation.
    struct FileStoreTestSuite<S: MessageStoreTrait> {
        suite: MessageStoreTestSuite<S>,
        file_store_root_path: String,
    }

    async fn setup_test() -> FileStoreTestSuite<MessageStoreEnum> {
        let path = Path::new(&temp_dir()).join(format!("FileStoreTestSuite-{}", id()));
        let file_store_path = path.join(format!("{}", Utc::now().timestamp_nanos()));
        let session_id = SessionID {
            begin_string: String::from("FIX.4.4"),
            sender_comp_id: String::from("SENDER"),
            target_comp_id: String::from("TARGET"),
            ..Default::default()
        };

        // create settings
        let cfg_str = format!(
            r#"
[DEFAULT]
FileStorePath={}

[SESSION]
BeginString={}
SenderCompID={}
TargetCompID={}"#,
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
        let s = FileStoreTestSuite {
            suite: MessageStoreTestSuite { msg_store: store },
            file_store_root_path: path.to_str().unwrap().to_string(),
        };
        s
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
