use crate::{
    config::FILE_LOG_PATH,
    errors::FixerError,
    fileutil::session_id_filename_prefix,
    log::{LogEnum, LogFactoryEnum, LogFactoryTrait, LogTrait},
    session::session_id::SessionID,
    settings::Settings,
};
use async_trait::async_trait;
use ramhorns::Template;
use std::{collections::HashMap, path::Path, sync::Arc};
use tokio::{
    fs::{DirBuilder, File, OpenOptions},
    io::AsyncWriteExt,
};

const GLOBAL_PATH: &str = "GLOBAL";

pub struct FileLog {
    event_file: File,
    message_file: File,
}

#[async_trait]
impl LogTrait for FileLog {
    async fn on_incoming(&mut self, data: &[u8]) {
        let mut mut_data = data.to_owned();
        mut_data.push(b'\n');
        let _ = self.message_file.write_all(&mut_data).await;
    }

    async fn on_outgoing(&mut self, data: &[u8]) {
        let mut mut_data = data.to_owned();
        mut_data.push(b'\n');
        let _ = self.message_file.write_all(&mut_data).await;
    }

    async fn on_event(&mut self, data: &str) {
        let mut mut_data = data.as_bytes().to_owned();
        mut_data.push(b'\n');
        let _ = self.event_file.write_all(&mut_data).await;
    }

    async fn on_eventf(&mut self, fmt: &str, params: HashMap<String, String>) {
        let tpl = Template::new(fmt).unwrap();
        self.on_event(&tpl.render(&params)).await;
    }
}

impl FileLog {
    async fn new(prefix: &str, log_path: &str) -> Result<Self, String> {
        let event_log_name = Path::new(log_path).join(prefix.to_string() + ".event.current.log");
        let message_log_name =
            Path::new(log_path).join(prefix.to_string() + ".messages.current.log");

        DirBuilder::new()
            .mode(0o777)
            .recursive(true)
            .create(log_path)
            .await
            .map_err(|err| err.to_string())?;

        let event_file = OpenOptions::new()
            .write(true)
            .read(true)
            .create(true)
            .append(true)
            .open(&event_log_name)
            .await
            .map_err(|err| err.to_string())?;

        let message_file = OpenOptions::new()
            .write(true)
            .read(true)
            .create(true)
            .append(true)
            .open(&message_log_name)
            .await
            .map_err(|err| err.to_string())?;

        Ok(FileLog {
            event_file,
            message_file,
        })
    }
}

#[derive(Default, Clone)]
pub struct FileLogFactory {
    global_log_path: String,
    session_log_paths: HashMap<Arc<SessionID>, String>,
}

impl FileLogFactory {
    // new creates an instance of LogFactory that writes messages and events to file.
    // The location of global and session log files is configured via FileLogPath.
    pub async fn new(settings: &mut Settings) -> Result<LogFactoryEnum, FixerError> {
        let mut log_factory = FileLogFactory::default();

        let gs_option = settings.global_settings().await;
        let gss = gs_option.as_ref().unwrap();
        let res = gss.setting(FILE_LOG_PATH)?;
        log_factory.global_log_path = res;

        for (sid, session_settings) in settings.session_settings().await.iter() {
            let log_path = session_settings.setting(FILE_LOG_PATH)?;
            log_factory.session_log_paths.insert(sid.clone(), log_path);
        }

        Ok(LogFactoryEnum::FileLogFactory(log_factory))
    }
}

#[async_trait]
impl LogFactoryTrait for FileLogFactory {
    async fn create(&mut self) -> Result<LogEnum, String> {
        let logger = FileLog::new(GLOBAL_PATH, &self.global_log_path).await?;
        Ok(LogEnum::FileLog(logger))
    }

    async fn create_session_log(&mut self, session_id: Arc<SessionID>) -> Result<LogEnum, String> {
        let prefix = session_id_filename_prefix(&session_id);
        let log_path = self.session_log_paths.get(&session_id).ok_or(format!(
            "logger not defined for {:?}",
            &*session_id.to_string()
        ))?;

        let logger = FileLog::new(&prefix, log_path).await?;
        Ok(LogEnum::FileLog(logger))
    }
}

#[cfg(test)]
mod tests {
    use super::FileLogFactory;
    use crate::{
        log::{LogFactoryTrait, LogTrait},
        settings::Settings,
    };
    use std::{env::temp_dir, path::Path};
    use tokio::{
        fs::File,
        io::{AsyncBufReadExt, BufReader},
    };

    async fn generate_helper(global_path: &str, local_path: &str) -> Settings {
        let cfg_str = format!(
            r#"# default settings for sessions
[DEFAULT]
ConnectionType=initiator
ReconnectInterval=60
SenderCompID=TW
FileLogPath={}

# session definition
[SESSION]
BeginString=FIX.4.1
TargetCompID=ARCA
FileLogPath={}

[SESSION]
BeginString=FIX.4.1
TargetCompID=ARCA
SessionQualifier=BS
"#,
            global_path, local_path,
        );
        let cfg = cfg_str.as_bytes();

        let s_result = Settings::parse(cfg).await;
        assert!(s_result.is_ok());
        s_result.unwrap()
    }

    #[tokio::test]
    async fn test_file_log_file_log_factory_new() {
        let file_log_factory_result = FileLogFactory::new(&mut Settings::new()).await;
        assert!(
            file_log_factory_result.is_err(),
            "Should expect error when settings have no file log path"
        );

        let mut settings = generate_helper(".", "mydir").await;

        let factory_result = FileLogFactory::new(&mut settings).await;
        assert!(factory_result.is_ok(), "Did not expect error",);
    }

    #[tokio::test]
    async fn test_new_file_log() {
        let tmp = String::from(temp_dir().to_str().unwrap());
        let mut settings = generate_helper(&tmp, &tmp).await;
        let factory_result = FileLogFactory::new(&mut settings).await;
        assert!(factory_result.is_ok());
        let mut factory = factory_result.unwrap();

        let logger_result = factory.create().await;
        assert!(logger_result.is_ok());
        let messages_path = Path::new(&tmp).join(format!("{}.messages.current.log", "GLOBAL"));
        let event_path = Path::new(&tmp).join(format!("{}.event.current.log", "GLOBAL"));
        let messages_exists = messages_path.exists();
        let event_exists = event_path.exists();
        assert!(messages_exists);
        assert!(event_exists);
    }

    #[tokio::test]
    async fn test_file_log_append() {
        let tmp = String::from(temp_dir().to_str().unwrap());
        let mut settings = generate_helper(&tmp, &tmp).await;
        let factory_result = FileLogFactory::new(&mut settings).await;
        assert!(factory_result.is_ok());
        let mut factory = factory_result.unwrap();

        let logger_result = factory.create().await;
        assert!(logger_result.is_ok());
        let mut logger = logger_result.unwrap();

        let message_path = Path::new(&tmp).join(format!("{}.messages.current.log", "GLOBAL"));
        let event_path = Path::new(&tmp).join(format!("{}.event.current.log", "GLOBAL"));

        let message_file_result = File::open(message_path).await;
        assert!(message_file_result.is_ok());
        let message_file = message_file_result.unwrap();
        let mut message_reader = BufReader::new(message_file);

        let event_file_result = File::open(event_path).await;
        assert!(event_file_result.is_ok());
        let event_file = event_file_result.unwrap();
        let mut event_reader = BufReader::new(event_file);

        logger.on_incoming(b"incoming").await;
        let mut msg_buf = String::new();
        let message_read_result = message_reader.read_line(&mut msg_buf).await;
        assert!(message_read_result.is_ok());
        assert!(message_read_result.unwrap() != 0);

        logger.on_event("Event").await;
        let mut msg_buf = String::new();
        let event_read_result = event_reader.read_line(&mut msg_buf).await;
        assert!(event_read_result.is_ok());
        assert!(event_read_result.unwrap() != 0);

        let new_factory_result = FileLogFactory::new(&mut settings).await;
        assert!(new_factory_result.is_ok());
        let mut new_factory = new_factory_result.unwrap();

        let new_logger_result = new_factory.create().await;
        assert!(new_logger_result.is_ok());
        let mut new_logger = new_logger_result.unwrap();

        new_logger.on_incoming(b"incoming").await;
        let mut msg_buf = String::new();
        let message_read_result = message_reader.read_line(&mut msg_buf).await;
        assert!(message_read_result.is_ok());
        assert!(message_read_result.unwrap() != 0);

        new_logger.on_event("Event").await;
        let mut msg_buf = String::new();
        let event_read_result = event_reader.read_line(&mut msg_buf).await;
        assert!(event_read_result.is_ok());
        assert!(event_read_result.unwrap() != 0);
    }
}
