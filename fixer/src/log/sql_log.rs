use crate::{
    config::{
        DYNAMIC_SESSIONS, SQL_LOG_CONN_MAX_LIFETIME, SQL_LOG_DATA_SOURCE_NAME, SQL_LOG_DRIVER,
    },
    log::{LogEnum, LogFactoryEnum, LogFactoryTrait, LogTrait},
    session::session_id::SessionID,
    settings::Settings,
};
use ramhorns::Template;
use rustc_hash::FxHashMap;
use simple_error::SimpleError;
use sqlx::{any::AnyPoolOptions, AnyPool};
use std::{sync::{Arc, LazyLock}, time::Duration};
use tokio::sync::Mutex;

const CREATE_MESSAGES_LOG_TABLE: &str = "CREATE TABLE IF NOT EXISTS messages_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  time TEXT NOT NULL,
  beginstring CHAR(8) NOT NULL,
  sendercompid VARCHAR(64) NOT NULL,
  sendersubid VARCHAR(64) NOT NULL,
  senderlocid VARCHAR(64) NOT NULL,
  targetcompid VARCHAR(64) NOT NULL,
  targetsubid VARCHAR(64) NOT NULL,
  targetlocid VARCHAR(64) NOT NULL,
  session_qualifier VARCHAR(64) NOT NULL,
  text TEXT NOT NULL
)";

const CREATE_EVENT_LOG_TABLE: &str = "CREATE TABLE IF NOT EXISTS event_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  time TEXT NOT NULL,
  beginstring CHAR(8) NOT NULL,
  sendercompid VARCHAR(64) NOT NULL,
  sendersubid VARCHAR(64) NOT NULL,
  senderlocid VARCHAR(64) NOT NULL,
  targetcompid VARCHAR(64) NOT NULL,
  targetsubid VARCHAR(64) NOT NULL,
  targetlocid VARCHAR(64) NOT NULL,
  session_qualifier VARCHAR(64) NOT NULL,
  text TEXT NOT NULL
)";

static SQLX_DRIVERS: LazyLock<()> = LazyLock::new(|| {
    sqlx::any::install_default_drivers();
});

pub struct SqlLog {
    session_id: Arc<SessionID>,
    pool: AnyPool,
}

impl SqlLog {
    async fn new(
        session_id: Arc<SessionID>,
        driver: &str,
        data_source_name: &str,
        conn_max_lifetime: Duration,
    ) -> Result<Self, String> {
        LazyLock::force(&SQLX_DRIVERS);

        let url = build_connection_url(driver, data_source_name);

        let pool = AnyPoolOptions::new()
            .max_lifetime(if conn_max_lifetime.is_zero() {
                None
            } else {
                Some(conn_max_lifetime)
            })
            .connect(&url)
            .await
            .map_err(|e| format!("failed to connect to database: {e}"))?;

        sqlx::query(CREATE_MESSAGES_LOG_TABLE)
            .execute(&pool)
            .await
            .map_err(|e| format!("failed to create messages_log table: {e}"))?;

        sqlx::query(CREATE_EVENT_LOG_TABLE)
            .execute(&pool)
            .await
            .map_err(|e| format!("failed to create event_log table: {e}"))?;

        Ok(SqlLog { session_id, pool })
    }

    async fn insert(&self, table: &str, text: &str) {
        let s = &self.session_id;
        let now = jiff::Timestamp::now().to_string();

        let sql = format!(
            "INSERT INTO {table} (time, beginstring, session_qualifier, sendercompid, sendersubid, senderlocid, targetcompid, targetsubid, targetlocid, text) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        );

        let _ = sqlx::query(&sql)
            .bind(&now)
            .bind(&s.begin_string)
            .bind(&s.qualifier)
            .bind(&s.sender_comp_id)
            .bind(&s.sender_sub_id)
            .bind(&s.sender_location_id)
            .bind(&s.target_comp_id)
            .bind(&s.target_sub_id)
            .bind(&s.target_location_id)
            .bind(text)
            .execute(&self.pool)
            .await;
    }
}

fn build_connection_url(driver: &str, data_source_name: &str) -> String {
    match driver {
        "sqlite" | "sqlite3" => format!("sqlite:{data_source_name}?mode=rwc"),
        "postgres" | "postgresql" => {
            if data_source_name.starts_with("postgres://")
                || data_source_name.starts_with("postgresql://")
            {
                data_source_name.to_string()
            } else {
                format!("postgres://{data_source_name}")
            }
        }
        "mysql" => {
            if data_source_name.starts_with("mysql://") {
                data_source_name.to_string()
            } else {
                format!("mysql://{data_source_name}")
            }
        }
        _ => format!("{driver}://{data_source_name}"),
    }
}

impl LogTrait for SqlLog {
    async fn on_incoming(&mut self, data: &[u8]) {
        let s = std::str::from_utf8(data).unwrap_or("<invalid utf8>");
        self.insert("messages_log", s).await;
    }

    async fn on_outgoing(&mut self, data: &[u8]) {
        let s = std::str::from_utf8(data).unwrap_or("<invalid utf8>");
        self.insert("messages_log", s).await;
    }

    async fn on_event(&mut self, data: &str) {
        self.insert("event_log", data).await;
    }

    async fn on_eventf(&mut self, fmt: &str, params: FxHashMap<String, String>) {
        let tpl = Template::new(fmt).unwrap();
        self.on_event(&tpl.render(&params)).await;
    }
}

#[derive(Clone)]
pub struct SqlLogFactory {
    settings: Arc<Mutex<Settings>>,
}

impl SqlLogFactory {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(settings: Arc<Mutex<Settings>>) -> LogFactoryEnum {
        LogFactoryEnum::SqlLogFactory(SqlLogFactory { settings })
    }
}

impl LogFactoryTrait for SqlLogFactory {
    async fn create(&mut self) -> Result<LogEnum, String> {
        let global_settings = {
            let mut lock = self.settings.lock().await;
            lock.global_settings().await.unwrap()
        };

        create_sql_log(Arc::new(SessionID::default()), &global_settings).await
    }

    async fn create_session_log(
        &mut self,
        session_id: Arc<SessionID>,
    ) -> Result<LogEnum, String> {
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
            return create_sql_log(session_id, session_settings).await;
        }
        if dynamic_sessions {
            return create_sql_log(session_id, &global_settings).await;
        }
        Err(format!("unknown session: {}", &session_id))
    }
}

async fn create_sql_log(
    session_id: Arc<SessionID>,
    session_settings: &crate::session::settings::SessionSettings,
) -> Result<LogEnum, String> {
    let driver = session_settings
        .setting(SQL_LOG_DRIVER)
        .map_err(|e| SimpleError::from(e).to_string())?;

    let data_source_name = session_settings
        .setting(SQL_LOG_DATA_SOURCE_NAME)
        .map_err(|e| SimpleError::from(e).to_string())?;

    let conn_max_lifetime = if session_settings.has_setting(SQL_LOG_CONN_MAX_LIFETIME) {
        let duration_str = session_settings
            .setting(SQL_LOG_CONN_MAX_LIFETIME)
            .map_err(|e| SimpleError::from(e).to_string())?;
        parse_duration::parse(&duration_str)
            .map_err(|e| format!("invalid SQLLogConnMaxLifetime: {e}"))?
    } else {
        Duration::from_secs(0)
    };

    let log = SqlLog::new(session_id, &driver, &data_source_name, conn_max_lifetime).await?;
    Ok(LogEnum::SqlLog(log))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::LogTrait;
    use crate::session::session_id::SessionID;
    use sqlx::Row;
    use std::sync::Arc;

    async fn setup_test_log() -> SqlLog {
        let session_id = Arc::new(SessionID {
            begin_string: String::from("FIX.4.4"),
            sender_comp_id: String::from("SENDER"),
            target_comp_id: String::from("TARGET"),
            ..Default::default()
        });

        let dir = std::env::temp_dir().join(format!(
            "SqlLogTest-{}-{}",
            std::process::id(),
            jiff::Timestamp::now().as_nanosecond()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("test.db");
        let db_path_str = db_path.to_str().unwrap();

        SqlLog::new(session_id, "sqlite", db_path_str, Duration::from_secs(0))
            .await
            .expect("should create sql log")
    }

    #[tokio::test]
    async fn test_sql_log_on_incoming() {
        let mut log = setup_test_log().await;
        log.on_incoming(b"8=FIX.4.4\x0135=A\x01").await;

        let rows: Vec<_> = sqlx::query("SELECT text FROM messages_log")
            .fetch_all(&log.pool)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        let text: &str = rows[0].get("text");
        assert_eq!(text, "8=FIX.4.4\x0135=A\x01");
    }

    #[tokio::test]
    async fn test_sql_log_on_outgoing() {
        let mut log = setup_test_log().await;
        log.on_outgoing(b"8=FIX.4.4\x0135=0\x01").await;

        let rows: Vec<_> = sqlx::query("SELECT text FROM messages_log")
            .fetch_all(&log.pool)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        let text: &str = rows[0].get("text");
        assert_eq!(text, "8=FIX.4.4\x0135=0\x01");
    }

    #[tokio::test]
    async fn test_sql_log_on_event() {
        let mut log = setup_test_log().await;
        log.on_event("Session created").await;

        let rows: Vec<_> = sqlx::query("SELECT text FROM event_log")
            .fetch_all(&log.pool)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        let text: &str = rows[0].get("text");
        assert_eq!(text, "Session created");
    }

    #[tokio::test]
    async fn test_sql_log_session_fields() {
        let mut log = setup_test_log().await;
        log.on_event("test").await;

        let rows: Vec<_> = sqlx::query(
            "SELECT beginstring, sendercompid, targetcompid FROM event_log",
        )
        .fetch_all(&log.pool)
        .await
        .unwrap();
        assert_eq!(rows.len(), 1);
        let begin_string: &str = rows[0].get("beginstring");
        let sender: &str = rows[0].get("sendercompid");
        let target: &str = rows[0].get("targetcompid");
        assert_eq!(begin_string, "FIX.4.4");
        assert_eq!(sender, "SENDER");
        assert_eq!(target, "TARGET");
    }
}
