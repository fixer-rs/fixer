use crate::{
    config::{
        DYNAMIC_SESSIONS, SQL_STORE_CONN_MAX_LIFETIME, SQL_STORE_DATA_SOURCE_NAME,
        SQL_STORE_DRIVER,
    },
    session::session_id::SessionID,
    session::settings::SessionSettings,
    settings::Settings,
    store::{
        MemoryStore, MessageStoreEnum, MessageStoreFactoryEnum, MessageStoreFactoryTrait,
        MessageStoreTrait,
    },
};
use jiff::Timestamp;
use simple_error::{SimpleError, SimpleResult};
use sqlx::{any::AnyPoolOptions, AnyPool, Row};
use std::{str::FromStr, sync::{Arc, LazyLock}, time::Duration};
use tokio::sync::Mutex;

const CREATE_SESSIONS_TABLE: &str = "CREATE TABLE IF NOT EXISTS sessions (
  beginstring CHAR(8) NOT NULL,
  sendercompid VARCHAR(64) NOT NULL,
  sendersubid VARCHAR(64) NOT NULL,
  senderlocid VARCHAR(64) NOT NULL,
  targetcompid VARCHAR(64) NOT NULL,
  targetsubid VARCHAR(64) NOT NULL,
  targetlocid VARCHAR(64) NOT NULL,
  session_qualifier VARCHAR(64) NOT NULL,
  creation_time TEXT NOT NULL,
  incoming_seqnum INT NOT NULL,
  outgoing_seqnum INT NOT NULL,
  PRIMARY KEY (beginstring, sendercompid, sendersubid, senderlocid,
               targetcompid, targetsubid, targetlocid, session_qualifier)
)";

const CREATE_MESSAGES_TABLE: &str = "CREATE TABLE IF NOT EXISTS messages (
  beginstring CHAR(8) NOT NULL,
  sendercompid VARCHAR(64) NOT NULL,
  sendersubid VARCHAR(64) NOT NULL,
  senderlocid VARCHAR(64) NOT NULL,
  targetcompid VARCHAR(64) NOT NULL,
  targetsubid VARCHAR(64) NOT NULL,
  targetlocid VARCHAR(64) NOT NULL,
  session_qualifier VARCHAR(64) NOT NULL,
  msgseqnum INT NOT NULL,
  message TEXT NOT NULL,
  PRIMARY KEY (beginstring, sendercompid, sendersubid, senderlocid,
               targetcompid, targetsubid, targetlocid, session_qualifier,
               msgseqnum)
)";

// Session WHERE clause used in all session-scoped queries
const SESSION_WHERE: &str = "beginstring=? AND session_qualifier=?
AND sendercompid=? AND sendersubid=? AND senderlocid=?
AND targetcompid=? AND targetsubid=? AND targetlocid=?";

static SQLX_DRIVERS: LazyLock<()> = LazyLock::new(|| {
    sqlx::any::install_default_drivers();
});

pub struct SqlStore {
    session_id: Arc<SessionID>,
    cache: MemoryStore,
    pool: AnyPool,
}

macro_rules! bind_session_id {
    ($query:expr, $s:expr) => {
        $query
            .bind(&$s.begin_string)
            .bind(&$s.qualifier)
            .bind(&$s.sender_comp_id)
            .bind(&$s.sender_sub_id)
            .bind(&$s.sender_location_id)
            .bind(&$s.target_comp_id)
            .bind(&$s.target_sub_id)
            .bind(&$s.target_location_id)
    };
}

impl SqlStore {
    pub async fn new(
        session_id: Arc<SessionID>,
        driver: &str,
        data_source_name: &str,
        conn_max_lifetime: Duration,
    ) -> SimpleResult<Self> {
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
            .map_err(|e| simple_error!("failed to connect to database: {e}"))?;

        // Create tables if they don't exist
        sqlx::query(CREATE_SESSIONS_TABLE)
            .execute(&pool)
            .await
            .map_err(|e| simple_error!("failed to create sessions table: {e}"))?;

        sqlx::query(CREATE_MESSAGES_TABLE)
            .execute(&pool)
            .await
            .map_err(|e| simple_error!("failed to create messages table: {e}"))?;

        let mut store = SqlStore {
            session_id,
            cache: MemoryStore::default(),
            pool,
        };

        store.cache.reset().await?;
        store.populate_cache().await?;

        Ok(store)
    }

    #[allow(clippy::cast_possible_truncation)]
    async fn populate_cache(&mut self) -> SimpleResult<()> {
        let s = &self.session_id;

        let sql = format!(
            "SELECT creation_time, incoming_seqnum, outgoing_seqnum FROM sessions WHERE {SESSION_WHERE}"
        );
        let query = bind_session_id!(sqlx::query(&sql), s);
        let row = query
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| simple_error!("query sessions: {e}"))?;

        if let Some(row) = row {
            // Session record found, load it
            let creation_time_str: String = row
                .try_get("creation_time")
                .map_err(|e| simple_error!("get creation_time: {e}"))?;
            let incoming_seqnum: i32 = row
                .try_get("incoming_seqnum")
                .map_err(|e| simple_error!("get incoming_seqnum: {e}"))?;
            let outgoing_seqnum: i32 = row
                .try_get("outgoing_seqnum")
                .map_err(|e| simple_error!("get outgoing_seqnum: {e}"))?;

            self.cache.creation_time = Timestamp::from_str(&creation_time_str)
                .map_err(|e| simple_error!("parse creation_time '{creation_time_str}': {e}"))?;
            self.cache
                .set_next_target_msg_seq_num(incoming_seqnum as isize)
                .await?;
            self.cache
                .set_next_sender_msg_seq_num(outgoing_seqnum as isize)
                .await?;
        } else {
            // Session record not found, create it
            let creation_time_str = self.cache.creation_time.to_string();
            let query = sqlx::query(
                "INSERT INTO sessions (
                    creation_time, incoming_seqnum, outgoing_seqnum,
                    beginstring, session_qualifier,
                    sendercompid, sendersubid, senderlocid,
                    targetcompid, targetsubid, targetlocid)
                 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&creation_time_str)
            .bind(self.cache.next_target_msg_seq_num().await as i32)
            .bind(self.cache.next_sender_msg_seq_num().await as i32)
            .bind(&s.begin_string)
            .bind(&s.qualifier)
            .bind(&s.sender_comp_id)
            .bind(&s.sender_sub_id)
            .bind(&s.sender_location_id)
            .bind(&s.target_comp_id)
            .bind(&s.target_sub_id)
            .bind(&s.target_location_id);
            query
                .execute(&self.pool)
                .await
                .map_err(|e| simple_error!("insert session: {e}"))?;
        }

        Ok(())
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

#[allow(clippy::cast_possible_truncation)]
impl MessageStoreTrait for SqlStore {
    async fn next_sender_msg_seq_num(&mut self) -> isize {
        self.cache.next_sender_msg_seq_num().await
    }

    async fn next_target_msg_seq_num(&mut self) -> isize {
        self.cache.next_target_msg_seq_num().await
    }

    async fn set_next_sender_msg_seq_num(&mut self, next_seq_num: isize) -> SimpleResult<()> {
        let s = &self.session_id;
        let sql = format!("UPDATE sessions SET outgoing_seqnum = ? WHERE {SESSION_WHERE}");
        let query = bind_session_id!(sqlx::query(&sql).bind(next_seq_num as i32), s);
        query
            .execute(&self.pool)
            .await
            .map_err(|e| simple_error!("update outgoing_seqnum: {e}"))?;

        self.cache.set_next_sender_msg_seq_num(next_seq_num).await
    }

    async fn set_next_target_msg_seq_num(&mut self, next_seq_num: isize) -> SimpleResult<()> {
        let s = &self.session_id;
        let sql = format!("UPDATE sessions SET incoming_seqnum = ? WHERE {SESSION_WHERE}");
        let query = bind_session_id!(sqlx::query(&sql).bind(next_seq_num as i32), s);
        query
            .execute(&self.pool)
            .await
            .map_err(|e| simple_error!("update incoming_seqnum: {e}"))?;

        self.cache.set_next_target_msg_seq_num(next_seq_num).await
    }

    async fn incr_next_sender_msg_seq_num(&mut self) -> SimpleResult<()> {
        let next = self.cache.next_sender_msg_seq_num().await + 1;
        self.set_next_sender_msg_seq_num(next).await
    }

    async fn incr_next_target_msg_seq_num(&mut self) -> SimpleResult<()> {
        let next = self.cache.next_target_msg_seq_num().await + 1;
        self.set_next_target_msg_seq_num(next).await
    }

    async fn creation_time(&self) -> Timestamp {
        self.cache.creation_time
    }

    async fn save_message(&mut self, seq_num: isize, msg: Vec<u8>) -> SimpleResult<()> {
        let s = &self.session_id;
        let msg_str =
            String::from_utf8(msg).map_err(|e| simple_error!("message not valid utf8: {e}"))?;

        let query = sqlx::query(
            "INSERT INTO messages (
                msgseqnum, message,
                beginstring, session_qualifier,
                sendercompid, sendersubid, senderlocid,
                targetcompid, targetsubid, targetlocid)
             VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(seq_num as i32)
        .bind(&msg_str)
        .bind(&s.begin_string)
        .bind(&s.qualifier)
        .bind(&s.sender_comp_id)
        .bind(&s.sender_sub_id)
        .bind(&s.sender_location_id)
        .bind(&s.target_comp_id)
        .bind(&s.target_sub_id)
        .bind(&s.target_location_id);
        query
            .execute(&self.pool)
            .await
            .map_err(|e| simple_error!("insert message: {e}"))?;

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
        let s = &self.session_id;

        let sql = format!(
            "SELECT message FROM messages WHERE {SESSION_WHERE} AND msgseqnum>=? AND msgseqnum<=? ORDER BY msgseqnum"
        );
        let query = bind_session_id!(sqlx::query(&sql), s)
            .bind(begin_seq_num as i32)
            .bind(end_seq_num as i32);
        let rows = query
            .fetch_all(&self.pool)
            .await
            .map_err(|e| simple_error!("query messages: {e}"))?;

        for row in &rows {
            let message: String = row
                .try_get("message")
                .map_err(|e| simple_error!("get message column: {e}"))?;
            cb(message.as_bytes())?;
        }

        Ok(())
    }

    async fn get_messages(
        &mut self,
        begin_seq_num: isize,
        end_seq_num: isize,
    ) -> SimpleResult<Vec<Vec<u8>>> {
        let mut msgs = Vec::new();
        self.iterate_messages(begin_seq_num, end_seq_num, &mut |m| {
            msgs.push(m.to_vec());
            Ok(())
        })
        .await?;
        Ok(msgs)
    }

    async fn refresh(&mut self) -> SimpleResult<()> {
        self.cache.reset().await?;
        self.populate_cache().await
    }

    async fn reset(&mut self) -> SimpleResult<()> {
        let s = &self.session_id;

        // Delete messages for this session
        let sql = format!("DELETE FROM messages WHERE {SESSION_WHERE}");
        let query = bind_session_id!(sqlx::query(&sql), s);
        query
            .execute(&self.pool)
            .await
            .map_err(|e| simple_error!("delete messages: {e}"))?;

        // Reset cache
        self.cache.reset().await?;

        // Update session record with reset values
        let creation_time_str = self.cache.creation_time.to_string();
        let sql = format!(
            "UPDATE sessions SET creation_time=?, incoming_seqnum=?, outgoing_seqnum=? WHERE {SESSION_WHERE}"
        );
        let query = bind_session_id!(
            sqlx::query(&sql)
                .bind(&creation_time_str)
                .bind(self.cache.next_target_msg_seq_num().await as i32)
                .bind(self.cache.next_sender_msg_seq_num().await as i32),
            s
        );
        query
            .execute(&self.pool)
            .await
            .map_err(|e| simple_error!("update session after reset: {e}"))?;

        Ok(())
    }

    async fn close(&mut self) -> SimpleResult<()> {
        self.pool.close().await;
        Ok(())
    }
}

#[derive(Clone)]
pub struct SqlStoreFactory {
    settings: Arc<Mutex<Settings>>,
}

impl MessageStoreFactoryTrait for SqlStoreFactory {
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
            return create_sql_store(session_id, session_settings).await;
        }
        if dynamic_sessions {
            return create_sql_store(session_id, &global_settings).await;
        }
        Err(simple_error!(
            "unknown session: {}",
            &session_id.to_string()
        ))
    }
}

async fn create_sql_store(
    session_id: Arc<SessionID>,
    session_settings: &SessionSettings,
) -> SimpleResult<MessageStoreEnum> {
    let driver = session_settings
        .setting(SQL_STORE_DRIVER)
        .map_err(SimpleError::from)?;

    let data_source_name = session_settings
        .setting(SQL_STORE_DATA_SOURCE_NAME)
        .map_err(SimpleError::from)?;

    let conn_max_lifetime = if session_settings.has_setting(SQL_STORE_CONN_MAX_LIFETIME) {
        let duration_str = session_settings
            .setting(SQL_STORE_CONN_MAX_LIFETIME)
            .map_err(SimpleError::from)?;
        parse_duration::parse(&duration_str)
            .map_err(|e| simple_error!("invalid SQLStoreConnMaxLifetime: {e}"))?
    } else {
        Duration::from_secs(0)
    };

    Ok(MessageStoreEnum::SqlStore(
        SqlStore::new(session_id, &driver, &data_source_name, conn_max_lifetime).await?,
    ))
}

impl SqlStoreFactory {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(settings: Arc<Mutex<Settings>>) -> MessageStoreFactoryEnum {
        MessageStoreFactoryEnum::SqlStoreFactory(SqlStoreFactory { settings })
    }
}

#[cfg(test)]
#[allow(clippy::items_after_statements)]
mod tests {
    use crate::{
        session::session_id::SessionID,
        settings::Settings,
        store::{
            MessageStoreEnum, MessageStoreFactoryTrait, MessageStoreTrait,
            sql_store::SqlStoreFactory, tests::MessageStoreTestSuite,
        },
    };
    use jiff::Timestamp;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    struct SqlStoreTestSuite<S: MessageStoreTrait> {
        suite: MessageStoreTestSuite<S>,
    }

    async fn setup_test() -> SqlStoreTestSuite<MessageStoreEnum> {
        let dir = std::env::temp_dir().join(format!(
            "SqlStoreTestSuite-{}-{}",
            std::process::id(),
            Timestamp::now().as_nanosecond()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("test.db");
        let db_path_str = db_path.to_str().unwrap();

        let session_id = SessionID {
            begin_string: String::from("FIX.4.4"),
            sender_comp_id: String::from("SENDER"),
            target_comp_id: String::from("TARGET"),
            ..Default::default()
        };

        let cfg_str = format!(
            r"
[DEFAULT]
SQLStoreDriver=sqlite3
SQLStoreDataSourceName={db_path_str}

[SESSION]
BeginString={}
SenderCompID={}
TargetCompID={}",
            session_id.begin_string, session_id.sender_comp_id, session_id.target_comp_id
        );

        let cfg = cfg_str.as_bytes();
        let s_result = Settings::parse(cfg).await;
        assert!(s_result.is_ok());
        let settings = s_result.unwrap();

        let factory = SqlStoreFactory::new(Arc::new(Mutex::new(settings)));
        let store_result = factory.create(Arc::new(session_id)).await;
        assert!(
            store_result.is_ok(),
            "create store: {:?}",
            store_result.err()
        );
        let store = store_result.unwrap();

        SqlStoreTestSuite {
            suite: MessageStoreTestSuite { msg_store: store },
        }
    }

    #[tokio::test]
    async fn test_sql_store_test_suite() {
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
