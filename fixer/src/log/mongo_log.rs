use crate::{
    config::{
        DYNAMIC_SESSIONS, MONGO_LOG_CONNECTION, MONGO_LOG_DATABASE, MONGO_LOG_REPLICA_SET,
    },
    log::{LogEnum, LogFactoryEnum, LogFactoryTrait, LogTrait},
    session::session_id::SessionID,
    settings::Settings,
};
use mongodb::{
    bson::doc,
    options::ClientOptions,
    Client, Collection,
};
use ramhorns::Template;
use rustc_hash::FxHashMap;
use simple_error::SimpleError;
use std::sync::Arc;
use tokio::sync::Mutex;

const MESSAGES_LOG_COLLECTION: &str = "messages_log";
const EVENT_LOG_COLLECTION: &str = "event_log";

pub struct MongoLog {
    session_id: Arc<SessionID>,
    messages_collection: Collection<mongodb::bson::Document>,
    event_collection: Collection<mongodb::bson::Document>,
}

impl MongoLog {
    async fn new(
        session_id: Arc<SessionID>,
        mongo_url: &str,
        db_name: &str,
        replica_set: &str,
        messages_log_collection: &str,
        event_log_collection: &str,
    ) -> Result<Self, String> {
        let mut client_options = ClientOptions::parse(mongo_url)
            .await
            .map_err(|e| format!("failed to parse mongo connection URL: {e}"))?;

        if replica_set.is_empty() {
            client_options.direct_connection = Some(true);
        } else {
            client_options.repl_set_name = Some(replica_set.to_string());
        }

        let client = Client::with_options(client_options)
            .map_err(|e| format!("failed to create mongo client: {e}"))?;

        let db = client.database(db_name);

        Ok(MongoLog {
            session_id,
            messages_collection: db.collection(messages_log_collection),
            event_collection: db.collection(event_log_collection),
        })
    }

    fn build_entry(&self, text: &[u8]) -> mongodb::bson::Document {
        let s = &self.session_id;
        doc! {
            "time": mongodb::bson::DateTime::now(),
            "begin_string": &s.begin_string,
            "session_qualifier": &s.qualifier,
            "sender_comp_id": &s.sender_comp_id,
            "sender_sub_id": &s.sender_sub_id,
            "sender_loc_id": &s.sender_location_id,
            "target_comp_id": &s.target_comp_id,
            "target_sub_id": &s.target_sub_id,
            "target_loc_id": &s.target_location_id,
            "text": mongodb::bson::Binary { subtype: mongodb::bson::spec::BinarySubtype::Generic, bytes: text.to_vec() },
        }
    }

    async fn insert(&mut self, collection: &str, text: &[u8]) {
        let entry = self.build_entry(text);
        let col = if collection == MESSAGES_LOG_COLLECTION {
            &self.messages_collection
        } else {
            &self.event_collection
        };
        let _ = col.insert_one(entry).await;
    }
}

impl LogTrait for MongoLog {
    async fn on_incoming(&mut self, data: &[u8]) {
        self.insert(MESSAGES_LOG_COLLECTION, data).await;
    }

    async fn on_outgoing(&mut self, data: &[u8]) {
        self.insert(MESSAGES_LOG_COLLECTION, data).await;
    }

    async fn on_event(&mut self, data: &str) {
        self.insert(EVENT_LOG_COLLECTION, data.as_bytes()).await;
    }

    async fn on_eventf(&mut self, fmt: &str, params: FxHashMap<String, String>) {
        let tpl = Template::new(fmt).unwrap();
        self.on_event(&tpl.render(&params)).await;
    }
}

#[derive(Clone)]
pub struct MongoLogFactory {
    settings: Arc<Mutex<Settings>>,
    messages_log_collection: String,
    event_log_collection: String,
}

impl MongoLogFactory {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(settings: Arc<Mutex<Settings>>) -> LogFactoryEnum {
        Self::new_prefixed(settings, "")
    }

    #[allow(clippy::new_ret_no_self)]
    pub fn new_prefixed(settings: Arc<Mutex<Settings>>, prefix: &str) -> LogFactoryEnum {
        LogFactoryEnum::MongoLogFactory(MongoLogFactory {
            settings,
            messages_log_collection: format!("{prefix}{MESSAGES_LOG_COLLECTION}"),
            event_log_collection: format!("{prefix}{EVENT_LOG_COLLECTION}"),
        })
    }

    async fn create_mongo_log(
        &self,
        session_id: Arc<SessionID>,
        session_settings: &crate::session::settings::SessionSettings,
    ) -> Result<LogEnum, String> {
        let mongo_url = session_settings
            .setting(MONGO_LOG_CONNECTION)
            .map_err(|e| SimpleError::from(e).to_string())?;

        let mongo_database = session_settings
            .setting(MONGO_LOG_DATABASE)
            .map_err(|e| SimpleError::from(e).to_string())?;

        let replica_set = session_settings
            .setting(MONGO_LOG_REPLICA_SET)
            .unwrap_or_default();

        let log = MongoLog::new(
            session_id,
            &mongo_url,
            &mongo_database,
            &replica_set,
            &self.messages_log_collection,
            &self.event_log_collection,
        )
        .await?;

        Ok(LogEnum::MongoLog(log))
    }
}

impl LogFactoryTrait for MongoLogFactory {
    async fn create(&mut self) -> Result<LogEnum, String> {
        let global_settings = {
            let mut lock = self.settings.lock().await;
            lock.global_settings().await.unwrap()
        };

        self.create_mongo_log(Arc::new(SessionID::default()), &global_settings)
            .await
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
            return self
                .create_mongo_log(session_id, session_settings)
                .await;
        }
        if dynamic_sessions {
            return self
                .create_mongo_log(session_id, &global_settings)
                .await;
        }
        Err(format!("unknown session: {}", &session_id))
    }
}
