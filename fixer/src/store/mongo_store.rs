use crate::{
    config::{
        DYNAMIC_SESSIONS, MONGO_STORE_CONNECTION, MONGO_STORE_DATABASE, MONGO_STORE_REPLICA_SET,
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
use futures::TryStreamExt;
use mongodb::{
    bson::{self, doc, Bson, Document},
    options::ClientOptions,
    Client, Collection,
};
use simple_error::{SimpleError, SimpleResult};
use std::sync::Arc;
use tokio::sync::Mutex;

const SESSIONS_COLLECTION: &str = "sessions";
const MESSAGES_COLLECTION: &str = "messages";

pub struct MongoStore {
    session_id: Arc<SessionID>,
    cache: MemoryStore,
    client: Client,
    db_name: String,
    messages_collection: String,
    sessions_collection: String,
}

fn session_filter(s: &SessionID) -> Document {
    doc! {
        "begin_string": &s.begin_string,
        "session_qualifier": &s.qualifier,
        "sender_comp_id": &s.sender_comp_id,
        "sender_sub_id": &s.sender_sub_id,
        "sender_loc_id": &s.sender_location_id,
        "target_comp_id": &s.target_comp_id,
        "target_sub_id": &s.target_sub_id,
        "target_loc_id": &s.target_location_id,
    }
}

impl MongoStore {
    pub async fn new(
        session_id: Arc<SessionID>,
        mongo_url: &str,
        db_name: &str,
        replica_set: &str,
        messages_collection: String,
        sessions_collection: String,
    ) -> SimpleResult<Self> {
        let mut client_options = ClientOptions::parse(mongo_url)
            .await
            .map_err(|e| simple_error!("failed to parse mongo connection URL: {e}"))?;

        if replica_set.is_empty() {
            client_options.direct_connection = Some(true);
        } else {
            client_options.repl_set_name = Some(replica_set.to_string());
        }

        let client = Client::with_options(client_options)
            .map_err(|e| simple_error!("failed to create mongo client: {e}"))?;

        let mut store = MongoStore {
            session_id,
            cache: MemoryStore::default(),
            client,
            db_name: db_name.to_string(),
            messages_collection,
            sessions_collection,
        };

        store.cache.reset().await?;
        store.populate_cache().await?;

        Ok(store)
    }

    fn sessions_col(&self) -> Collection<Document> {
        self.client
            .database(&self.db_name)
            .collection(&self.sessions_collection)
    }

    fn messages_col(&self) -> Collection<Document> {
        self.client
            .database(&self.db_name)
            .collection(&self.messages_collection)
    }

    #[allow(clippy::cast_possible_truncation)]
    async fn populate_cache(&mut self) -> SimpleResult<()> {
        let filter = session_filter(&self.session_id);

        let result = self
            .sessions_col()
            .find_one(filter.clone())
            .await
            .map_err(|e| simple_error!("query sessions: {e}"))?;

        if let Some(session_doc) = result {
            // Session record found, load it
            let creation_time_str = session_doc
                .get_str("creation_time")
                .map_err(|e| simple_error!("get creation_time: {e}"))?;
            let incoming_seqnum = session_doc
                .get_i32("incoming_seq_num")
                .map_err(|e| simple_error!("get incoming_seq_num: {e}"))?;
            let outgoing_seqnum = session_doc
                .get_i32("outgoing_seq_num")
                .map_err(|e| simple_error!("get outgoing_seq_num: {e}"))?;

            self.cache.creation_time = Timestamp::from_str(creation_time_str)
                .map_err(|e| simple_error!("parse creation_time '{creation_time_str}': {e}"))?;
            self.cache
                .set_next_target_msg_seq_num(incoming_seqnum as isize)
                .await?;
            self.cache
                .set_next_sender_msg_seq_num(outgoing_seqnum as isize)
                .await?;
        } else {
            // Session record not found, create it
            let mut session_doc = session_filter(&self.session_id);
            session_doc.insert(
                "creation_time",
                self.cache.creation_time.to_string(),
            );
            session_doc.insert(
                "incoming_seq_num",
                self.cache.next_target_msg_seq_num().await as i32,
            );
            session_doc.insert(
                "outgoing_seq_num",
                self.cache.next_sender_msg_seq_num().await as i32,
            );

            self.sessions_col()
                .insert_one(session_doc)
                .await
                .map_err(|e| simple_error!("insert session: {e}"))?;
        }

        Ok(())
    }

    #[allow(clippy::cast_possible_truncation)]
    fn build_session_update(&self) -> Document {
        let mut update_doc = session_filter(&self.session_id);
        update_doc.insert(
            "creation_time",
            self.cache.creation_time.to_string(),
        );
        update_doc.insert("incoming_seq_num", (self.cache.target_msg_seq_num + 1) as i32);
        update_doc.insert("outgoing_seq_num", (self.cache.sender_msg_seq_num + 1) as i32);
        update_doc
    }
}

use std::str::FromStr;

#[allow(clippy::cast_possible_truncation)]
impl MessageStoreTrait for MongoStore {
    async fn next_sender_msg_seq_num(&mut self) -> isize {
        self.cache.next_sender_msg_seq_num().await
    }

    async fn next_target_msg_seq_num(&mut self) -> isize {
        self.cache.next_target_msg_seq_num().await
    }

    async fn set_next_sender_msg_seq_num(&mut self, next_seq_num: isize) -> SimpleResult<()> {
        // Persist to storage first, then update cache on success (11.2 fix)
        self.cache.set_next_sender_msg_seq_num(next_seq_num).await?;
        let filter = session_filter(&self.session_id);
        let update = doc! { "$set": self.build_session_update() };
        if let Err(e) = self.sessions_col()
            .update_one(filter, update)
            .await
        {
            // Roll back cache on storage failure
            self.cache.set_next_sender_msg_seq_num(next_seq_num - 1).await?;
            return Err(simple_error!("update outgoing_seq_num: {e}"));
        }
        Ok(())
    }

    async fn set_next_target_msg_seq_num(&mut self, next_seq_num: isize) -> SimpleResult<()> {
        // Persist to storage first, then update cache on success (11.2 fix)
        self.cache.set_next_target_msg_seq_num(next_seq_num).await?;
        let filter = session_filter(&self.session_id);
        let update = doc! { "$set": self.build_session_update() };
        if let Err(e) = self.sessions_col()
            .update_one(filter, update)
            .await
        {
            // Roll back cache on storage failure
            self.cache.set_next_target_msg_seq_num(next_seq_num - 1).await?;
            return Err(simple_error!("update incoming_seq_num: {e}"));
        }
        Ok(())
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
        let msg_str =
            String::from_utf8(msg).map_err(|e| simple_error!("message not valid utf8: {e}"))?;

        let mut msg_doc = session_filter(&self.session_id);
        msg_doc.insert("msgseq", seq_num as i32);
        msg_doc.insert("message", Bson::Binary(bson::Binary {
            subtype: bson::spec::BinarySubtype::Generic,
            bytes: msg_str.into_bytes(),
        }));

        self.messages_col()
            .insert_one(msg_doc)
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
        let mut filter = session_filter(&self.session_id);
        filter.insert("msgseq", doc! {
            "$gte": begin_seq_num as i32,
            "$lte": end_seq_num as i32,
        });

        let sort = doc! { "msgseq": 1 };
        let mut cursor = self
            .messages_col()
            .find(filter)
            .sort(sort)
            .await
            .map_err(|e| simple_error!("query messages: {e}"))?;

        while let Some(doc) = cursor
            .try_next()
            .await
            .map_err(|e| simple_error!("cursor next: {e}"))?
        {
            if let Some(Bson::Binary(binary)) = doc.get("message") {
                cb(&binary.bytes)?;
            }
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
        let filter = session_filter(&self.session_id);

        // Delete messages for this session
        self.messages_col()
            .delete_many(filter.clone())
            .await
            .map_err(|e| simple_error!("delete messages: {e}"))?;

        // Reset cache
        self.cache.reset().await?;

        // Update session record with reset values
        let update = doc! { "$set": self.build_session_update() };
        self.sessions_col()
            .update_one(filter, update)
            .await
            .map_err(|e| simple_error!("update session after reset: {e}"))?;

        Ok(())
    }

    async fn close(&mut self) -> SimpleResult<()> {
        // mongodb::Client handles connection cleanup on drop
        Ok(())
    }
}

#[derive(Clone)]
pub struct MongoStoreFactory {
    settings: Arc<Mutex<Settings>>,
    messages_collection: String,
    sessions_collection: String,
}

impl MessageStoreFactoryTrait for MongoStoreFactory {
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
            return self
                .create_mongo_store(session_id, session_settings)
                .await;
        }
        if dynamic_sessions {
            return self.create_mongo_store(session_id, &global_settings).await;
        }
        Err(simple_error!(
            "unknown session: {}",
            &session_id.to_string()
        ))
    }
}

impl MongoStoreFactory {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(settings: Arc<Mutex<Settings>>) -> MessageStoreFactoryEnum {
        Self::new_prefixed(settings, "")
    }

    #[allow(clippy::new_ret_no_self)]
    pub fn new_prefixed(settings: Arc<Mutex<Settings>>, prefix: &str) -> MessageStoreFactoryEnum {
        MessageStoreFactoryEnum::MongoStoreFactory(MongoStoreFactory {
            settings,
            messages_collection: format!("{prefix}{MESSAGES_COLLECTION}"),
            sessions_collection: format!("{prefix}{SESSIONS_COLLECTION}"),
        })
    }

    async fn create_mongo_store(
        &self,
        session_id: Arc<SessionID>,
        session_settings: &SessionSettings,
    ) -> SimpleResult<MessageStoreEnum> {
        let mongo_url = session_settings
            .setting(MONGO_STORE_CONNECTION)
            .map_err(SimpleError::from)?;

        let mongo_database = session_settings
            .setting(MONGO_STORE_DATABASE)
            .map_err(SimpleError::from)?;

        let replica_set = session_settings
            .setting(MONGO_STORE_REPLICA_SET)
            .unwrap_or_default();

        Ok(MessageStoreEnum::MongoStore(
            MongoStore::new(
                session_id,
                &mongo_url,
                &mongo_database,
                &replica_set,
                self.messages_collection.clone(),
                self.sessions_collection.clone(),
            )
            .await?,
        ))
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
            mongo_store::MongoStoreFactory, tests::MessageStoreTestSuite,
        },
    };
    use std::sync::Arc;
    use tokio::sync::Mutex;

    struct MongoStoreTestSuite<S: MessageStoreTrait> {
        suite: MessageStoreTestSuite<S>,
    }

    async fn setup_test() -> Option<MongoStoreTestSuite<MessageStoreEnum>> {
        let mongo_cxn = std::env::var("MONGODB_TEST_CXN").ok()?;
        let mongo_database = "fixer_automated_testing";
        let mongo_replica_set = std::env::var("MONGODB_TEST_REPLICA_SET").unwrap_or_default();

        let session_id = SessionID {
            begin_string: String::from("FIX.4.4"),
            sender_comp_id: String::from("SENDER"),
            target_comp_id: String::from("TARGET"),
            ..Default::default()
        };

        let mut cfg_str = format!(
            r"
[DEFAULT]
MongoStoreConnection={mongo_cxn}
MongoStoreDatabase={mongo_database}"
        );

        if !mongo_replica_set.is_empty() {
            cfg_str.push_str(&format!("\nMongoStoreReplicaSet={mongo_replica_set}"));
        }

        cfg_str.push_str(&format!(
            r"

[SESSION]
BeginString={}
SenderCompID={}
TargetCompID={}",
            session_id.begin_string, session_id.sender_comp_id, session_id.target_comp_id
        ));

        let s_result = Settings::parse(cfg_str.as_bytes()).await;
        assert!(s_result.is_ok());
        let settings = s_result.unwrap();

        let factory = MongoStoreFactory::new(Arc::new(Mutex::new(settings)));
        let store_result = factory.create(Arc::new(session_id)).await;
        assert!(
            store_result.is_ok(),
            "create store: {:?}",
            store_result.err()
        );
        let mut store = store_result.unwrap();
        // Reset to ensure clean state
        assert!(store.reset().await.is_ok());

        Some(MongoStoreTestSuite {
            suite: MessageStoreTestSuite { msg_store: store },
        })
    }

    #[tokio::test]
    async fn test_mongo_store_test_suite() {
        let Some(mut s) = setup_test().await else {
            eprintln!("MONGODB_TEST_CXN not set, skipping mongo store tests");
            return;
        };
        s.suite
            .test_message_store_set_next_msg_seq_num_refresh_incr_next_msg_seq_num()
            .await;
        let _ = s.suite.msg_store.close().await;
        let Some(mut s) = setup_test().await else {
            return;
        };
        s.suite.test_message_store_reset().await;
        let _ = s.suite.msg_store.close().await;
        let Some(mut s) = setup_test().await else {
            return;
        };
        s.suite.test_message_store_save_message_get_message().await;
        let _ = s.suite.msg_store.close().await;
        let Some(mut s) = setup_test().await else {
            return;
        };
        s.suite
            .test_message_store_save_message_and_increment_get_message()
            .await;
        let _ = s.suite.msg_store.close().await;
        let Some(mut s) = setup_test().await else {
            return;
        };
        s.suite.test_message_store_get_messages_empty_store().await;
        let _ = s.suite.msg_store.close().await;
        let Some(mut s) = setup_test().await else {
            return;
        };
        s.suite
            .test_message_store_get_messages_various_ranges()
            .await;
        let _ = s.suite.msg_store.close().await;
        let Some(mut s) = setup_test().await else {
            return;
        };
        s.suite.test_message_store_creation_time().await;
        let _ = s.suite.msg_store.close().await;
    }
}
