use crate::session::session_id::SessionID;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use enum_dispatch::enum_dispatch;
use simple_error::SimpleResult;
use std::collections::HashMap;

// The MessageStore interface provides methods to record and retrieve messages for resend purposes
#[async_trait]
#[enum_dispatch]
pub trait MessageStoreTrait {
    async fn next_sender_msg_seq_num(&mut self) -> isize;
    async fn next_target_msg_seq_num(&mut self) -> isize;
    async fn incr_next_sender_msg_seq_num(&mut self) -> SimpleResult<()>;
    async fn incr_next_target_msg_seq_num(&mut self) -> SimpleResult<()>;
    async fn set_next_sender_msg_seq_num(&mut self, next_seq_num: isize) -> SimpleResult<()>;
    async fn set_next_target_msg_seq_num(&mut self, next_seq_num: isize) -> SimpleResult<()>;
    async fn creation_time(&self) -> DateTime<Utc>;
    async fn save_message(&mut self, seq_num: isize, msg: Vec<u8>) -> SimpleResult<()>;
    async fn save_message_and_incr_next_sender_msg_seq_num(
        &mut self,
        seq_num: isize,
        msg: Vec<u8>,
    ) -> SimpleResult<()>;
    async fn get_messages(
        &self,
        begin_seq_num: isize,
        end_seq_num: isize,
    ) -> SimpleResult<Vec<Vec<u8>>>;
    async fn refresh(&mut self) -> SimpleResult<()>;
    async fn reset(&mut self) -> SimpleResult<()>;
    async fn close(&mut self) -> SimpleResult<()>;
}

//The MessageStoreFactory interface is used by session to create a session specific message store
#[async_trait]
#[enum_dispatch]
pub trait MessageStoreFactoryTrait {
    async fn create(&self, session_id: SessionID) -> SimpleResult<MessageStoreEnum>;
}

#[enum_dispatch(MessageStoreTrait)]
pub enum MessageStoreEnum {
    MemoryStore,
    #[cfg(test)]
    MockMemoryStore(crate::fixer_test::MockStoreShared),
}

impl Default for MessageStoreEnum {
    fn default() -> Self {
        Self::MemoryStore(MemoryStore::default())
    }
}

#[enum_dispatch(MessageStoreFactoryTrait)]
pub enum MessageStoreFactoryEnum {
    MemoryStoreFactory,
}

#[derive(Default)]
pub struct MemoryStore {
    pub sender_msg_seq_num: isize,
    pub target_msg_seq_num: isize,
    pub creation_time: DateTime<Utc>,
    pub message_map: HashMap<isize, Vec<u8>>,
}

#[async_trait]
impl MessageStoreTrait for MemoryStore {
    async fn next_sender_msg_seq_num(&mut self) -> isize {
        self.sender_msg_seq_num + 1
    }

    async fn next_target_msg_seq_num(&mut self) -> isize {
        self.target_msg_seq_num + 1
    }

    async fn incr_next_sender_msg_seq_num(&mut self) -> SimpleResult<()> {
        self.sender_msg_seq_num += 1;
        Ok(())
    }

    async fn incr_next_target_msg_seq_num(&mut self) -> SimpleResult<()> {
        self.target_msg_seq_num += 1;
        Ok(())
    }

    async fn set_next_sender_msg_seq_num(&mut self, next_seq_num: isize) -> SimpleResult<()> {
        self.sender_msg_seq_num = next_seq_num - 1;
        Ok(())
    }

    async fn set_next_target_msg_seq_num(&mut self, next_seq_num: isize) -> SimpleResult<()> {
        self.target_msg_seq_num = next_seq_num - 1;
        Ok(())
    }

    async fn creation_time(&self) -> DateTime<Utc> {
        self.creation_time
    }

    async fn save_message(&mut self, seq_num: isize, msg: Vec<u8>) -> SimpleResult<()> {
        self.message_map.insert(seq_num, msg);
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
        &self,
        begin_seq_num: isize,
        end_seq_num: isize,
    ) -> SimpleResult<Vec<Vec<u8>>> {
        let mut msgs: Vec<Vec<u8>> = vec![];
        let mut seq_num = begin_seq_num;
        while seq_num <= end_seq_num {
            if self.message_map.contains_key(&seq_num) {
                msgs.push(self.message_map.get(&seq_num).unwrap().to_vec());
            }
            seq_num += 1;
        }

        Ok(msgs)
    }

    async fn refresh(&mut self) -> SimpleResult<()> {
        // nop, nothing to refresh
        Ok(())
    }

    async fn reset(&mut self) -> SimpleResult<()> {
        self.sender_msg_seq_num = 0;
        self.target_msg_seq_num = 0;
        self.creation_time = Utc::now().into();
        self.message_map.clear();
        Ok(())
    }

    async fn close(&mut self) -> SimpleResult<()> {
        // nop, nothing to close
        Ok(())
    }
}

pub struct MemoryStoreFactory;

#[async_trait]
impl MessageStoreFactoryTrait for MemoryStoreFactory {
    async fn create(&self, _session_id: SessionID) -> SimpleResult<MessageStoreEnum> {
        let mut m = MemoryStore::default();
        let result = m.reset().await;
        if result.is_err() {
            return Err(simple_error!("reset: {}", result.unwrap_err()));
        }
        Ok(MessageStoreEnum::MemoryStore(m))
    }
}

impl MemoryStoreFactory {
    // new returns a MessageStoreFactory instance that created in-memory MessageStores
    pub fn new() -> MessageStoreFactoryEnum {
        MessageStoreFactoryEnum::MemoryStoreFactory(MemoryStoreFactory)
    }
}
