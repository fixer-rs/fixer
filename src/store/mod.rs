use crate::session::session_id::SessionID;
use chrono::NaiveDateTime;
use chrono::Utc;
use dashmap::DashMap;
use simple_error::SimpleResult;

//The MessageStore interface provides methods to record and retrieve messages for resend purposes
pub trait MessageStore: Send + Sync {
    fn next_sender_msg_seq_num(&self) -> isize;
    fn next_target_msg_seq_num(&self) -> isize;
    fn incr_next_sender_msg_seq_num(&mut self) -> SimpleResult<()>;
    fn incr_next_target_msg_seq_num(&mut self) -> SimpleResult<()>;
    fn set_next_sender_msg_seq_num(&mut self, next_seq_num: isize) -> SimpleResult<()>;
    fn set_next_target_msg_seq_num(&mut self, next_seq_num: isize) -> SimpleResult<()>;
    fn creation_time(&self) -> NaiveDateTime;
    fn save_message(&mut self, seq_num: isize, msg: Vec<u8>) -> SimpleResult<()>;
    fn save_message_and_incr_next_sender_msg_seq_num(
        &mut self,
        seq_num: isize,
        msg: Vec<u8>,
    ) -> SimpleResult<()>;
    fn get_messages(&self, begin_seq_num: isize, end_seq_num: isize) -> SimpleResult<Vec<Vec<u8>>>;
    fn refresh(&self) -> SimpleResult<()>;
    fn reset(&mut self) -> SimpleResult<()>;
    fn close(&self) -> SimpleResult<()>;
}

//The MessageStoreFactory interface is used by session to create a session specific message store
pub trait MessageStoreFactory {
    fn create(&self, session_id: SessionID) -> SimpleResult<Box<dyn MessageStore>>;
}

#[derive(Default)]
pub struct MemoryStore {
    pub sender_msg_seq_num: isize,
    pub target_msg_seq_num: isize,
    pub creation_time: NaiveDateTime,
    pub message_map: DashMap<isize, Vec<u8>>,
}

impl MessageStore for MemoryStore {
    fn next_sender_msg_seq_num(&self) -> isize {
        self.sender_msg_seq_num + 1
    }

    fn next_target_msg_seq_num(&self) -> isize {
        self.target_msg_seq_num + 1
    }

    fn incr_next_sender_msg_seq_num(&mut self) -> SimpleResult<()> {
        self.sender_msg_seq_num += 1;
        Ok(())
    }

    fn incr_next_target_msg_seq_num(&mut self) -> SimpleResult<()> {
        self.target_msg_seq_num += 1;
        Ok(())
    }

    fn set_next_sender_msg_seq_num(&mut self, next_seq_num: isize) -> SimpleResult<()> {
        self.sender_msg_seq_num = next_seq_num - 1;
        Ok(())
    }

    fn set_next_target_msg_seq_num(&mut self, next_seq_num: isize) -> SimpleResult<()> {
        self.target_msg_seq_num = next_seq_num - 1;
        Ok(())
    }

    fn creation_time(&self) -> NaiveDateTime {
        self.creation_time
    }

    fn save_message(&mut self, seq_num: isize, msg: Vec<u8>) -> SimpleResult<()> {
        self.message_map.insert(seq_num, msg);
        Ok(())
    }

    fn save_message_and_incr_next_sender_msg_seq_num(
        &mut self,
        seq_num: isize,
        msg: Vec<u8>,
    ) -> SimpleResult<()> {
        self.save_message(seq_num, msg)?;
        Ok(self.incr_next_sender_msg_seq_num()?)
    }

    fn get_messages(&self, begin_seq_num: isize, end_seq_num: isize) -> SimpleResult<Vec<Vec<u8>>> {
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

    fn refresh(&self) -> SimpleResult<()> {
        // nop, nothing to refresh
        Ok(())
    }

    fn reset(&mut self) -> SimpleResult<()> {
        self.sender_msg_seq_num = 0;
        self.target_msg_seq_num = 0;
        self.creation_time = Utc::now().naive_utc();
        self.message_map.clear();
        Ok(())
    }

    fn close(&self) -> SimpleResult<()> {
        // nop, nothing to close
        Ok(())
    }
}

pub struct MemoryStoreFactory;

impl MessageStoreFactory for MemoryStoreFactory {
    fn create(&self, _session_id: SessionID) -> SimpleResult<Box<dyn MessageStore>> {
        let mut m = MemoryStore::default();
        let result = m.reset();
        if result.is_err() {
            return Err(simple_error!("reset: {}", result.unwrap_err()));
        }
        Ok(Box::new(m))
    }
}

impl MemoryStoreFactory {
    // new returns a MessageStoreFactory instance that created in-memory MessageStores
    pub fn new() -> Box<dyn MessageStoreFactory> {
        Box::new(MemoryStoreFactory {})
    }
}
