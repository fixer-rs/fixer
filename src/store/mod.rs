use crate::session::session_id::SessionID;
use crate::store::file_store::{FileStore, FileStoreFactory};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use enum_dispatch::enum_dispatch;
use simple_error::SimpleResult;
use std::collections::HashMap;
use std::sync::Arc;

pub mod file_store;

// The MessageStoreTrait interface provides methods to record and retrieve messages for resend purposes
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
        &mut self,
        begin_seq_num: isize,
        end_seq_num: isize,
    ) -> SimpleResult<Vec<Vec<u8>>>;

    async fn refresh(&mut self) -> SimpleResult<()>;
    async fn reset(&mut self) -> SimpleResult<()>;

    async fn close(&mut self) -> SimpleResult<()>;
}

// The MessageStoreFactoryTrait interface is used by session to create a session specific message store
#[async_trait]
#[enum_dispatch]
pub trait MessageStoreFactoryTrait {
    async fn create(&self, session_id: Arc<SessionID>) -> SimpleResult<MessageStoreEnum>;
}

#[enum_dispatch(MessageStoreTrait)]
pub enum MessageStoreEnum {
    MemoryStore,
    FileStore,
    #[cfg(test)]
    MockMemoryStore(crate::fixer_test::MockStoreShared),
}

impl Default for MessageStoreEnum {
    fn default() -> Self {
        Self::MemoryStore(MemoryStore::default())
    }
}

#[enum_dispatch(MessageStoreFactoryTrait)]
#[derive(Clone)]
pub enum MessageStoreFactoryEnum {
    MemoryStoreFactory,
    FileStoreFactory,
}

impl Default for MessageStoreFactoryEnum {
    fn default() -> Self {
        MemoryStoreFactory::new()
    }
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

    async fn reset(&mut self) -> SimpleResult<()> {
        self.sender_msg_seq_num = 0;
        self.target_msg_seq_num = 0;
        self.creation_time = Utc::now();
        self.message_map.clear();
        Ok(())
    }

    async fn refresh(&mut self) -> SimpleResult<()> {
        // nop, nothing to refresh
        Ok(())
    }

    async fn close(&mut self) -> SimpleResult<()> {
        // nop, nothing to close
        Ok(())
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
        &mut self,
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
}

#[derive(Clone)]
pub struct MemoryStoreFactory;

#[async_trait]
impl MessageStoreFactoryTrait for MemoryStoreFactory {
    async fn create(&self, _session_id: Arc<SessionID>) -> SimpleResult<MessageStoreEnum> {
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

#[cfg(test)]
mod tests {
    use crate::{
        session::session_id::SessionID,
        store::{
            MemoryStoreFactory, MessageStoreEnum, MessageStoreFactoryTrait, MessageStoreTrait,
        },
    };
    use chrono::Utc;
    use std::{collections::HashMap, sync::Arc};

    // MessageStoreTestSuite is the suite of all tests that should be run against all MessageStore implementations.
    pub struct MessageStoreTestSuite<S: MessageStoreTrait> {
        pub msg_store: S,
    }

    impl<S: MessageStoreTrait> MessageStoreTestSuite<S> {
        pub async fn test_message_store_set_next_msg_seq_num_refresh_incr_next_msg_seq_num(
            &mut self,
        ) {
            // Given a MessageStore with the following sender and target seqnums
            assert!(self
                .msg_store
                .set_next_sender_msg_seq_num(867)
                .await
                .is_ok());
            assert!(self
                .msg_store
                .set_next_target_msg_seq_num(5309)
                .await
                .is_ok());

            // When the store is refreshed from its backing store
            assert!(self.msg_store.refresh().await.is_ok());

            // Then the sender and target seqnums should still be
            assert_eq!(867, self.msg_store.next_sender_msg_seq_num().await);
            assert_eq!(5309, self.msg_store.next_target_msg_seq_num().await);

            // When the sender and target seqnums are incremented
            assert!(self.msg_store.incr_next_sender_msg_seq_num().await.is_ok());
            assert!(self.msg_store.incr_next_target_msg_seq_num().await.is_ok());

            // Then the sender and target seqnums should be
            assert_eq!(868, self.msg_store.next_sender_msg_seq_num().await);
            assert_eq!(5310, self.msg_store.next_target_msg_seq_num().await);

            // When the store is refreshed from its backing store
            assert!(self.msg_store.refresh().await.is_ok());

            // Then the sender and target seqnums should still be
            assert_eq!(868, self.msg_store.next_sender_msg_seq_num().await);
            assert_eq!(5310, self.msg_store.next_target_msg_seq_num().await);
        }

        pub async fn test_message_store_reset(&mut self) {
            // Given a MessageStore with the following sender and target seqnums
            assert!(self
                .msg_store
                .set_next_sender_msg_seq_num(1234)
                .await
                .is_ok());
            assert!(self
                .msg_store
                .set_next_target_msg_seq_num(5678)
                .await
                .is_ok());

            // When the store is reset
            assert!(self.msg_store.reset().await.is_ok());

            // Then the sender and target seqnums should be
            assert_eq!(1, self.msg_store.next_sender_msg_seq_num().await);
            assert_eq!(1, self.msg_store.next_target_msg_seq_num().await);

            // When the store is refreshed from its backing store
            assert!(self.msg_store.refresh().await.is_ok());

            // Then the sender and target seqnums should still be
            assert_eq!(1, self.msg_store.next_sender_msg_seq_num().await);
            assert_eq!(1, self.msg_store.next_target_msg_seq_num().await);
        }

        pub async fn test_message_store_save_message_get_message(&mut self) {
            // Given the following saved messages
            let expected_msgs_by_seq_num: HashMap<isize, String> = hashmap! {
                1 => String::from("In the frozen land of Nador"),
                2 => String::from("they were forced to eat Robin's minstrels"),
                3 => String::from("and there was much rejoicing"),
            };

            for (seq_num, msg) in expected_msgs_by_seq_num.iter() {
                assert!(self
                    .msg_store
                    .save_message(*seq_num, msg.clone().into_bytes())
                    .await
                    .is_ok());
            }

            // When the messages are retrieved from the MessageStore
            let actual_msgs_result = self.msg_store.get_messages(1, 3).await;
            assert!(actual_msgs_result.is_ok());
            let actual_msgs = actual_msgs_result.unwrap();

            // Then the messages should be
            assert_eq!(actual_msgs.len(), 3);
            assert_eq!(
                expected_msgs_by_seq_num.get(&1).unwrap().as_bytes(),
                actual_msgs[0],
            );
            assert_eq!(
                expected_msgs_by_seq_num.get(&2).unwrap().as_bytes(),
                actual_msgs[1],
            );
            assert_eq!(
                expected_msgs_by_seq_num.get(&3).unwrap().as_bytes(),
                actual_msgs[2],
            );

            // When the store is refreshed from its backing store
            assert!(self.msg_store.refresh().await.is_ok());

            // And the messages are retrieved from the MessageStore
            let actual_msgs_result = self.msg_store.get_messages(1, 3).await;
            assert!(actual_msgs_result.is_ok());
            let actual_msgs = actual_msgs_result.unwrap();

            // Then the messages should still be
            assert_eq!(actual_msgs.len(), 3);
            assert_eq!(
                expected_msgs_by_seq_num.get(&1).unwrap().as_bytes(),
                actual_msgs[0]
            );
            assert_eq!(
                expected_msgs_by_seq_num.get(&2).unwrap().as_bytes(),
                actual_msgs[1]
            );
            assert_eq!(
                expected_msgs_by_seq_num.get(&3).unwrap().as_bytes(),
                actual_msgs[2]
            );
        }

        pub async fn test_message_store_save_message_and_increment_get_message(&mut self) {
            assert!(self
                .msg_store
                .set_next_sender_msg_seq_num(420)
                .await
                .is_ok());

            // Given the following saved messages
            let expected_msgs_by_seq_num: HashMap<isize, String> = hashmap! {
                1 => String::from("In the frozen land of Nador"),
                2 => String::from("they were forced to eat Robin's minstrels"),
                3 => String::from("and there was much rejoicing"),
            };

            for (seq_num, msg) in expected_msgs_by_seq_num.iter() {
                assert!(self
                    .msg_store
                    .save_message_and_incr_next_sender_msg_seq_num(
                        *seq_num,
                        msg.clone().into_bytes()
                    )
                    .await
                    .is_ok());
            }

            assert_eq!(423, self.msg_store.next_sender_msg_seq_num().await);

            // When the messages are retrieved from the MessageStore
            let actual_msgs_result = self.msg_store.get_messages(1, 3).await;
            assert!(actual_msgs_result.is_ok());
            let actual_msgs = actual_msgs_result.unwrap();

            // Then the messages should be
            assert_eq!(actual_msgs.len(), 3);
            assert_eq!(
                expected_msgs_by_seq_num.get(&1).unwrap().as_bytes(),
                actual_msgs[0]
            );
            assert_eq!(
                expected_msgs_by_seq_num.get(&2).unwrap().as_bytes(),
                actual_msgs[1]
            );
            assert_eq!(
                expected_msgs_by_seq_num.get(&3).unwrap().as_bytes(),
                actual_msgs[2]
            );

            // When the store is refreshed from its backing store
            assert!(self.msg_store.refresh().await.is_ok());

            // And the messages are retrieved from the MessageStore
            let actual_msgs_result = self.msg_store.get_messages(1, 3).await;
            assert!(actual_msgs_result.is_ok());
            let actual_msgs = actual_msgs_result.unwrap();

            assert_eq!(423, self.msg_store.next_sender_msg_seq_num().await);

            // Then the messages should still be
            assert_eq!(actual_msgs.len(), 3);
            assert_eq!(
                expected_msgs_by_seq_num.get(&1).unwrap().as_bytes(),
                actual_msgs[0]
            );
            assert_eq!(
                expected_msgs_by_seq_num.get(&2).unwrap().as_bytes(),
                actual_msgs[1]
            );
            assert_eq!(
                expected_msgs_by_seq_num.get(&3).unwrap().as_bytes(),
                actual_msgs[2]
            );
        }

        pub async fn test_message_store_get_messages_empty_store(&mut self) {
            // When messages are retrieved from an empty store
            let actual_msgs_result = self.msg_store.get_messages(1, 2).await;
            assert!(actual_msgs_result.is_ok());
            let messages = actual_msgs_result.unwrap();

            // Then no messages should be returned
            assert!(
                messages.is_empty(),
                "Did not expect messages from empty store"
            );
        }

        pub async fn test_message_store_get_messages_various_ranges(&mut self) {
            // Given the following saved messages
            assert!(self
                .msg_store
                .save_message(1, "hello".as_bytes().to_vec())
                .await
                .is_ok());
            assert!(self
                .msg_store
                .save_message(2, "cruel".as_bytes().to_vec())
                .await
                .is_ok());
            assert!(self
                .msg_store
                .save_message(3, "world".as_bytes().to_vec())
                .await
                .is_ok());

            // When the following requests are made to the store
            struct TestCase {
                begin_seq_no: isize,
                end_seq_no: isize,
                expected_bytes: Vec<Vec<u8>>,
            }

            let tests = vec![
                TestCase {
                    begin_seq_no: 1,
                    end_seq_no: 1,
                    expected_bytes: vec!["hello".as_bytes().to_vec()],
                },
                TestCase {
                    begin_seq_no: 1,
                    end_seq_no: 2,
                    expected_bytes: vec!["hello".as_bytes().to_vec(), "cruel".as_bytes().to_vec()],
                },
                TestCase {
                    begin_seq_no: 1,
                    end_seq_no: 3,
                    expected_bytes: vec![
                        "hello".as_bytes().to_vec(),
                        "cruel".as_bytes().to_vec(),
                        "world".as_bytes().to_vec(),
                    ],
                },
                TestCase {
                    begin_seq_no: 1,
                    end_seq_no: 4,
                    expected_bytes: vec![
                        "hello".as_bytes().to_vec(),
                        "cruel".as_bytes().to_vec(),
                        "world".as_bytes().to_vec(),
                    ],
                },
                TestCase {
                    begin_seq_no: 2,
                    end_seq_no: 3,
                    expected_bytes: vec!["cruel".as_bytes().to_vec(), "world".as_bytes().to_vec()],
                },
                TestCase {
                    begin_seq_no: 3,
                    end_seq_no: 3,
                    expected_bytes: vec!["world".as_bytes().to_vec()],
                },
                TestCase {
                    begin_seq_no: 3,
                    end_seq_no: 4,
                    expected_bytes: vec!["world".as_bytes().to_vec()],
                },
                TestCase {
                    begin_seq_no: 4,
                    end_seq_no: 4,
                    expected_bytes: vec![],
                },
                TestCase {
                    begin_seq_no: 4,
                    end_seq_no: 10,
                    expected_bytes: vec![],
                },
            ];

            // Then the returned messages should be
            for test in tests.iter() {
                let actual_msgs_result = self
                    .msg_store
                    .get_messages(test.begin_seq_no, test.end_seq_no)
                    .await;
                assert!(actual_msgs_result.is_ok());
                let actual_msgs = actual_msgs_result.unwrap();
                assert_eq!(actual_msgs.len(), test.expected_bytes.len());
                for (i, expected_msg) in test.expected_bytes.iter().enumerate() {
                    assert_eq!(
                        String::from_utf8_lossy(expected_msg).to_string(),
                        String::from_utf8_lossy(&actual_msgs[i].clone()).to_string()
                    );
                }
            }
        }

        pub async fn test_message_store_creation_time(&mut self) {
            let t0 = Utc::now();
            assert!(self.msg_store.reset().await.is_ok());
            let t1 = Utc::now();
            assert!(self.msg_store.creation_time().await > t0);
            assert!(self.msg_store.creation_time().await < t1);
        }
    }

    // MemoryStoreTestSuite runs all tests in the MessageStoreTestSuite against the MemoryStore implementation.
    pub struct MemoryStoreTestSuite<S: MessageStoreTrait> {
        pub suite: MessageStoreTestSuite<S>,
    }

    async fn setup_test() -> MemoryStoreTestSuite<MessageStoreEnum> {
        let factory = MemoryStoreFactory::new();
        let store_result = factory.create(Arc::new(SessionID::default())).await;
        assert!(store_result.is_ok());
        let store = store_result.unwrap();
        let s = MemoryStoreTestSuite {
            suite: MessageStoreTestSuite { msg_store: store },
        };
        s
    }

    #[tokio::test]
    async fn test_memory_store_test_suite() {
        let mut s = setup_test().await;
        s.suite
            .test_message_store_set_next_msg_seq_num_refresh_incr_next_msg_seq_num()
            .await;
        let mut s = setup_test().await;
        s.suite.test_message_store_reset().await;
        let mut s = setup_test().await;
        s.suite.test_message_store_save_message_get_message().await;
        let mut s = setup_test().await;
        s.suite
            .test_message_store_save_message_and_increment_get_message()
            .await;
        let mut s = setup_test().await;
        s.suite.test_message_store_get_messages_empty_store().await;
        let mut s = setup_test().await;
        s.suite
            .test_message_store_get_messages_various_ranges()
            .await;
        let mut s = setup_test().await;
        s.suite.test_message_store_creation_time().await;
    }
}
