#[cfg(test)]
use crate::message_router::tests::MessageRouterTestSuite;
use crate::{
    errors::{unsupported_message_type, MessageRejectErrorResult},
    fix_string::FIXString,
    message::Message,
    msg_type::is_admin_message_type,
    registry::SESSIONS,
    session::session_id::SessionID,
    tag::{TAG_APPL_VER_ID, TAG_BEGIN_STRING, TAG_MSG_TYPE},
    BEGIN_STRING_FIX40, BEGIN_STRING_FIX41, BEGIN_STRING_FIX42, BEGIN_STRING_FIX43,
    BEGIN_STRING_FIX44, BEGIN_STRING_FIXT11,
};
use parking_lot::Mutex;
use std::{
    collections::{hash_map::DefaultHasher, HashMap},
    hash::{Hash, Hasher},
    sync::Arc,
};

#[derive(Eq, PartialEq, Hash)]
pub struct RouteKey {
    pub fix_version: String,
    pub msg_type: String,
}

impl RouteKey {
    pub fn get_hash(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        hasher.finish()
    }
}

// #![feature(async_await)]
// #![warn(rust_2018_idioms)]
// use std::sync::{Arc, Mutex};
// use std::error::Error;
// use tokio::{runtime::Runtime};

// #[derive(Clone)]
// struct OtherLib { }

// impl OtherLib {
//     pub fn do_something(&self, text1: String, text2: String) {
//         println!("doing something in other lib: {} + {}", text1, text2);
//     }
// }

// type Callback = Arc<Mutex<dyn 'static + FnMut(String, String) + Send + Sync>>;

// struct LibThreaded {
//     something_threaded: String,
//     callback: Callback,
// }

// impl LibThreaded {
//     pub fn new(callback: Option<Callback>) -> LibThreaded {
//         LibThreaded {
//             something_threaded: "I am in a thread: ".to_string(),
//             callback: callback.unwrap_or_else(|| Arc::new(Mutex::new(|_,_| {})))
//         }
//     }

//     async fn receiving(&mut self) {
//         println!("in receiving loop");
//             let c = &mut *self.callback.lock().unwrap();
//             (c)(self.something_threaded.clone(), "hello world".to_string());
//     }
// }

// struct Lib {
//     something: String,
//     callback: Callback,
// }

// impl Lib {
//     pub fn new() -> Lib {
//         Lib { something: "I am lib: ".to_string(), callback: Arc::new(Mutex::new(|_, _| {})) }
//     }

//     pub async fn set_callback(&mut self, callback: Option<impl 'static + FnMut(String, String) + Send + Sync>) {
//         println!("in lib2");
//         let callback = callback.map(|cb| Arc::new(Mutex::new(cb)) as Callback); //line 1
//         if let Some(cb) = &callback {  //line 2
//             self.callback = cb.clone();
//             let c = &mut *self.callback.lock().unwrap();
//             (c)(self.something.clone(), "hello world".to_string());
//         }
//         let mut t = LibThreaded::new(callback);

//         tokio::spawn(async move {
//             t.receiving().await;
//         });
//     }
// }

// fn main() -> Result<(), Box<dyn Error>> {
//     let ol = OtherLib {};

//     let callback = move |text1: String, text2: String| {
//             ol.do_something(text1, text2);
//     };

//     let rt = Runtime::new()?;
//     rt.block_on(async {
//         let mut lib = Lib::new();
//         lib.set_callback(Some(callback)).await;
//     });
//     rt.shutdown_on_idle();
//     Ok(())
// }

pub const APPL_VER_ID_FIX27: &str = "0";
pub const APPL_VER_ID_FIX30: &str = "1";
pub const APPL_VER_ID_FIX40: &str = "2";
pub const APPL_VER_ID_FIX41: &str = "3";
pub const APPL_VER_ID_FIX42: &str = "4";
pub const APPL_VER_ID_FIX43: &str = "5";
pub const APPL_VER_ID_FIX44: &str = "6";
pub const APPL_VER_ID_FIX50: &str = "7";
pub const APPL_VER_ID_FIX50_SP1: &str = "8";
pub const APPL_VER_ID_FIX50_SP2: &str = "9";

// A MessageRouter is a mutex for MessageRoutes.
#[derive(Default)]
pub struct MessageRouter
// <
//     #[cfg(not(test))] F: FnMut(&MessageRouter<F>, Arc<Mutex<Message>>, Arc<SessionID>) -> MessageRejectErrorResult,
//     #[cfg(test)] F: FnMut(
//         &MessageRouterTestSuite<F>,
//         Arc<Mutex<Message>>,
//         Arc<SessionID>,
//     ) -> MessageRejectErrorResult,
// >
{
    #[cfg(not(test))]
    pub routes: Arc<
        Mutex<
            HashMap<
                RouteKey,
                Box<
                    dyn FnMut(
                        &MessageRouter,
                        Arc<Mutex<Message>>,
                        Arc<SessionID>,
                    ) -> MessageRejectErrorResult,
                >,
            >,
        >,
    >,
    #[cfg(test)]
    pub routes: Arc<
        Mutex<
            HashMap<
                RouteKey,
                Box<
                    dyn FnMut(
                        Arc<Mutex<MessageRouterTestSuite>>,
                        Arc<Mutex<Message>>,
                        Arc<SessionID>,
                    ) -> MessageRejectErrorResult,
                >,
            >,
        >,
    >,
}

impl MessageRouter {
    // new returns an initialized MessageRouter instance.
    pub fn new() -> Self {
        Self {
            routes: Arc::new(Mutex::new(hashmap! {})),
        }
    }

    // add_route adds a route to the MessageRouter instance keyed to begin string and msg_type.
    #[cfg(not(test))]
    pub fn add_route(
        &self,
        begin_string: String,
        msg_type: String,
        router: Box<
            dyn FnMut(
                &MessageRouter,
                Arc<Mutex<Message>>,
                Arc<SessionID>,
            ) -> MessageRejectErrorResult,
        >,
    ) {
        let hash = RouteKey {
            fix_version: begin_string,
            msg_type,
        };
        let _ = self.routes.lock().insert(hash, router);
    }

    #[cfg(test)]
    pub fn add_route(
        &self,
        begin_string: String,
        msg_type: String,
        router: Box<
            dyn FnMut(
                Arc<Mutex<MessageRouterTestSuite>>,
                Arc<Mutex<Message>>,
                Arc<SessionID>,
            ) -> MessageRejectErrorResult,
        >,
    ) {
        let hash = RouteKey {
            fix_version: begin_string,
            msg_type,
        };
        let _ = self.routes.lock().insert(hash, router);
    }

    // route may be called from the from_app/from_admin callbacks. Messages that cannot be routed will be rejected with UNSUPPORTED_MESSAGE_TYPE.
    #[cfg(not(test))]
    pub async fn route(
        g: &MessageRouter,
        msg: Arc<Mutex<Message>>,
        session_id: Arc<SessionID>,
    ) -> MessageRejectErrorResult {
        let msg_clone = msg.clone();
        let lock = msg_clone.lock();
        let begin_bytes = lock.header.get_bytes(TAG_BEGIN_STRING)?;
        let msg_type_bytes = lock.header.get_bytes(TAG_MSG_TYPE)?;
        drop(lock);
        let begin_string = String::from_utf8_lossy(&begin_bytes).to_string();
        let msg_type_string = String::from_utf8_lossy(&msg_type_bytes).to_string();
        Self::try_route(g, begin_string, msg_type_string, msg, session_id).await
    }

    #[cfg(test)]
    pub async fn route(
        g: Arc<Mutex<MessageRouterTestSuite>>,
        msg: Arc<Mutex<Message>>,
        session_id: Arc<SessionID>,
    ) -> MessageRejectErrorResult {
        let msg_clone = msg.clone();
        let lock = msg_clone.lock();
        let begin_bytes = lock.header.get_bytes(TAG_BEGIN_STRING)?;
        let msg_type_bytes = lock.header.get_bytes(TAG_MSG_TYPE)?;
        drop(lock);
        let begin_string = String::from_utf8_lossy(&begin_bytes).to_string();
        let msg_type_string = String::from_utf8_lossy(&msg_type_bytes).to_string();
        Self::try_route(g, begin_string, msg_type_string, msg, session_id).await
    }

    #[cfg(not(test))]
    async fn try_route(
        g: &MessageRouter,
        begin_string: String,
        msg_type: String,
        msg: Arc<Mutex<Message>>,
        session_id: Arc<SessionID>,
    ) -> MessageRejectErrorResult {
        let is_admin_msg = is_admin_message_type(msg_type.as_bytes());
        let fix_version =
            Self::get_fix_version(begin_string, is_admin_msg, msg.clone(), session_id.clone())
                .await;

        if let Some(ref mut route) = g.routes.lock().get_mut(&RouteKey {
            fix_version,
            msg_type: msg_type.to_string(),
        }) {
            return route(g, msg, session_id);
        };

        if is_admin_msg || msg_type == "j" {
            return Ok(());
        }

        Err(unsupported_message_type())
    }

    #[cfg(test)]
    async fn try_route(
        g: Arc<Mutex<MessageRouterTestSuite>>,
        begin_string: String,
        msg_type: String,
        msg: Arc<Mutex<Message>>,
        session_id: Arc<SessionID>,
    ) -> MessageRejectErrorResult {
        let is_admin_msg = is_admin_message_type(msg_type.as_bytes());
        let fix_version =
            Self::get_fix_version(begin_string, is_admin_msg, msg.clone(), session_id.clone())
                .await;
        let g_clone = g.clone();
        if let Some(ref mut route) = g.lock().mr.routes.lock().get_mut(&RouteKey {
            fix_version,
            msg_type: msg_type.to_string(),
        }) {
            return route(g_clone, msg, session_id.clone());
        }

        if is_admin_msg || msg_type == "j" {
            return Ok(());
        }

        Err(unsupported_message_type())
    }

    async fn get_fix_version(
        begin_string: String,
        is_admin_msg: bool,
        msg: Arc<Mutex<Message>>,
        session_id: Arc<SessionID>,
    ) -> String {
        let mut fix_version = begin_string;

        if fix_version == BEGIN_STRING_FIXT11 && !is_admin_msg {
            let mut appl_ver_id = FIXString::new();
            if let Err(_) = msg
                .lock()
                .header
                .get_field(TAG_APPL_VER_ID, &mut appl_ver_id)
            {
                let lock = (*SESSIONS).lock().await;
                let session = lock.get(&session_id).unwrap(); // TODO: check if we need to handle this
                appl_ver_id = session
                    .clone()
                    .lock()
                    .await
                    .target_default_application_version_id();
            }

            fix_version = match appl_ver_id.as_str() {
                APPL_VER_ID_FIX40 => BEGIN_STRING_FIX40.to_string(),
                APPL_VER_ID_FIX41 => BEGIN_STRING_FIX41.to_string(),
                APPL_VER_ID_FIX42 => BEGIN_STRING_FIX42.to_string(),
                APPL_VER_ID_FIX43 => BEGIN_STRING_FIX43.to_string(),
                APPL_VER_ID_FIX44 => BEGIN_STRING_FIX44.to_string(),
                &_ => appl_ver_id,
            };
        }

        fix_version
    }
}

#[cfg(test)]
mod tests {
    // use crate::higher_order_closure;
    use crate::{
        errors::{
            new_business_message_reject_error, MessageRejectError, MessageRejectErrorEnum,
            MessageRejectErrorResult, RejectLogon,
        },
        fix_string::FIXString,
        message::Message,
        message_router::{MessageRouter, APPL_VER_ID_FIX50, APPL_VER_ID_FIX50_SP1},
        registry::{register_session, SESSIONS},
        session::{session_id::SessionID, Session},
        tag::{TAG_BEGIN_STRING, TAG_SENDER_COMP_ID, TAG_TARGET_COMP_ID},
        BEGIN_STRING_FIX42, BEGIN_STRING_FIXT11,
    };
    use parking_lot::Mutex as StdMutex;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    pub struct MessageRouterTestSuite {
        pub mr: MessageRouter,
        msg: Message,
        session_id: SessionID,
        return_reject: Option<MessageRejectErrorEnum>,
        routed_by: String,
        routed_session_id: SessionID,
        routed_message: Message,
        begin_string: Arc<String>,
    }

    impl MessageRouterTestSuite {
        fn given_the_route(&self, begin_string: Arc<String>, msg_type: String) {
            let msg_clone = msg_type.clone();
            let begin_clone = begin_string.to_string();
            let add_route = move |payload: Arc<StdMutex<MessageRouterTestSuite>>,
                                  msg: Arc<StdMutex<Message>>,
                                  session_id: Arc<SessionID>|
                  -> MessageRejectErrorResult {
                let mut lock = payload.lock();
                lock.routed_by = format!("{}:{}", begin_clone, msg_type);
                lock.routed_session_id = (*session_id).clone();
                lock.routed_message = msg.lock().clone();
                let reject_result = lock.return_reject.clone();
                println!("----------------------------------1");
                match reject_result {
                    Some(err) => return Err(err),
                    None => return Ok(()),
                }
            };

            self.mr
                .add_route(begin_string.to_string(), msg_clone, Box::new(add_route));
        }

        fn given_the_message(&mut self, msg_bytes: &[u8]) {
            let parse_result = self.msg.parse_message(msg_bytes);
            assert!(parse_result.is_ok());

            let mut begin_string = FIXString::new();
            assert!(self
                .msg
                .header
                .get_field(TAG_BEGIN_STRING, &mut begin_string)
                .is_ok());
            let mut sender_comp_id = FIXString::new();
            assert!(self
                .msg
                .header
                .get_field(TAG_SENDER_COMP_ID, &mut sender_comp_id)
                .is_ok());
            let mut target_comp_id = FIXString::new();
            assert!(self
                .msg
                .header
                .get_field(TAG_TARGET_COMP_ID, &mut target_comp_id)
                .is_ok());
            self.session_id = SessionID {
                begin_string,
                sender_comp_id,
                target_comp_id,
                ..Default::default()
            };
        }

        async fn given_target_default_appl_ver_id_for_session(
            &self,
            default_appl_ver_id: &str,
            session_id: &Arc<SessionID>,
        ) {
            let s = Session {
                session_id: session_id.clone(),
                target_default_appl_ver_id: default_appl_ver_id.to_string(),
                ..Default::default()
            };

            assert!(register_session(Arc::new(Mutex::new(s))).await.is_ok())
        }

        fn given_afix42_new_order_single(&mut self) {
            self.given_the_message("8=FIX.4.29=8735=D49=TW34=356=ISLD52=20160421-14:43:5040=160=20160421-14:43:5054=121=311=id10=235".as_bytes());
        }

        fn given_afixt_logon_message(&mut self) {
            self.given_the_message(
                "8=FIXT.1.19=6335=A34=149=TW52=20160420-21:21:4956=ISLD98=0108=21137=810=105"
                    .as_bytes(),
            );
        }

        fn anticipate_reject(&mut self, rej: MessageRejectErrorEnum) {
            self.return_reject = Some(rej);
        }

        fn verify_message_not_routed(&self) {
            assert_eq!("", &*self.routed_by, "Message should not be routed");
        }

        fn verify_message_routed_by(&self, begin_string: &str, msg_type: &str) {
            assert_ne!("", &*self.routed_by, "Message expected to be routed");

            assert_eq!(format!("{}:{}", begin_string, msg_type), &*self.routed_by);
            assert_eq!(self.session_id, self.routed_session_id);
            assert_eq!(self.msg.to_string(), &*self.routed_message.to_string());
        }

        fn reset_router(&mut self) {
            self.mr = MessageRouter::new();
            self.routed_by = String::new();
            self.routed_session_id = SessionID::default();
            self.routed_message = Message::new();
            self.return_reject = None;
            self.begin_string = Arc::new(String::new());
        }

        async fn setup_test() -> MessageRouterTestSuite {
            let suite = MessageRouterTestSuite {
                mr: MessageRouter::new(),
                msg: Message::new(),
                session_id: SessionID::default(),
                routed_by: String::new(),
                routed_session_id: SessionID::default(),
                routed_message: Message::new(),
                return_reject: None,
                begin_string: Arc::new(String::new()),
            };
            let mut lock = (*SESSIONS).lock().await;
            lock.clear();
            suite
        }
    }

    #[tokio::test]
    async fn test_no_route() {
        let mut suite = MessageRouterTestSuite::setup_test().await;
        let msg = "8=FIX.4.39=8735=D49=TW34=356=ISLD52=20160421-14:43:5040=160=20160421-14:43:5054=121=311=id10=235".as_bytes();
        suite.given_the_message(msg);
        let suite_msg = Arc::new(StdMutex::new(suite.msg.clone()));
        let session_id = Arc::new(suite.session_id.clone());
        let suite_mutex = Arc::new(StdMutex::new(suite));
        let suite_mutex_clone = suite_mutex.clone();

        let rej = MessageRouter::route(suite_mutex, suite_msg, session_id).await;
        let lock = suite_mutex_clone.lock();
        lock.verify_message_not_routed();
        assert_eq!(
            new_business_message_reject_error("Unsupported Message Type".to_string(), 3, None),
            rej.unwrap_err(),
        );
    }

    #[tokio::test]
    async fn test_no_route_whitelisted_message_types() {
        let tests = vec!["0", "A", "1", "2", "3", "4", "5", "j"];

        for test in tests {
            let mut suite = MessageRouterTestSuite::setup_test().await;

            let msg = format!("8=FIX.4.39=8735={}49=TW34=356=ISLD52=20160421-14:43:5040=160=20160421-14:43:5054=121=311=id10=235", test);
            suite.given_the_message(msg.as_bytes());

            let suite_msg = Arc::new(StdMutex::new(suite.msg.clone()));
            let session_id = Arc::new(suite.session_id.clone());
            let suite_mutex = Arc::new(StdMutex::new(suite));
            let suite_mutex_clone = suite_mutex.clone();

            let rej = MessageRouter::route(suite_mutex, suite_msg, session_id).await;
            let lock = suite_mutex_clone.lock();
            lock.verify_message_not_routed();
            assert!(
                rej.is_ok(),
                "Message type '{}' should not be rejected by the MessageRouter",
                test
            );
        }
    }

    #[tokio::test]
    async fn test_simple_route() {
        let mut suite = MessageRouterTestSuite::setup_test().await;
        suite.given_the_route(
            Arc::new(String::from(BEGIN_STRING_FIX42)),
            String::from("D"),
        );
        suite.given_the_route(
            Arc::new(String::from(BEGIN_STRING_FIXT11)),
            String::from("A"),
        );
        suite.given_afix42_new_order_single();

        let suite_msg = Arc::new(StdMutex::new(suite.msg.clone()));
        let session_id = Arc::new(suite.session_id.clone());
        let suite_mutex = Arc::new(StdMutex::new(suite));
        let suite_mutex_clone = suite_mutex.clone();

        let rej = MessageRouter::route(suite_mutex, suite_msg, session_id).await;
        let lock = suite_mutex_clone.lock();
        lock.verify_message_routed_by(BEGIN_STRING_FIX42, "D");
        assert!(rej.is_ok());
    }

    // // #[tokio::test]
    // // async fn test_simple_route_with_reject() {
    // //     let mut suite = MessageRouterTestSuite::setup_test().await;
    // //     suite.given_the_route(BEGIN_STRING_FIX42, "D").await;
    // //     suite.given_the_route(BEGIN_STRING_FIXT11, "A").await;
    // //     suite.anticipate_reject(MessageRejectError::new("some error".to_string(), 5, None));

    // //     suite.given_afix42_new_order_single();
    // //     let rej = suite
    // //         .mr
    // //         .route(suite.msg.clone(), suite.session_id.clone())
    // //         .await;
    // //     suite.verify_message_routed_by(BEGIN_STRING_FIX42, "D");
    // //     assert_eq!(suite.return_reject.unwrap(), rej.unwrap_err());
    // // }

    // // #[tokio::test]
    // // async fn test_route_fixt_admin_message() {
    // //     let mut suite = MessageRouterTestSuite::setup_test().await;
    // //     suite.given_the_route(BEGIN_STRING_FIX42, "D").await;
    // //     suite.given_the_route(BEGIN_STRING_FIXT11, "A").await;
    // //     suite.given_afixt_logon_message();

    // //     let rej = suite
    // //         .mr
    // //         .route(suite.msg.clone(), suite.session_id.clone())
    // //         .await;
    // //     suite.verify_message_routed_by(BEGIN_STRING_FIXT11, "A");
    // //     assert!(rej.is_ok());
    // // }

    // // #[tokio::test]
    // // async fn test_route_fixt50_app_with_appl_ver_id() {
    // //     let mut suite = MessageRouterTestSuite::setup_test().await;
    // //     suite.given_the_route(BEGIN_STRING_FIX42, "D").await;
    // //     suite.given_the_route(APPL_VER_ID_FIX50, "D").await;
    // //     suite.given_the_route(APPL_VER_ID_FIX50_SP1, "D").await;

    // //     let msg = "8=FIXT.1.19=8935=D49=TW34=356=ISLD52=20160424-16:48:261128=740=160=20160424-16:48:2611=id21=310=120".as_bytes();
    // //     suite.given_the_message(msg);
    // //     let rej = suite
    // //         .mr
    // //         .route(suite.msg.clone(), suite.session_id.clone())
    // //         .await;
    // //     suite.verify_message_routed_by(APPL_VER_ID_FIX50, "D");
    // //     assert!(rej.is_ok());
    // // }

    // // #[tokio::test]
    // // async fn test_route_fixt_app_with_appl_ver_id() {
    // //     let mut suite = MessageRouterTestSuite::setup_test().await;
    // //     suite.given_the_route(BEGIN_STRING_FIX42, "D").await;
    // //     suite.given_the_route(APPL_VER_ID_FIX50, "D").await;
    // //     suite.given_the_route(APPL_VER_ID_FIX50_SP1, "D").await;

    // //     let msg = "8=FIXT.1.19=8935=D49=TW34=356=ISLD52=20160424-16:48:261128=840=160=20160424-16:48:2611=id21=310=120".as_bytes();
    // //     suite.given_the_message(msg);

    // //     let rej = suite
    // //         .mr
    // //         .route(suite.msg.clone(), suite.session_id.clone())
    // //         .await;
    // //     suite.verify_message_routed_by(APPL_VER_ID_FIX50_SP1, "D");
    // //     assert!(rej.is_ok());
    // // }

    // // #[tokio::test]
    // // async fn test_route_fixt_app_with_default_appl_ver_id() {
    // //     let mut suite = MessageRouterTestSuite::setup_test().await;
    // //     suite.given_the_route(BEGIN_STRING_FIX42, "D").await;
    // //     suite.given_the_route(APPL_VER_ID_FIX50, "D").await;
    // //     suite.given_the_route(APPL_VER_ID_FIX50_SP1, "D").await;
    // //     suite
    // //         .given_target_default_appl_ver_id_for_session(
    // //             "8",
    // //             &Arc::new(SessionID {
    // //                 begin_string: BEGIN_STRING_FIXT11.to_string(),
    // //                 sender_comp_id: "ISLD".to_string(),
    // //                 target_comp_id: "TW".to_string(),
    // //                 ..Default::default()
    // //             }),
    // //         )
    // //         .await;

    // //     let msg = "8=FIXT.1.19=8235=D49=TW34=356=ISLD52=20160424-16:48:2640=160=20160424-16:48:2611=id21=310=120".as_bytes();
    // //     suite.given_the_message(msg);
    // //     let rej = suite
    // //         .mr
    // //         .route(suite.msg.clone(), suite.session_id.clone())
    // //         .await;
    // //     suite.verify_message_routed_by(APPL_VER_ID_FIX50_SP1, "D");
    // //     assert!(rej.is_ok());
    // }
}
