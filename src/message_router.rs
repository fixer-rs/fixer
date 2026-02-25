#[cfg(test)]
use crate::message_router::tests::MessageRouterTestSuite;
use crate::{
    BEGIN_STRING_FIX40, BEGIN_STRING_FIX41, BEGIN_STRING_FIX42, BEGIN_STRING_FIX43,
    BEGIN_STRING_FIX44, BEGIN_STRING_FIXT11,
    errors::{MessageRejectErrorResult, unsupported_message_type},
    fix_string::FIXString,
    message::Message,
    msg_type::is_admin_message_type,
    registry::SESSIONS,
    session::session_id::SessionID,
    tag::{TAG_APPL_VER_ID, TAG_BEGIN_STRING, TAG_MSG_TYPE},
};
use std::{collections::HashMap, sync::Arc};

#[derive(Eq, PartialEq, Hash)]
pub struct RouteKey {
    pub fix_version: String,
    pub msg_type: String,
}

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

#[cfg(not(test))]
type RouteCallback = Box<
    dyn FnMut(&mut MessageRouter, &Message, Arc<SessionID>) -> MessageRejectErrorResult,
>;

#[cfg(test)]
type RouteCallback = Box<
    dyn FnMut(&mut MessageRouterTestSuite, &Message, Arc<SessionID>) -> MessageRejectErrorResult,
>;

// A MessageRouter routes FIX messages to registered callbacks.
#[derive(Default)]
pub struct MessageRouter {
    pub routes: HashMap<RouteKey, RouteCallback>,
}

impl MessageRouter {
    // new returns an initialized MessageRouter instance.
    pub fn new() -> Self {
        Self {
            routes: HashMap::new(),
        }
    }

    // add_route adds a route to the MessageRouter instance keyed to begin string and msg_type.
    pub fn add_route(
        &mut self,
        begin_string: String,
        msg_type: String,
        router: RouteCallback,
    ) {
        let hash = RouteKey {
            fix_version: begin_string,
            msg_type,
        };
        self.routes.insert(hash, router);
    }

    // route may be called from the from_app/from_admin callbacks. Messages that cannot be routed will be rejected with UNSUPPORTED_MESSAGE_TYPE.
    #[cfg(not(test))]
    pub async fn route(
        g: &mut MessageRouter,
        msg: &Message,
        session_id: Arc<SessionID>,
    ) -> MessageRejectErrorResult {
        let begin_bytes = msg.header.get_bytes(TAG_BEGIN_STRING)?;
        let msg_type_bytes = msg.header.get_bytes(TAG_MSG_TYPE)?;
        let begin_string = String::from_utf8_lossy(&begin_bytes).to_string();
        let msg_type_string = String::from_utf8_lossy(&msg_type_bytes).to_string();
        Self::try_route(g, begin_string, msg_type_string, msg, session_id).await
    }

    #[cfg(test)]
    pub async fn route(
        g: &mut MessageRouterTestSuite,
        msg: &Message,
        session_id: Arc<SessionID>,
    ) -> MessageRejectErrorResult {
        let begin_bytes = msg.header.get_bytes(TAG_BEGIN_STRING)?;
        let msg_type_bytes = msg.header.get_bytes(TAG_MSG_TYPE)?;
        let begin_string = String::from_utf8_lossy(&begin_bytes).to_string();
        let msg_type_string = String::from_utf8_lossy(&msg_type_bytes).to_string();
        Self::try_route(g, begin_string, msg_type_string, msg, session_id).await
    }

    #[cfg(not(test))]
    async fn try_route(
        g: &mut MessageRouter,
        begin_string: String,
        msg_type: String,
        msg: &Message,
        session_id: Arc<SessionID>,
    ) -> MessageRejectErrorResult {
        let is_admin_msg = is_admin_message_type(msg_type.as_bytes());
        let fix_version =
            Self::get_fix_version(begin_string, is_admin_msg, msg, session_id.clone())
                .await;
        let key = RouteKey {
            fix_version: fix_version.clone(),
            msg_type: msg_type.clone(),
        };

        if let Some(mut route) = g.routes.remove(&key) {
            let res = route(g, msg, session_id.clone());
            g.routes.insert(key, route);
            res
        } else {
            if is_admin_msg || msg_type == "j" {
                return Ok(());
            }

            Err(unsupported_message_type())
        }
    }

    #[cfg(test)]
    async fn try_route(
        g: &mut MessageRouterTestSuite,
        begin_string: String,
        msg_type: String,
        msg: &Message,
        session_id: Arc<SessionID>,
    ) -> MessageRejectErrorResult {
        let is_admin_msg = is_admin_message_type(msg_type.as_bytes());
        let fix_version =
            Self::get_fix_version(begin_string, is_admin_msg, msg, session_id.clone())
                .await;
        let key = RouteKey {
            fix_version: fix_version.clone(),
            msg_type: msg_type.clone(),
        };

        if let Some(mut route) = g.mr.routes.remove(&key) {
            let res = route(g, msg, session_id.clone());
            g.mr.routes.insert(key, route);
            res
        } else {
            if is_admin_msg || msg_type == "j" {
                return Ok(());
            }

            Err(unsupported_message_type())
        }
    }

    #[allow(clippy::unused_async)]
    async fn get_fix_version(
        begin_string: String,
        is_admin_msg: bool,
        msg: &Message,
        session_id: Arc<SessionID>,
    ) -> String {
        let mut fix_version = begin_string;

        if fix_version == BEGIN_STRING_FIXT11 && !is_admin_msg {
            let mut appl_ver_id = FIXString::new();
            if msg
                .header
                .get_field(TAG_APPL_VER_ID, &mut appl_ver_id)
                .is_err()
            {
                if let Some(reg) = (*SESSIONS).get(&session_id) {
                    appl_ver_id.clone_from(&reg.target_default_appl_ver_id.lock().unwrap());
                }
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
#[allow(clippy::items_after_statements, clippy::needless_pass_by_value)]
mod tests {
    use crate::{
        BEGIN_STRING_FIX42, BEGIN_STRING_FIXT11,
        errors::{
            MessageRejectError, MessageRejectErrorEnum, MessageRejectErrorResult,
            new_business_message_reject_error,
        },
        fix_string::FIXString,
        message::Message,
        message_router::{APPL_VER_ID_FIX50, APPL_VER_ID_FIX50_SP1, MessageRouter},
        registry::{SESSIONS, SessionRegistration, register_session},
        session::session_id::SessionID,
        tag::{TAG_BEGIN_STRING, TAG_SENDER_COMP_ID, TAG_TARGET_COMP_ID},
    };
    use serial_test::serial;
    use std::sync::Arc;

    pub struct MessageRouterTestSuite {
        pub mr: MessageRouter,
        msg: Message,
        session_id: SessionID,
        return_reject: Option<MessageRejectErrorEnum>,
        routed_by: String,
        routed_session_id: SessionID,
        routed_message: Message,
    }

    impl MessageRouterTestSuite {
        fn given_the_route(&mut self, begin_string: String, msg_type: String) {
            let msg_clone = msg_type.clone();
            let begin_clone = begin_string.clone();

            let add_route = move |payload: &mut MessageRouterTestSuite,
                                  msg: &Message,
                                  session_id: Arc<SessionID>|
                  -> MessageRejectErrorResult {
                payload.routed_by = format!("{begin_clone}:{msg_type}");
                payload.routed_session_id = (*session_id).clone();
                payload.routed_message = msg.clone();
                let reject_result = payload.return_reject.clone();

                match reject_result {
                    Some(err) => Err(err),
                    None => Ok(()),
                }
            };

            self.mr
                .add_route(begin_string.clone(), msg_clone, Box::new(add_route));
        }

        fn given_the_message(&mut self, msg_bytes: &[u8]) {
            let parse_result = self.msg.parse_message(msg_bytes);
            assert!(parse_result.is_ok());

            let mut begin_string = FIXString::new();
            assert!(
                self.msg
                    .header
                    .get_field(TAG_BEGIN_STRING, &mut begin_string)
                    .is_ok()
            );
            let mut sender_comp_id = FIXString::new();
            assert!(
                self.msg
                    .header
                    .get_field(TAG_SENDER_COMP_ID, &mut sender_comp_id)
                    .is_ok()
            );
            let mut target_comp_id = FIXString::new();
            assert!(
                self.msg
                    .header
                    .get_field(TAG_TARGET_COMP_ID, &mut target_comp_id)
                    .is_ok()
            );
            let si = SessionID {
                begin_string,
                sender_comp_id: target_comp_id,
                target_comp_id: sender_comp_id,
                ..Default::default()
            };
            self.session_id = si;
        }

        #[allow(clippy::unused_async)]
        async fn given_target_default_appl_ver_id_for_session(
            &self,
            default_appl_ver_id: &str,
            session_id: &Arc<SessionID>,
        ) {
            let target_default_appl_ver_id =
                Arc::new(std::sync::Mutex::new(default_appl_ver_id.to_string()));
            let (admin_tx, _admin_rx) = tokio::sync::mpsc::unbounded_channel();
            let registration = SessionRegistration {
                admin_tx,
                target_default_appl_ver_id,
            };

            assert!(register_session(session_id.clone(), registration).is_ok());
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

            assert_eq!(format!("{begin_string}:{msg_type}"), &*self.routed_by);
            assert_eq!(self.session_id, self.routed_session_id);
            assert_eq!(self.msg.to_string(), &*self.routed_message.to_string());
        }

        #[allow(clippy::unused_async)]
        async fn setup_test() -> MessageRouterTestSuite {
            let suite = MessageRouterTestSuite {
                mr: MessageRouter::new(),
                msg: Message::new(),
                session_id: SessionID::default(),
                routed_by: String::new(),
                routed_session_id: SessionID::default(),
                routed_message: Message::new(),
                return_reject: None,
            };
            (*SESSIONS).clear();
            suite
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_no_route() {
        let mut suite = MessageRouterTestSuite::setup_test().await;
        let msg = "8=FIX.4.39=8735=D49=TW34=356=ISLD52=20160421-14:43:5040=160=20160421-14:43:5054=121=311=id10=235".as_bytes();
        suite.given_the_message(msg);
        let suite_msg = suite.msg.clone();
        let session_id = Arc::new(suite.session_id.clone());

        let rej = MessageRouter::route(&mut suite, &suite_msg, session_id).await;
        suite.verify_message_not_routed();
        assert_eq!(
            new_business_message_reject_error("Unsupported Message Type".to_string(), 3, None),
            rej.unwrap_err(),
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_no_route_whitelisted_message_types() {
        let tests = vec!["0", "A", "1", "2", "3", "4", "5", "j"];

        for test in tests {
            let mut suite = MessageRouterTestSuite::setup_test().await;

            let msg = format!(
                "8=FIX.4.39=8735={test}49=TW34=356=ISLD52=20160421-14:43:5040=160=20160421-14:43:5054=121=311=id10=235"
            );
            suite.given_the_message(msg.as_bytes());

            let suite_msg = suite.msg.clone();
            let session_id = Arc::new(suite.session_id.clone());

            let rej = MessageRouter::route(&mut suite, &suite_msg, session_id).await;
            suite.verify_message_not_routed();
            assert!(
                rej.is_ok(),
                "Message type '{test}' should not be rejected by the MessageRouter"
            );
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_simple_route() {
        let mut suite = MessageRouterTestSuite::setup_test().await;
        suite.given_the_route(String::from(BEGIN_STRING_FIX42), String::from("D"));
        suite.given_the_route(String::from(BEGIN_STRING_FIXT11), String::from("A"));
        suite.given_afix42_new_order_single();

        let suite_msg = suite.msg.clone();
        let session_id = Arc::new(suite.session_id.clone());
        let rej = MessageRouter::route(&mut suite, &suite_msg, session_id).await;

        suite.verify_message_routed_by(BEGIN_STRING_FIX42, "D");
        assert!(rej.is_ok());
    }

    #[tokio::test]
    #[serial]
    async fn test_simple_route_with_reject() {
        let mut suite = MessageRouterTestSuite::setup_test().await;
        suite.given_the_route(String::from(BEGIN_STRING_FIX42), String::from("D"));
        suite.given_the_route(String::from(BEGIN_STRING_FIXT11), String::from("A"));
        suite.anticipate_reject(MessageRejectError::new("some error".to_string(), 5, None));
        suite.given_afix42_new_order_single();

        let suite_msg = suite.msg.clone();
        let session_id = Arc::new(suite.session_id.clone());
        let rej = MessageRouter::route(&mut suite, &suite_msg, session_id).await;
        suite.verify_message_routed_by(BEGIN_STRING_FIX42, "D");
        assert_eq!(suite.return_reject.unwrap(), rej.unwrap_err());
    }

    #[tokio::test]
    #[serial]
    async fn test_route_fixt_admin_message() {
        let mut suite = MessageRouterTestSuite::setup_test().await;
        suite.given_the_route(String::from(BEGIN_STRING_FIX42), String::from("D"));
        suite.given_the_route(String::from(BEGIN_STRING_FIXT11), String::from("A"));
        suite.given_afixt_logon_message();

        let suite_msg = suite.msg.clone();
        let session_id = Arc::new(suite.session_id.clone());
        let rej = MessageRouter::route(&mut suite, &suite_msg, session_id).await;
        suite.verify_message_routed_by(BEGIN_STRING_FIXT11, "A");
        assert!(rej.is_ok());
    }

    #[tokio::test]
    #[serial]
    async fn test_route_fixt50_app_with_appl_ver_id() {
        let mut suite = MessageRouterTestSuite::setup_test().await;
        suite.given_the_route(String::from(BEGIN_STRING_FIX42), String::from("D"));
        suite.given_the_route(String::from(APPL_VER_ID_FIX50), String::from("D"));
        suite.given_the_route(String::from(APPL_VER_ID_FIX50_SP1), String::from("D"));

        let msg = "8=FIXT.1.19=8935=D49=TW34=356=ISLD52=20160424-16:48:261128=740=160=20160424-16:48:2611=id21=310=120".as_bytes();
        suite.given_the_message(msg);
        let suite_msg = suite.msg.clone();
        let session_id = Arc::new(suite.session_id.clone());
        let rej = MessageRouter::route(&mut suite, &suite_msg, session_id).await;
        suite.verify_message_routed_by(APPL_VER_ID_FIX50, "D");
        assert!(rej.is_ok());
    }

    #[tokio::test]
    #[serial]
    async fn test_route_fixt_app_with_appl_ver_id() {
        let mut suite = MessageRouterTestSuite::setup_test().await;
        suite.given_the_route(String::from(BEGIN_STRING_FIX42), String::from("D"));
        suite.given_the_route(String::from(APPL_VER_ID_FIX50), String::from("D"));
        suite.given_the_route(String::from(APPL_VER_ID_FIX50_SP1), String::from("D"));

        let msg = "8=FIXT.1.19=8935=D49=TW34=356=ISLD52=20160424-16:48:261128=840=160=20160424-16:48:2611=id21=310=120".as_bytes();
        suite.given_the_message(msg);

        let suite_msg = suite.msg.clone();
        let session_id = Arc::new(suite.session_id.clone());
        let rej = MessageRouter::route(&mut suite, &suite_msg, session_id).await;
        suite.verify_message_routed_by(APPL_VER_ID_FIX50_SP1, "D");
        assert!(rej.is_ok());
    }

    #[tokio::test]
    #[serial]
    async fn test_route_fixt_app_with_default_appl_ver_id() {
        let mut suite = MessageRouterTestSuite::setup_test().await;
        suite.given_the_route(String::from(BEGIN_STRING_FIX42), String::from("D"));
        suite.given_the_route(String::from(APPL_VER_ID_FIX50), String::from("D"));
        suite.given_the_route(String::from(APPL_VER_ID_FIX50_SP1), String::from("D"));

        let session_id = Arc::new(SessionID {
            begin_string: BEGIN_STRING_FIXT11.to_string(),
            sender_comp_id: "ISLD".to_string(),
            target_comp_id: "TW".to_string(),
            ..Default::default()
        });
        suite
            .given_target_default_appl_ver_id_for_session("8", &session_id)
            .await;

        let msg = "8=FIXT.1.19=8235=D49=TW34=356=ISLD52=20160424-16:48:2640=160=20160424-16:48:2611=id21=310=120".as_bytes();
        suite.given_the_message(msg);

        let suite_msg = suite.msg.clone();
        let session_id = Arc::new(suite.session_id.clone());

        let rej = MessageRouter::route(&mut suite, &suite_msg, session_id).await;
        suite.verify_message_routed_by(APPL_VER_ID_FIX50_SP1, "D");
        assert!(rej.is_ok());
    }
}
