use crate::{
    errors::FixerError,
    fix_string::FIXString,
    message::Message,
    session::{session_id::SessionID, Session},
    tag::{TAG_BEGIN_STRING, TAG_SENDER_COMP_ID, TAG_TARGET_COMP_ID},
};
use dashmap::DashMap;
use once_cell::sync::Lazy;
use simple_error::{SimpleError, SimpleResult};
use std::sync::Arc;
pub static SESSIONS: Lazy<DashMap<Arc<SessionID>, Session>> = Lazy::new(|| DashMap::new());

pub static ERR_DUPLICATE_SESSION_ID: Lazy<SimpleError> =
    Lazy::new(|| simple_error!("Duplicate SessionID"));
pub static ERR_UNKNOWN_SESSION: Lazy<SimpleError> = Lazy::new(|| simple_error!("Unknown session"));

// Messagable is a Message or something that can be converted to a Message.
pub trait Messageable {
    fn to_message(&self) -> &Message;
}

// send determines the session to send Messagable using header fields begin_string, target_comp_id, sender_comp_id.
pub async fn send(message: &dyn Messageable) -> Result<(), FixerError> {
    let msg = message.to_message();
    let mut begin_string = FIXString::new();
    msg.header.get_field(TAG_BEGIN_STRING, &mut begin_string)?;

    let mut target_comp_id = FIXString::new();
    msg.header
        .get_field(TAG_TARGET_COMP_ID, &mut target_comp_id)?;

    let mut sender_comp_id = FIXString::new();
    msg.header
        .get_field(TAG_SENDER_COMP_ID, &mut sender_comp_id)?;

    let session_id = SessionID {
        begin_string,
        target_comp_id,
        sender_comp_id,
        ..Default::default()
    };

    send_to_target(message, &Arc::new(session_id)).await
}

// send_to_target sends a message based on the session_id. Convenient for use in from_app since it provides a session ID for incoming messages.
pub async fn send_to_target(
    message: &dyn Messageable,
    session_id: &Arc<SessionID>,
) -> Result<(), FixerError> {
    let msg = message.to_message();
    let mut session = (*SESSIONS)
        .get_mut(session_id)
        .ok_or(ERR_UNKNOWN_SESSION.clone())?;

    session.queue_for_send(msg).await
}

// unregister_session removes a session from the set of known sessions.
pub fn unregister_session(session_id: Arc<SessionID>) -> SimpleResult<()> {
    if (*SESSIONS).contains_key(&session_id) {
        (*SESSIONS).remove(&session_id);
        return Ok(());
    }

    Err(ERR_UNKNOWN_SESSION.clone())
}

pub fn register_session(s: Session) -> SimpleResult<()> {
    if (*SESSIONS).contains_key(&s.session_id) {
        return Err(ERR_DUPLICATE_SESSION_ID.clone());
    }

    (*SESSIONS).insert(s.session_id.clone(), s);
    Ok(())
}
