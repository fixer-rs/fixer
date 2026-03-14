use crate::{
    errors::FixerError,
    fix_string::FIXString,
    message::Message,
    session::{AdminEnum, QueueForSend, session_id::SessionID},
    tag::{TAG_BEGIN_STRING, TAG_SENDER_COMP_ID, TAG_TARGET_COMP_ID},
};
use dashmap::DashMap;
use simple_error::{SimpleError, SimpleResult};
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::Mutex as StdMutex;
use tokio::sync::mpsc::UnboundedSender;

/// `SessionRegistration` holds the channel handles needed to communicate with a
/// running session. This replaces the previous `Arc<Mutex<Session>>` — callers
/// send commands through channels instead of locking the session directly.
#[derive(Clone)]
pub struct SessionRegistration {
    pub admin_tx: UnboundedSender<AdminEnum>,
    /// Shared with the Session so the message router can read the value
    /// without locking the entire session. Updated by the session during logon.
    pub target_default_appl_ver_id: Arc<StdMutex<String>>,
    /// Capacity for the inbound message channel (0 = unbounded, default 1).
    pub in_chan_capacity: usize,
}

pub static SESSIONS: LazyLock<DashMap<Arc<SessionID>, SessionRegistration>> =
    LazyLock::new(DashMap::new);
pub static ERR_DUPLICATE_SESSION_ID: LazyLock<SimpleError> =
    LazyLock::new(|| simple_error!("Duplicate SessionID"));
pub static ERR_UNKNOWN_SESSION: LazyLock<SimpleError> =
    LazyLock::new(|| simple_error!("Unknown session"));

// Messagable is a Message or something that can be converted to a Message.
pub trait Messageable: Send + Sync {
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

// send_owned is like send but takes an owned Message, avoiding a clone.
pub async fn send_owned(message: Message) -> Result<(), FixerError> {
    let mut begin_string = FIXString::new();
    message
        .header
        .get_field(TAG_BEGIN_STRING, &mut begin_string)?;

    let mut target_comp_id = FIXString::new();
    message
        .header
        .get_field(TAG_TARGET_COMP_ID, &mut target_comp_id)?;

    let mut sender_comp_id = FIXString::new();
    message
        .header
        .get_field(TAG_SENDER_COMP_ID, &mut sender_comp_id)?;

    let session_id = SessionID {
        begin_string,
        target_comp_id,
        sender_comp_id,
        ..Default::default()
    };

    send_to_target_owned(message, &Arc::new(session_id)).await
}

// send_to_target sends a message based on the session_id. Sends through a
// channel to the session's run loop rather than locking the session directly.
pub async fn send_to_target(
    message: &dyn Messageable,
    session_id: &Arc<SessionID>,
) -> Result<(), FixerError> {
    let msg = message.to_message();
    send_to_target_owned(msg.clone(), session_id).await
}

// send_to_target_owned is like send_to_target but takes an owned Message,
// avoiding a clone when the caller already has ownership.
pub async fn send_to_target_owned(
    message: Message,
    session_id: &Arc<SessionID>,
) -> Result<(), FixerError> {
    let registration = (*SESSIONS)
        .get(session_id)
        .ok_or(ERR_UNKNOWN_SESSION.clone())?;

    let (result_tx, result_rx) = tokio::sync::oneshot::channel();
    registration
        .admin_tx
        .send(AdminEnum::QueueForSend(QueueForSend {
            msg: message,
            result: result_tx,
        }))
        .map_err(|_| FixerError::from(ERR_UNKNOWN_SESSION.clone()))?;

    result_rx
        .await
        .map_err(|_| FixerError::from(ERR_UNKNOWN_SESSION.clone()))?
}

// unregister_session removes a session from the set of known sessions.
pub fn unregister_session(session_id: &Arc<SessionID>) -> SimpleResult<()> {
    if (*SESSIONS).contains_key(session_id) {
        (*SESSIONS).remove(session_id);
        return Ok(());
    }

    Err(ERR_UNKNOWN_SESSION.clone())
}

pub fn register_session(
    session_id: Arc<SessionID>,
    registration: SessionRegistration,
) -> SimpleResult<()> {
    if (*SESSIONS).contains_key(&session_id) {
        return Err(ERR_DUPLICATE_SESSION_ID.clone());
    }

    (*SESSIONS).insert(session_id, registration);
    Ok(())
}

// lookup_admin_tx returns the admin channel sender for the given session, if it exists.
pub fn lookup_admin_tx(session_id: &Arc<SessionID>) -> Option<UnboundedSender<AdminEnum>> {
    let reg = (*SESSIONS).get(session_id)?;
    Some(reg.admin_tx.clone())
}

// lookup_session_registration returns the registration for the given session, if it exists.
pub fn lookup_session_registration(
    session_id: &Arc<SessionID>,
) -> Option<SessionRegistration> {
    let reg = (*SESSIONS).get(session_id)?;
    Some(reg.clone())
}

// lookup_session_registration_flexible first tries an exact match, then falls back to
// matching on all fields except qualifier. This is needed because incoming connections
// don't carry a qualifier — it's a server-side config concept (e.g. SessionQualifier=FIX50
// to disambiguate multiple FIXT.1.1 sessions with the same comp IDs).
pub fn lookup_session_registration_flexible(
    session_id: &Arc<SessionID>,
) -> Option<(Arc<SessionID>, SessionRegistration)> {
    // Exact match first
    if let Some(reg) = (*SESSIONS).get(session_id) {
        return Some((session_id.clone(), reg.clone()));
    }

    // Fall back: match on all fields except qualifier, but only when the
    // incoming session has an empty qualifier. A non-empty qualifier (e.g.
    // from DynamicQualifier assignment) should require an exact match.
    if session_id.qualifier.is_empty() {
        for entry in &(*SESSIONS) {
            let candidate = entry.key();
            if candidate.begin_string == session_id.begin_string
                && candidate.sender_comp_id == session_id.sender_comp_id
                && candidate.target_comp_id == session_id.target_comp_id
                && candidate.sender_sub_id == session_id.sender_sub_id
                && candidate.sender_location_id == session_id.sender_location_id
                && candidate.target_sub_id == session_id.target_sub_id
                && candidate.target_location_id == session_id.target_location_id
            {
                return Some((candidate.clone(), entry.value().clone()));
            }
        }
    }

    None
}
