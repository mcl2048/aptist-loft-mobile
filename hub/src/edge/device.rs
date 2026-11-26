use serde::{Deserialize, Serialize};
use wasm_bindgen::JsValue;
use worker::{D1Database, Request, Response};

use super::http::{self, CONFLICT, CONSENT, Result, SESSION, SLOW, UNAVAILABLE};
use super::portal::{Renewal, Session};
use super::{Config, first, first_col, now, number, prepare};

#[derive(Serialize, Deserialize)]
struct Identity {
    subject: String,
    email: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub(super) struct MailGrant {
    pub(super) token: String,
}

#[derive(Deserialize)]
pub(super) struct Device {
    pub(super) owner_hash: String,
    identity_box: String,
    mail_box: Option<String>,
    mail_expires_at: Option<u64>,
    mail_revision: u32,
}

pub(super) async fn find(db: &D1Database, hash: &str) -> Result<Option<Device>> {
    first(
        db,
        "SELECT owner_hash, identity_box, mail_box, mail_expires_at, mail_revision FROM hub_device_session WHERE session_hash = ?1",
        &[hash.into()],
    )
    .await
}

pub(super) fn renewal(request: &Request, device: Device) -> Result<Renewal> {
    Ok(Renewal {
        device_token: super::bearer_token(request)?,
        owner_hash: device.owner_hash,
        mail_revision: device.mail_revision,
    })
}

pub(super) async fn revoke(db: &D1Database, hash: &str) -> Result<()> {
    batch(
        db,
        vec![
            prepare(
                db,
                "DELETE FROM hub_device_session WHERE session_hash = ?1",
                &[hash.into()],
            )?,
            prepare(
                db,
                include_str!("../sql/device_logout_receipts.sql"),
                &[hash.into()],
            )?,
        ],
    )
    .await
}

pub(super) async fn cancel(db: &D1Database, id: &str, proof: &str) -> Result<()> {
    batch(
        db,
        vec![
            prepare(
                db,
                include_str!("../sql/device_cancel_enrollment.sql"),
                &[id.into(), proof.into(), number(now())],
            )?,
            prepare(
                db,
                include_str!("../sql/cancel.sql"),
                &[id.into(), proof.into()],
            )?,
        ],
    )
    .await
}

pub(super) fn response(
    config: &Config,
    hash: &str,
    device: Device,
    issued_token: Option<&str>,
) -> Result<Response> {
    let identity: Identity = config.open("identity", hash, &device.identity_box)?;
    let (expires_at, expires_in) = device.mail_expiry();
    let mut response = serde_json::json!({
        "issuer": config.issuer, "subject": identity.subject, "mailRead": expires_in > 0,
        "expiresAt": expires_at, "expiresIn": expires_in, "durable": true,
    });
    if let Some(email) = identity.email {
        response["email"] = email.into();
    }
    if let Some(token) = issued_token {
        response["status"] = "complete".into();
        response["sessionToken"] = token.into();
    }
    http::json(200, &response)
}

impl Device {
    fn mail_expiry(&self) -> (u64, u64) {
        let at = now();
        self.mail_expires_at
            .filter(|expires| *expires > at && self.mail_box.is_some())
            .map_or((0, 0), |expires| (expires, expires - at))
    }

    pub(super) fn mail_session(&self, config: &Config, hash: &str) -> Result<Session> {
        if self.mail_expiry().1 == 0 {
            return Err(CONSENT);
        }
        let identity: Identity = config.open("identity", hash, &self.identity_box)?;
        let grant: MailGrant =
            config.open("mail", hash, self.mail_box.as_deref().ok_or(CONSENT)?)?;
        Ok(Session {
            token: String::new(),
            portal_access: grant.token,
            subject: identity.subject,
            email: identity.email,
            mail_read: true,
            durable: true,
            renewal: None,
        })
    }

    pub(super) async fn mail_current(&self, db: &D1Database, hash: &str) -> Result<()> {
        let current = find(db, hash).await?.ok_or(SESSION)?;
        if current.mail_revision != self.mail_revision || current.mail_expiry().1 == 0 {
            return Err(CONSENT);
        }
        Ok(())
    }
}

pub(super) async fn invalidate_mail(db: &D1Database, hash: &str, original: &Device) -> Result<()> {
    super::write(db, "UPDATE hub_device_session SET mail_box = NULL, mail_expires_at = NULL WHERE session_hash = ?1 AND mail_revision = ?2",
        &[hash.into(), number(original.mail_revision.into())]).await
}

pub(super) async fn issue(
    config: &Config,
    db: &D1Database,
    id: &str,
    proof: &str,
    phase: &str,
    session: &Session,
    grant_expires_at: u64,
) -> Result<Response> {
    let owner = config.owner_hash(&session.subject);
    let token = session
        .renewal
        .as_ref()
        .map_or(session.token.as_str(), |r| r.device_token.as_str());
    let hash = config.hash("session", token);
    if phase == "ready" {
        let at = now();
        let (mail_box, mail_expires_at) = if session.mail_read {
            let grant = MailGrant {
                token: session.portal_access.clone(),
            };
            (
                config.seal("mail", &hash, &grant)?.into(),
                number(grant_expires_at),
            )
        } else {
            (JsValue::NULL, JsValue::NULL)
        };
        let install = match &session.renewal {
            Some(renewal) => prepare(
                db,
                include_str!("../sql/device_renew.sql"),
                &[
                    id.into(),
                    hash.clone().into(),
                    owner.into(),
                    mail_box,
                    mail_expires_at,
                    number(renewal.mail_revision.into()),
                    proof.into(),
                    number(at),
                ],
            )?,
            None => {
                let identity_box = config.seal(
                    "identity",
                    &hash,
                    &Identity {
                        subject: session.subject.clone(),
                        email: session.email.clone(),
                    },
                )?;
                prepare(
                    db,
                    include_str!("../sql/device_enroll.sql"),
                    &[
                        id.into(),
                        owner.into(),
                        identity_box.into(),
                        mail_box,
                        mail_expires_at,
                        proof.into(),
                        number(at),
                        number(32),
                    ],
                )?
            }
        };
        let mark = prepare(
            db,
            include_str!("../sql/device_issue.sql"),
            &[id.into(), proof.into(), number(at), hash.clone().into()],
        )?;
        batch(db, vec![install, mark]).await?;
    }
    let receipt: Option<String> = first_col(
        db,
        include_str!("../sql/device_receipt.sql"),
        "session_hash",
        &[id.into(), proof.into(), number(now()), hash.clone().into()],
    )
    .await?;
    if receipt.is_none() {
        return if session.renewal.is_some() {
            if find(db, &hash).await?.is_some() {
                Err(CONFLICT)
            } else {
                Err(SESSION)
            }
        } else {
            Err(SLOW)
        };
    }
    response(
        config,
        &hash,
        find(db, &hash).await?.ok_or(SESSION)?,
        Some(token),
    )
}

async fn batch(db: &D1Database, statements: Vec<worker::D1PreparedStatement>) -> Result<()> {
    let result = db.batch(statements).await.map_err(|_| UNAVAILABLE)?;
    if result.iter().any(|statement| !statement.success()) {
        return Err(UNAVAILABLE);
    }
    Ok(())
}
