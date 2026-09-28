//! Code for authenticating to Edinburgh University's Learn instance
//!
//! Thank you to @kilolympus and @chaives for figuring out the login process
//! See: <https://git.tardisproject.uk/kilo/echo360-downloader>

use serde::{Deserialize, Serialize};
use std::{io::{self, Write}, sync::{Mutex, TryLockError}, time::Duration};
use thirtyfour::{By, WebDriver};
use thiserror::Error;
use url::Url;

use crate::Client;

/// Information used to login
pub type Credentials = (String, Password);

static LOCK: Mutex<()> = Mutex::new(());

#[derive(Deserialize)]
struct BrowserCookie {
    name: String,
    value: String,
    domain: Option<String>,
    path: Option<String>,
    secure: Option<bool>,
    #[serde(rename = "httpOnly")]
    http_only: Option<bool>,
}

/// An error encountered when logging in
#[derive(Error, Debug)]
pub enum Error {
    #[error("browser failed to start: {0}")]
    BrowserError(String),

    #[error("microsoft authentication failed: {0}")]
    MicrosoftAuth(String),
    
    #[error("couldn't import microsoft authentication cookies: {0}")]
    CookieImport(String),
    
    #[error("couldn't update status: {0}")]
    StatusError(String),

    #[error("Already locked in state: {0}")]
    LockedError(String),

    #[error("misc I/O error: {}", .0)]
    IOError(#[from] std::io::Error),
}

impl Client {
    /// Attempt to authenticate with the set credentials
    pub fn authenticate(&self) -> Result<(), Error> {
        self.authenticate_with_callbacks(
            read_otp,
            |number| {
                println!("Approve the sign-in request for code: {number}");
                Ok(())
            },
            |_| Ok(()),
        )
    }

    /// Authenticate with Microsoft while letting the caller own user prompts.
    pub fn authenticate_with_callbacks<OTP, APPROVAL, STATUS>(
        &self,
        mut otp_provider: OTP,
        mut approval_notifier: APPROVAL,
        mut status_notifier: STATUS,
    ) -> Result<(), Error>
    where
        OTP: FnMut() -> Result<String, String>,
        APPROVAL: FnMut(u64) -> Result<(), String>,
        STATUS: FnMut(&'static str) -> Result<(), String>,
    {
        let _lock = LOCK.try_lock().map_err(|e| {
            Error::LockedError(match e {
                TryLockError::WouldBlock => "auth in progress",
                TryLockError::Poisoned(_) => "lock is poisoned"
            }.to_owned())
        })?;

        let username = self.creds.0.clone();
        let password = self.creds.1.as_ref().to_owned();
        if !username.ends_with("@ed.ac.uk") {
            return Err(Error::MicrosoftAuth(
                "username must end with @ed.ac.uk".to_owned(),
            ));
        }
        if password.is_empty() {
            return Err(Error::MicrosoftAuth(
                "password must not be empty".to_owned(),
            ));
        }

        let runtime = tokio::runtime::Runtime::new()
            .map_err(|error| Error::MicrosoftAuth(error.to_string()))?;
        
        let cookies = runtime.block_on(authenticate_with_browser(
            &mut otp_provider,
            &mut approval_notifier,
            &mut status_notifier,
            username,
            password
        ))?;
        
        let browser_cookies: Vec<BrowserCookie> = serde_json::from_str(&cookies)
            .map_err(|error| Error::CookieImport(error.to_string()))?;

        let mut store = self.cookies.write().unwrap();

        for browser_cookie in browser_cookies {
            extract_cookie(&mut store, browser_cookie)?;
        }
        
        Ok(())
    }

    /// Serialise the auth state, for persistence
    pub fn auth_state(&self) -> AuthState {
        let mut ser = Vec::new();
        self.cookies
            .read()
            .unwrap()
            .save_incl_expired_and_nonpersistent_json(&mut ser)
            .unwrap();
        AuthState(ser)
    }
}

fn extract_cookie(store: &mut std::sync::RwLockWriteGuard<'_, reqwest_cookie_store::CookieStore>, cookie: BrowserCookie) -> Result<(), Error> {
    let domain = cookie
        .domain
        .ok_or_else(|| Error::CookieImport(format!("cookie {} has no domain", cookie.name)))?;
    let url = Url::parse(&format!(
        "https://{}{}",
        domain.trim_start_matches('.'),
        cookie.path.as_deref().unwrap_or("/")
    ))
    .map_err(|error| Error::CookieImport(error.to_string()))?;
    let mut raw = format!(
        "{}={}; Domain={}; Path={}",
        cookie.name,
        cookie.value,
        domain,
        cookie.path.as_deref().unwrap_or("/")
    );
    if cookie.secure.unwrap_or(false) {
        raw.push_str("; Secure");
    }
    if cookie.http_only.unwrap_or(false) {
        raw.push_str("; HttpOnly");
    }
    let parsed = reqwest_cookie_store::RawCookie::parse(&raw)
        .map_err(|error| Error::CookieImport(error.to_string()))?;
    store
        .insert_raw(&parsed, &url)
        .map_err(|error| Error::CookieImport(error.to_string()))?;
    Ok(())
}

async fn authenticate_with_browser<OTP, APPROVAL>(
    otp_provider: &mut OTP,
    approval_notifier: &mut APPROVAL,
    status_notifier: &mut impl FnMut(&'static str) -> Result<(), String>,
    username: String,
    password: String,
) -> Result<String, Error>
where
    OTP: FnMut() -> Result<String, String>,
    APPROVAL: FnMut(u64) -> Result<(), String>, 
{
    status_notifier("Launching browser (This may take a while)...").map_err(Error::MicrosoftAuth)?;
    let driver = uoe_ms_auth::create_driver()
        .await
        .map_err(|error| Error::BrowserError(error.to_string()))?;

    authenticate_with_ms(
        otp_provider,
        approval_notifier,
        status_notifier,
        username,
        password,
        &driver,
    )
    .await?;
    status_notifier("authenticating with learn...").map_err(Error::MicrosoftAuth)?; 
    authenticate_with_learn(&driver)
        .await
        .map_err(|error| Error::MicrosoftAuth(error.to_string()))?;

    status_notifier("Dumping cookies...").map_err(Error::MicrosoftAuth)?;
    Ok(
        uoe_ms_auth::cookies_from(
            &driver,
            vec![
                "edadfed.ed.ac.uk",
                "exampapers.ed.ac.uk",
                "idp.ed.ac.uk",
                "www.learn.ed.ac.uk",
                "login.live.com",
                "login.microsoft.com",
                "login.microsoftonline.com",
            ],
        )
        .await
    )
}

async fn authenticate_with_ms<OTP, APPROVAL>(
    otp_provider: &mut OTP,
    approval_notifier: &mut APPROVAL,
    status_notifier: &mut impl FnMut(&'static str) -> Result<(), String>,
    username: String,
    password: String,
    driver: &WebDriver,
) -> Result<(), Error>
where
    OTP: FnMut() -> Result<String, String>,
    APPROVAL: FnMut(u64) -> Result<(), String>,
{
    let mut state = uoe_ms_auth::AuthState::Init;
    while !state.exit_state() {
        state = match state {
            uoe_ms_auth::AuthState::CredsPrompt { .. } => uoe_ms_auth::AuthState::CredsPrompt {
                username: {
                    status_notifier("Submitting credentials...").map_err(Error::MicrosoftAuth)?;
                    Some(username.clone())
                },
                password: Some(password.clone()),
            },
            uoe_ms_auth::AuthState::ApproveAppNotif(number) => {
                approval_notifier(number).map_err(Error::MicrosoftAuth)?;
                uoe_ms_auth::AuthState::ApproveAppNotif(number)
            }
            uoe_ms_auth::AuthState::PhoneOTP(_) => uoe_ms_auth::AuthState::PhoneOTP(Some(
                otp_provider().map_err(Error::MicrosoftAuth)?,
            )),
            state => state,
        };

        state = uoe_ms_auth::step_auth_sm(driver, state)
            .await
            .map_err(|error| Error::MicrosoftAuth(error.to_string()))?
    }
    if state != uoe_ms_auth::AuthState::Authenticated {
        return Err(Error::MicrosoftAuth(format!(
            "authentication ended in {state:?}"
        )));
    }
    Ok(())
}

async fn authenticate_with_learn(driver: &WebDriver) -> Result<(), thirtyfour::error::WebDriverError> {
    driver.goto("https://www.learn.ed.ac.uk/").await?;
    
    if let Ok(login) = driver.find(By::ClassName("easelogin-bt")).await {
        login.click().await?;
    }

    tokio::time::sleep(Duration::from_secs(1)).await;
    Ok(())
}

fn read_otp() -> Result<String, String> {
    print!("Please enter an OTP from your Microsoft Authenticator app: ");
    io::stdout().flush().map_err(|error| error.to_string())?;
    let mut otp = String::new();
    io::stdin()
        .read_line(&mut otp)
        .map_err(|error| error.to_string())?;
    Ok(otp.trim().to_owned())
}

/// Contains cached authentication cookies
#[derive(Serialize, Deserialize, Clone)]
pub struct AuthState(pub(crate) Vec<u8>);

impl std::fmt::Debug for AuthState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AuthState (***)")?;
        Ok(())
    }
}

/// A password, wrapped so we don't print it by accident
#[derive(Clone, Serialize, Deserialize)]
pub struct Password(String);
impl std::fmt::Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Password (******)")?;
        Ok(())
    }
}

impl From<String> for Password {
    fn from(value: String) -> Self {
        Password(value)
    }
}

impl From<Password> for String {
    fn from(val: Password) -> Self {
        val.0
    }
}

impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}
