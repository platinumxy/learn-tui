use std::rc::Rc;
use std::sync::mpsc::Sender;

use crate::{
    auth_cache::LoginDetails,
    event::{Event, EventBus},
    main_screen::MainScreen,
    ExitState, Screen,
};
use anyhow::Result;
use crossterm::event::{KeyCode, KeyModifiers};
use edlearn_client::{AuthState, Client};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph, Wrap},
};

/// Prompts the user for their credentials
pub struct LoginPrompt {
    username: String,
    password: String,
    remember: bool,
    selected: SelectedInput,
    message: String,
    events: Rc<EventBus>,
    otp_response: Option<Sender<String>>,
    otp: String,
}

impl LoginPrompt {
    /// Create a blank form for credentials.
    /// The given [`EventBus`] will be used to initialise the [`MainScreen`] once the user submits.
    pub fn new(events: Rc<EventBus>) -> Self {
        Self {
            events,
            username: String::new(),
            password: String::new(),
            remember: false,
            selected: SelectedInput::Username,
            message: String::new(),
            otp_response: None,
            otp: String::new(),
        }
    }

    /// Create a blank form with the given message.
    /// This can be used to re-prompt for authentication, etc.
    pub fn new_with_msg(events: Rc<EventBus>, message: &'static str) -> Self {
        Self {
            events,
            username: String::new(),
            password: String::new(),
            remember: false,
            selected: SelectedInput::Username,
            message: message.to_owned(),
            otp_response: None,
            otp: String::new(),
        }
    }
}

impl Screen for LoginPrompt {
    fn draw(&mut self, frame: &mut ratatui::Frame) {
        // TODO: Ugly layout code that could probably be replaced with flexbox
        let horiz_layout = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(Constraint::from_percentages([25, 50, 25]))
            .split(frame.size());

        let layout = Layout::default()
            .constraints(vec![
                Constraint::Min(2),    // header
                Constraint::Length(1), // padding
                Constraint::Length(1), // username
                Constraint::Length(1), // password
                Constraint::Length(1), // remember me
                Constraint::Length(1), // padding
                Constraint::Min(3),    // message
            ])
            .split(horiz_layout[1]);

        let username_para = Paragraph::new(format!("Username: {}", self.username))
            .block(Block::new().borders(self.selected.borders_for(SelectedInput::Username)));
        let password_para =
            Paragraph::new(format!("Password: {}", "*".repeat(self.password.len())))
                .block(Block::new().borders(self.selected.borders_for(SelectedInput::Password)));
        let remember_para = Paragraph::new(format!(
            "Remember? {}",
            if self.remember { "Y" } else { "N" }
        ))
        .block(Block::new().borders(self.selected.borders_for(SelectedInput::Remember)));

        let header_para = Paragraph::new("Login")
            .block(Block::new().borders(Borders::BOTTOM))
            .alignment(Alignment::Center);

        let message = if self.otp_response.is_some() {
            format!("Enter Microsoft Authenticator OTP: {}", self.otp)
        } else {
            self.message.clone()
        };
        let message_para = Paragraph::new(message)
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: false });

        frame.render_widget(header_para, layout[0]);
        frame.render_widget(username_para, layout[2]);
        frame.render_widget(password_para, layout[3]);
        frame.render_widget(remember_para, layout[4]);
        frame.render_widget(message_para, layout[6]);
    }
    fn handle_event(&mut self, event: Event) -> Result<ExitState> {
        match event {
            Event::AuthStatus(message) => {
                self.message = message.to_owned();
                return Ok(ExitState::Running);
            }
            Event::AuthApproval(number) => {
                self.message = format!("Approve sign-in request: {number}");
                return Ok(ExitState::Running);
            }
            Event::AuthOtp { response } => {
                self.otp_response = Some(response);
                self.otp.clear();
                return Ok(ExitState::Running);
            }
            Event::AuthFinished(result) => return self.auth_finished(result),
            _ => (),
        }

        if let Event::Key(k) = event {
            if self.otp_response.is_some() {
                return self.handle_otp_key(k.code);
            }
            match k.code {
                // Quit shortcuts
                KeyCode::Esc => return Ok(ExitState::Quit),
                KeyCode::Char('c') | KeyCode::Char('C') if k.modifiers == KeyModifiers::CONTROL => {
                    return Ok(ExitState::Quit);
                }

                // Navigate form fields
                KeyCode::Tab | KeyCode::Down => self.selected.down(),
                KeyCode::BackTab | KeyCode::Up => self.selected.up(),
                KeyCode::Enter if self.selected != SelectedInput::Remember => self.selected.down(),

                // Typing
                KeyCode::Char(c) if !c.is_control() => match self.selected {
                    SelectedInput::Username => self.username.push(c),
                    SelectedInput::Password => self.password.push(c),
                    SelectedInput::Remember => self.remember = !self.remember,
                },
                KeyCode::Backspace => match self.selected {
                    SelectedInput::Username => {
                        self.username.pop();
                    }
                    SelectedInput::Password => {
                        self.password.pop();
                    }
                    SelectedInput::Remember => self.remember = !self.remember,
                },

                // Submit
                KeyCode::Enter => {
                    if self.username.is_empty() {
                        self.message = "Username is empty!".to_owned();
                    } else if self.password.is_empty() {
                        self.message = "Password is empty!".to_owned();
                    } else {
                        self.start_authentication();
                    }
                }

                _ => (),
            };
        };

        Ok(ExitState::Running)
    }
}

impl LoginPrompt {
    fn start_authentication(&mut self) {
        let username = self.username.clone();
        let password = self.password.clone();
        let events = self.events.clone();
        self.message = "Authenticating...".to_owned();

        events.spawn("microsoft_auth", move |_, event_send| {
            let client = Client::new((username, password.into()));
            let approval_send = event_send.clone();
            let otp_send = event_send.clone();
            let status_send = event_send.clone();
            let result = client
                .authenticate_with_callbacks(
                    move || {
                        let (response_send, response_recv) = std::sync::mpsc::channel();
                        otp_send
                            .send(Event::AuthOtp {
                                response: response_send,
                            })
                            .map_err(|error| error.to_string())?;
                        response_recv.recv().map_err(|error| error.to_string())
                    },
                    move |number| {
                        approval_send
                            .send(Event::AuthApproval(number))
                            .map_err(|error| error.to_string())
                    },
                    move |message| {
                        status_send
                            .send(Event::AuthStatus(message))
                            .map_err(|error| error.to_string())
                    },
                )
                .map(|_| client.auth_state())
                .map_err(|error| error.to_string());

            let _ = event_send.send(Event::AuthFinished(result));
        });
    }

    fn handle_otp_key(&mut self, code: KeyCode) -> Result<ExitState> {
        match code {
            KeyCode::Char(c) if c.is_ascii_digit() => self.otp.push(c),
            KeyCode::Backspace => {
                self.otp.pop();
            }
            KeyCode::Enter if !self.otp.is_empty() => {
                if let Some(response) = self.otp_response.take() {
                    let _ = response.send(std::mem::take(&mut self.otp));
                }
            }
            KeyCode::Esc => return Ok(ExitState::Quit),
            _ => (),
        }
        Ok(ExitState::Running)
    }

    fn auth_finished(&mut self, result: Result<AuthState, String>) -> Result<ExitState> {
        match result {
            Ok(state) => Ok(ExitState::ChangeScreen(Box::new(MainScreen::new(
                self.events.clone(),
                LoginDetails {
                    creds: (self.username.clone(), self.password.clone().into()),
                    remember: self.remember,
                    auth_state: Some(state),
                },
            )))),
            Err(error) => {
                self.message = error;
                Ok(ExitState::Running)
            }
        }
    }
}

#[derive(PartialEq, Eq)]
enum SelectedInput {
    Username,
    Password,
    Remember,
}
impl SelectedInput {
    fn up(&mut self) {
        *self = match self {
            Self::Username => Self::Remember,
            Self::Password => Self::Username,
            Self::Remember => Self::Password,
        };
    }

    fn down(&mut self) {
        *self = match self {
            Self::Username => Self::Password,
            Self::Password => Self::Remember,
            Self::Remember => Self::Username,
        };
    }

    fn borders_for(&self, inp: SelectedInput) -> Borders {
        if inp == *self {
            Borders::LEFT
        } else {
            Borders::NONE
        }
    }
}
