use std::{error::Error, fmt::Display};

#[derive(Debug)]
pub(crate) enum MultipartError {
    NoName,
    InvalidValue,
    ReadError,
}

impl Display for MultipartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MultipartError::NoName => f.write_str("No named field in multipart"),
            MultipartError::InvalidValue => f.write_str("Invalid value in multipart"),
            MultipartError::ReadError => f.write_str("Reading multipart error"),
        }
    }
}

impl Error for MultipartError {}

#[derive(Debug)]
pub(crate) struct NotLoggedIn;

impl Display for NotLoggedIn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Not logged in")
    }
}

impl Error for NotLoggedIn {}

#[derive(Debug)]
pub(crate) enum SignupError {
    UsernameExists,
    InvalidUsername,
    PasswordsDoNotMatch,
    MissingDetails,
    InvalidPassword,
    InternalError,
}

impl Display for SignupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignupError::InvalidUsername => f.write_str("Invalid username"),
            SignupError::UsernameExists => f.write_str("Username already exists"),
            SignupError::PasswordsDoNotMatch => f.write_str("Passwords do not match"),
            SignupError::MissingDetails => f.write_str("Missing Details"),
            SignupError::InvalidPassword => f.write_str("Invalid Password"),
            SignupError::InternalError => f.write_str("Internal Error"),
        }
    }
}

impl Error for SignupError {}

#[derive(Debug)]
pub(crate) enum LoginError {
    MissingDetails,
    UserDoesNotExist,
    WrongPassword,
}

impl Display for LoginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoginError::UserDoesNotExist => f.write_str("User does not exist"),
            LoginError::MissingDetails => f.write_str("Missing details"),
            LoginError::WrongPassword => f.write_str("Wrong password"),
        }
    }
}

impl Error for LoginError {}

#[derive(Debug)]
pub(crate) struct NoUser(pub String);

impl Display for NoUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("could not find user '{}'", self.0))
    }
}

impl Error for NoUser {}
