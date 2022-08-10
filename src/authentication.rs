use std::{str::FromStr, sync::Arc};

use once_cell::sync::OnceCell;
use pbkdf2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Pbkdf2,
};
use rand_core::{OsRng, RngCore};

use crate::{
    errors::{LoginError, SignupError},
    Database, Random,
};

#[derive(Clone, Copy)]
pub(crate) struct SessionToken(u128);

impl FromStr for SessionToken {
    type Err = <u128 as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse().map(Self)
    }
}

impl SessionToken {
    pub fn generate_new(random: Random) -> Self {
        let mut u128_pool = [0u8; 16];
        random.lock().unwrap().fill_bytes(&mut u128_pool);
        Self(u128::from_le_bytes(u128_pool))
    }

    pub fn into_cookie_value(self) -> String {
        // TODO Opportunity for a smaller format that is still a valid cookie value
        self.0.to_string()
    }

    pub fn into_database_value(self) -> Vec<u8> {
        self.0.to_le_bytes().to_vec()
    }
}

pub(crate) struct User {
    pub username: String,
}

#[derive(Clone)]
pub(crate) struct AuthState(Option<(SessionToken, Arc<OnceCell<User>>)>, Database);

impl AuthState {
    pub fn logged_in(&self) -> bool {
        self.0.is_some()
    }

    pub async fn get_user(&self) -> Option<&User> {
        let (session_token, cell) = self.0.as_ref()?;
        // Want to use get_or_init here but function needs to be async
        if cell.get().is_none() {
            const QUERY: &str =
                "SELECT id, username FROM users JOIN sessions ON user_id = id WHERE session_token = $1;";

            let user: Option<(i32, String)> = sqlx::query_as(QUERY)
                .bind(&session_token.into_database_value())
                .fetch_optional(&self.1)
                .await
                .unwrap();

            if let Some((_id, username)) = user {
                let _err = cell.set(User { username });
            } else {
                dbg!("Invalid session_token used");
            }
        }
        cell.get()
    }
}

/// TODO date
pub(crate) async fn new_session(database: &Database, random: Random, user_id: i32) -> SessionToken {
    const QUERY: &str = "INSERT INTO sessions (session_token, user_id) VALUES ($1, $2);";

    let session_token = SessionToken::generate_new(random);

    let _result = sqlx::query(QUERY)
        .bind(&session_token.into_database_value())
        .bind(user_id)
        .execute(database)
        .await
        .unwrap();

    session_token
}

/// **AUTH MIDDLEWARE**
pub(crate) async fn auth<B>(
    mut req: http::Request<B>,
    next: axum::middleware::Next<B>,
    database: Database,
) -> axum::response::Response {
    // Assuming we only have one cookie
    let key_pair_opt = req
        .headers()
        .get("Cookie")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split_once(';').map(|(left, _)| left).unwrap_or(value))
        .and_then(|kv| kv.split_once('='));

    let auth_state = if let Some((key, value)) = key_pair_opt {
        if key != crate::USER_COOKIE_NAME {
            None
        } else if let Ok(value) = value.parse::<SessionToken>() {
            Some(value)
        } else {
            None
        }
    } else {
        None
    };
    req.extensions_mut().insert(AuthState(
        auth_state.map(|v| (v, Arc::new(OnceCell::new()))),
        database,
    ));
    next.run(req).await
}

pub(crate) async fn signup(
    database: &Database,
    random: Random,
    username: &str,
    password: &str,
) -> Result<SessionToken, SignupError> {
    fn valid_username(username: &str) -> bool {
        (1..20).contains(&username.len())
            && username.chars().all(|c| matches!(c, 'a'..='z' | '0'..='9'))
    }

    if !valid_username(username) {
        return Err(SignupError::InvalidUsername);
    }

    const INSERT_QUERY: &str =
        "INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id;";

    let salt = SaltString::generate(&mut OsRng);

    // Hash password to PHC string ($pbkdf2-sha256$...)
    let password_hash = Pbkdf2.hash_password(password.as_bytes(), &salt);

    let hashed_password = if let Ok(password) = password_hash {
        password.to_string()
    } else {
        return Err(SignupError::InvalidPassword);
    };

    let fetch_one = sqlx::query_as(INSERT_QUERY)
        .bind(username)
        .bind(hashed_password)
        .fetch_one(database)
        .await;

    let user_id: i32 = match fetch_one {
        Ok((user_id,)) => user_id,
        Err(sqlx::Error::Database(database))
            if database.constraint() == Some("users_username_key") =>
        {
            return Err(SignupError::UsernameExists);
        }
        Err(err) => {
            dbg!(err);
            return Err(SignupError::InternalError);
        }
    };

    Ok(new_session(database, random, user_id).await)
}

pub(crate) async fn login(
    database: &Database,
    random: Random,
    username: &str,
    password: &str,
) -> Result<SessionToken, LoginError> {
    const LOGIN_QUERY: &str = "SELECT id, password FROM users WHERE users.username = $1;";

    let row: Option<(i32, String)> = sqlx::query_as(LOGIN_QUERY)
        .bind(username)
        .fetch_optional(database)
        .await
        .unwrap();

    let (user_id, hashed_password) = if let Some(row) = row {
        row
    } else {
        return Err(LoginError::UserDoesNotExist);
    };

    // Verify password against PHC string
    let parsed_hash = PasswordHash::new(&hashed_password).unwrap();
    if let Err(err) = Pbkdf2.verify_password(password.as_bytes(), &parsed_hash) {
        dbg!(err);
        return Err(LoginError::WrongPassword);
    }

    Ok(new_session(database, random, user_id).await)
}

pub(crate) async fn delete_user(auth_state: AuthState) {
    const DELETE_QUERY: &str = "DELETE FROM users 
        WHERE users.id = (
            SELECT user_id FROM sessions WHERE sessions.session_token = $1
        );";

    let _res = sqlx::query(DELETE_QUERY)
        .bind(&auth_state.0.unwrap().0.into_database_value())
        .execute(&auth_state.1)
        .await
        .unwrap();
}
