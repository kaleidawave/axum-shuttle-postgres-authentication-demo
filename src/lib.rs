mod authentication;
mod errors;
mod utils;

use std::sync::{Arc, Mutex};

use axum::{
    extract::{Extension, Multipart, Path},
    middleware,
    response::{Html, IntoResponse, Redirect},
    routing::{any, get, post},
    Router,
};
use http::Response;

use authentication::{auth, delete_user, login, signup, AuthState};
use errors::{LoginError, NoUser, NotLoggedIn, SignupError};
use pbkdf2::password_hash::rand_core::OsRng;
use rand_chacha::ChaCha8Rng;
use rand_core::{RngCore, SeedableRng};
use shuttle_service::{error::CustomError, ShuttleAxum};
use sqlx::Executor;
use tera::{Context, Tera};
use utils::*;

type Templates = Arc<Tera>;
type Database = sqlx::PgPool;
type Random = Arc<Mutex<ChaCha8Rng>>;

const USER_COOKIE_NAME: &str = "user_token";
const COOKIE_MAX_AGE: &str = "9999999";

#[shuttle_service::main]
async fn server(#[shuttle_shared_db::Postgres] pool: Database) -> ShuttleAxum {
    pool.execute(include_str!("../schema.sql"))
        .await
        .map_err(CustomError::new)?;

    Ok(sync_wrapper::SyncWrapper::new(get_router(pool)))
}

pub fn get_router(database: Database) -> Router {
    let mut tera = Tera::default();
    tera.add_raw_templates(vec![
        ("base.html", include_str!("../templates/base.html")),
        ("index", include_str!("../templates/index.html")),
        ("signup", include_str!("../templates/signup.html")),
        ("login", include_str!("../templates/login.html")),
        ("users", include_str!("../templates/users.html")),
        ("user", include_str!("../templates/user.html")),
    ])
    .unwrap();

    let middleware_database = database.clone();
    let random = ChaCha8Rng::seed_from_u64(OsRng.next_u64());

    Router::new()
        .route("/", get(index))
        .route("/signup", get(get_signup).post(post_signup))
        .route("/login", get(get_login).post(post_login))
        .route("/logout", post(logout_response))
        .route("/delete", post(post_delete))
        .route("/me", get(me))
        .route("/user/:username", get(user))
        .route("/users", get(users))
        .route("/styles.css", any(styles))
        .layer(middleware::from_fn(move |req, next| {
            auth(req, next, middleware_database.clone())
        }))
        .layer(Extension(Arc::new(tera)))
        .layer(Extension(database))
        .layer(Extension(Arc::new(Mutex::new(random))))
}

async fn index(
    Extension(current_user): Extension<AuthState>,
    Extension(templates): Extension<Templates>,
) -> impl IntoResponse {
    let mut context = Context::new();
    context.insert("logged_in", &current_user.logged_in());
    context.insert("home_screen", &true);
    Html(templates.render("index", &context).unwrap())
}

async fn user(
    Path(username): Path<String>,
    Extension(mut auth_state): Extension<AuthState>,
    Extension(database): Extension<Database>,
    Extension(templates): Extension<Templates>,
) -> impl IntoResponse {
    const QUERY: &str = "SELECT username FROM users WHERE username = $1;";

    let user: Option<(String,)> = sqlx::query_as(QUERY)
        .bind(&username)
        .fetch_optional(&database)
        .await
        .unwrap();

    if let Some((username,)) = user {
        let user_is_self = auth_state
            .get_user()
            .await
            .map(|logged_in_user| logged_in_user.username == username)
            .unwrap_or_default();
        let mut context = Context::new();
        context.insert("username", &username);
        context.insert("is_self", &user_is_self);
        Ok(Html(templates.render("user", &context).unwrap()))
    } else {
        Err(error_page(&NoUser(username)))
    }
}

async fn get_signup(Extension(templates): Extension<Templates>) -> impl IntoResponse {
    Html(templates.render("signup", &Context::new()).unwrap())
}

async fn get_login(Extension(templates): Extension<Templates>) -> impl IntoResponse {
    Html(templates.render("login", &Context::new()).unwrap())
}

async fn post_signup(
    Extension(database): Extension<Database>,
    Extension(random): Extension<Random>,
    multipart: Multipart,
) -> impl IntoResponse {
    let data = parse_multipart(multipart)
        .await
        .map_err(|err| error_page(&err))?;

    if let (Some(username), Some(password), Some(confirm_password)) = (
        data.get("username"),
        data.get("password"),
        data.get("confirm_password"),
    ) {
        if password != confirm_password {
            return Err(error_page(&SignupError::PasswordsDoNotMatch));
        }

        match signup(&database, random, username, password).await {
            Ok(session_token) => Ok(login_response(session_token)),
            Err(error) => Err(error_page(&error)),
        }
    } else {
        Err(error_page(&SignupError::MissingDetails))
    }
}

async fn post_login(
    Extension(database): Extension<Database>,
    Extension(random): Extension<Random>,
    multipart: Multipart,
) -> impl IntoResponse {
    let data = parse_multipart(multipart)
        .await
        .map_err(|err| error_page(&err))?;

    if let (Some(username), Some(password)) = (data.get("username"), data.get("password")) {
        match login(&database, random, username, password).await {
            Ok(session_token) => Ok(login_response(session_token)),
            Err(err) => Err(error_page(&err)),
        }
    } else {
        Err(error_page(&LoginError::MissingDetails))
    }
}

async fn post_delete(Extension(current_user): Extension<AuthState>) -> impl IntoResponse {
    if !current_user.logged_in() {
        return Err(error_page(&NotLoggedIn));
    }

    delete_user(current_user).await;

    Ok(logout_response().await)
}

async fn styles() -> impl IntoResponse {
    Response::builder()
        .status(http::StatusCode::OK)
        .header("Content-Type", "text/css")
        .body(include_str!("../public/styles.css").to_owned())
        .unwrap()
}

async fn me(
    Extension(mut current_user): Extension<AuthState>,
) -> Result<impl IntoResponse, impl IntoResponse> {
    if let Some(user) = current_user.get_user().await {
        Ok(Redirect::to(&format!("/user/{}", user.username)))
    } else {
        Err(error_page(&NotLoggedIn))
    }
}

async fn users(
    Extension(database): Extension<Database>,
    Extension(templates): Extension<Templates>,
) -> impl IntoResponse {
    const QUERY: &str = "SELECT username FROM users LIMIT 100;";

    let users: Vec<(String,)> = sqlx::query_as(QUERY).fetch_all(&database).await.unwrap();

    // This should be a no op right :)
    let users = users.into_iter().map(|(value,)| value).collect::<Vec<_>>();

    let mut context = Context::new();
    context.insert("users", &users);

    Html(templates.render("users", &context).unwrap())
}
