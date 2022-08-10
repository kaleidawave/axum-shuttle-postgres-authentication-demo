use std::fs;

#[tokio::main]
async fn main() {
    println!("Spinning server up on http://localhost:3000");

    use sqlx::postgres::PgPoolOptions;

    let env = fs::read_to_string(".env").unwrap();
    let (key, database_url) = env.split_once('=').unwrap();

    assert_eq!(key, "DATABASE_URL");

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(database_url)
        .await
        .unwrap();

    let get_router = axum_postgres_authentication::get_router(pool);
    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(get_router.into_make_service())
        .await
        .unwrap();
}
