use anyhow::Result;
use sqlx::SqlitePool;

pub type DbPool = SqlitePool;

pub async fn connect(url: &str) -> Result<DbPool> {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(8)
        .connect(url)
        .await?;
    Ok(pool)
}

pub async fn run_migrations(pool: &DbPool) -> Result<()> {
    sqlx::migrate!("./migrations").run(pool).await?;
    Ok(())
}
