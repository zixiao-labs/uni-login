use anyhow::Result;
use sqlx::SqlitePool;

pub type DbPool = SqlitePool;

/// Creates and returns a SQLite connection pool connected to the given database URL.
///
/// The pool is configured with a bounded number of connections to be used by the application.
///
/// # Examples
///
/// ```
/// # async fn _example() -> anyhow::Result<()> {
/// let pool = server::db::connect("sqlite::memory:").await?;
/// // use `pool` to run queries...
/// # Ok(())
/// # }
/// ```
///
/// # Returns
///
/// A `DbPool` connected to the provided `url`.
pub async fn connect(url: &str) -> Result<DbPool> {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(8)
        .connect(url)
        .await?;
    Ok(pool)
}

/// Runs SQLx migrations located in `./migrations` against the given database pool.
///
/// # Examples
///
/// ```no_run
/// # use server::db::run_migrations;
/// # use sqlx::SqlitePool;
/// # async fn __doc_example() -> anyhow::Result<()> {
/// let pool = SqlitePool::connect("sqlite::memory:").await?;
/// run_migrations(&pool).await?;
/// # Ok(())
/// # }
/// ```
///
/// # Returns
///
/// `Ok(())` if migrations were applied successfully, `Err` otherwise.
pub async fn run_migrations(pool: &DbPool) -> Result<()> {
    sqlx::migrate!("./migrations").run(pool).await?;
    Ok(())
}
