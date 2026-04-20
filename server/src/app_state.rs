use std::sync::Arc;

use crate::{config::Config, db::DbPool, oauth::AuthCodeStore};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: DbPool,
    pub codes: Arc<AuthCodeStore>,
}
