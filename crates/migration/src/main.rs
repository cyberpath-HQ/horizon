use sea_orm_migration::prelude::*;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    unsafe {
        if !std::env::var("DATABASE_URL").is_ok() {
            std::env::set_var(
                "DATABASE_URL",
                format!(
                    "postgres://{}:{}@{}:{}/{}",
                    std::env::var("HORIZON_DATABASE_USER").unwrap(),
                    std::env::var("HORIZON_DATABASE_PASSWORD").unwrap(),
                    std::env::var("HORIZON_DATABASE_HOST").unwrap(),
                    std::env::var("HORIZON_DATABASE_PORT").unwrap(),
                    std::env::var("HORIZON_DATABASE_NAME").unwrap(),
                ),
            );
        }
    }
    cli::run_cli(migration::Migrator).await;
}
