use sea_orm_migration::prelude::*;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    unsafe {
        if !std::env::var("DATABASE_URL").is_ok() {
            let db_user =
                std::env::var("HORIZON_DATABASE_USER").expect("HORIZON_DATABASE_USER environment variable must be set");
            let db_password = std::env::var("HORIZON_DATABASE_PASSWORD")
                .expect("HORIZON_DATABASE_PASSWORD environment variable must be set");
            let db_host =
                std::env::var("HORIZON_DATABASE_HOST").expect("HORIZON_DATABASE_HOST environment variable must be set");
            let db_port =
                std::env::var("HORIZON_DATABASE_PORT").expect("HORIZON_DATABASE_PORT environment variable must be set");
            let db_name =
                std::env::var("HORIZON_DATABASE_NAME").expect("HORIZON_DATABASE_NAME environment variable must be set");

            std::env::set_var(
                "DATABASE_URL",
                format!(
                    "postgres://{}:{}@{}:{}/{}",
                    db_user, db_password, db_host, db_port, db_name
                ),
            );
        }
    }
    cli::run_cli(migration::Migrator).await;
}
