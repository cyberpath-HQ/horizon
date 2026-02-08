use auth::password::{hash_password, verify_password};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use secrecy::SecretString;

fn bench_hash_password(c: &mut Criterion) {
    c.bench_function("hash_password", |b| {
        let password = SecretString::from("TestPassword123!".to_string());
        b.iter(|| hash_password(black_box(&password), black_box(None)))
    });
}

fn bench_verify_password(c: &mut Criterion) {
    let password = SecretString::from("TestPassword123!".to_string());
    let hash = hash_password(&password, None).unwrap();
    c.bench_function("verify_password", |b| {
        b.iter(|| verify_password(black_box(&password), black_box(hash.expose_secret())))
    });
}

criterion_group!(benches, bench_hash_password, bench_verify_password);
criterion_main!(benches);