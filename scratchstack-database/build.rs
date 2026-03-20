fn main() {
    // Ensure we rebuild the MIGRATOR if any of the migration files change
    println!("cargo:rerun-if-changed=migrations");
}