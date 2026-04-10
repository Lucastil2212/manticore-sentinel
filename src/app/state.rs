use crate::core::snapshot::SystemSnapshot;

#[derive(Default)]
pub struct AppState {
    pub latest: Option<SystemSnapshot>,
}
