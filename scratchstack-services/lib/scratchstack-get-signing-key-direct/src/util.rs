use sqlx::any::AnyKind;

pub struct Binder {
    pub(crate) kind: AnyKind,
    pub(crate) next_id: usize,
}

impl Binder {
    pub(crate) fn new(kind: AnyKind) -> Self {
        Self {
            kind,
            next_id: 1,
        }
    }

    pub(crate) fn next_param_id(&mut self) -> String {
        let id = self.next_id;
        self.next_id += 1;

        match self.kind {
            AnyKind::Postgres => format!("${}", id),
            AnyKind::Mssql => format!("@p{}", id),
            _ => "?".into(),
        }
    }
}
