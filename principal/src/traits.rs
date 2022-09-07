pub trait ToArn {
    fn to_arn(&self) -> String;
}

pub trait TryToArn {
    fn try_to_arn(&self) -> Option<String>;
}

impl<T: ToArn> TryToArn for T {
    fn try_to_arn(&self) -> Option<String> {
        Some(self.to_arn())
    }
}
