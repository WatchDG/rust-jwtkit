use crate::enums::Algorithm;

pub struct HeaderBuilder {
    alg: Algorithm,
    typ: Option<String>,
    kid: Option<String>,
}

impl HeaderBuilder {
    pub fn new(alg: Algorithm) -> Self {
        Self {
            alg,
            typ: Some("JWT".to_string()),
            kid: None,
        }
    }

    pub fn typ(mut self, typ: impl Into<String>) -> Self {
        self.typ = Some(typ.into());
        self
    }

    pub fn kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }

    pub fn build(self) -> crate::Header {
        crate::Header {
            alg: self.alg,
            typ: self.typ,
            kid: self.kid,
        }
    }
}
