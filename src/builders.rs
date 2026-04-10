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

pub struct PayloadBuilder {
    iss: Option<String>,
    sub: Option<String>,
    aud: Option<String>,
    exp: Option<u64>,
    nbf: Option<u64>,
    iat: Option<u64>,
    jti: Option<String>,
}

impl PayloadBuilder {
    pub fn new() -> Self {
        Self {
            iss: None,
            sub: None,
            aud: None,
            exp: None,
            nbf: None,
            iat: None,
            jti: None,
        }
    }

    pub fn iss(mut self, iss: impl Into<String>) -> Self {
        self.iss = Some(iss.into());
        self
    }

    pub fn sub(mut self, sub: impl Into<String>) -> Self {
        self.sub = Some(sub.into());
        self
    }

    pub fn aud(mut self, aud: impl Into<String>) -> Self {
        self.aud = Some(aud.into());
        self
    }

    pub fn exp(mut self, exp: u64) -> Self {
        self.exp = Some(exp);
        self
    }

    pub fn nbf(mut self, nbf: u64) -> Self {
        self.nbf = Some(nbf);
        self
    }

    pub fn iat(mut self, iat: u64) -> Self {
        self.iat = Some(iat);
        self
    }

    pub fn jti(mut self, jti: impl Into<String>) -> Self {
        self.jti = Some(jti.into());
        self
    }

    pub fn build(self) -> crate::Payload {
        crate::Payload {
            iss: self.iss,
            sub: self.sub,
            aud: self.aud,
            exp: self.exp,
            nbf: self.nbf,
            iat: self.iat,
            jti: self.jti,
        }
    }
}

impl Default for PayloadBuilder {
    fn default() -> Self {
        Self::new()
    }
}
