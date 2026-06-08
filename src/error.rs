#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("record not found")]
    NotFound,
    #[error("unique constraint violation: {0}")]
    Conflict(String),
    #[error("foreign key constraint violation: {0}")]
    ForeignKeyViolation(String),
    #[error("database error: {0}")]
    Database(String),
    #[error("migration error: {0}")]
    Migration(String),
    #[error("corrupt stored data: {0}")]
    Corrupt(String),

    #[error("the license offer has expired; begin a new enrollment")]
    OfferExpired,
    #[error("no enrollment session found with the given identifier")]
    SessionNotFound,
    #[error("invalid state machine transition: {0}")]
    InvalidTransition(String),
    #[error("all seat slots for this license are occupied")]
    SeatLimitReached,
    #[error("payment intent is not in the RequiresCapture state")]
    PaymentNotHeld,
    #[error("TSA timestamping failed after all retries: {0}")]
    TsaFailed(String),
    #[error("payment capture failed: {0}")]
    PaymentCaptureFailed(String),
    #[error("payment cancellation failed: {0}")]
    PaymentCancelFailed(String),
    #[error("revocation is not supported for air-gapped licenses")]
    RevocationNotSupported,
    #[error("client version {got} is below the required minimum {required}")]
    ClientVersionRejected { required: String, got: String },
    #[error("offer nonce in receipt does not match the session")]
    OfferNonceMismatch,
    #[error("consent record is invalid: {0}")]
    ConsentInvalid(String),
    #[error("a transfer request is already pending for this license")]
    TransferAlreadyPending,
    #[error("the customer's signature on the receipt is invalid")]
    InvalidReceiptSignature,
    #[error("product is not accepting new enrollments")]
    ProductInactive,
    #[error("no active fingerprint binding found for this hardware on this license")]
    BindingNotFound,
    #[error("secret wrapping failed: {0}")]
    SecretWrappingFailed(String),
    #[error("no payment provider configured for this product")]
    NoPaymentProvider,

    // product activation gate
    #[error("product cannot be activated: term declarations are missing or incomplete")]
    TermDeclarationsMissing,
    #[error(
        "product cannot be activated: no terms document with acceptable validation status exists"
    )]
    TermsDocumentNotReady,
    #[error("product cannot be activated: customer fields configuration is missing or invalid")]
    CustomerFieldsInvalid,
    #[error("product cannot be activated: no terms document has been activated yet")]
    TermsDocumentNotActivated,

    // terms document lifecycle
    #[error(
        "terms document has unresolved conflicts; mandatory blocks must be restored before activation"
    )]
    TermsConflictsUnresolved,
    #[error("terms document has unacknowledged warnings; acknowledge before activating")]
    TermsWarningsUnacknowledged,

    // term declaration field values
    #[error("invalid term declaration value for field '{field}': '{value}'")]
    InvalidTermDeclarationValue { field: &'static str, value: String },

    // customer field configuration
    #[error("national_id field only accepts gdpr_basis = LegalObligation")]
    NationalIdRequiresLegalObligation,
    #[error("gdpr_basis LegitimateInterest requires a non-empty purpose_description")]
    LegitimateInterestRequiresPurpose,
    #[error("unknown customer field key: '{0}'")]
    UnknownFieldKey(String),
    #[error("field '{field}' has invalid value: {reason}")]
    InvalidFieldValue { field: String, reason: String },

    // upgrade policy
    #[error("version string '{0}' is not a valid semver version or wildcard pattern")]
    InvalidVersionPattern(String),
}

#[cfg(feature = "storage-sqlite")]
impl From<sqlx::Error> for Error {
    fn from(e: sqlx::Error) -> Self {
        match &e {
            sqlx::Error::RowNotFound => Error::NotFound,
            sqlx::Error::Database(db) => {
                let msg = db.message().to_string();
                if db.is_unique_violation() {
                    Error::Conflict(msg)
                } else if db.is_foreign_key_violation() || msg.contains("FOREIGN KEY") {
                    Error::ForeignKeyViolation(msg)
                } else {
                    Error::Database(msg)
                }
            }
            _ => Error::Database(e.to_string()),
        }
    }
}

#[cfg(all(feature = "storage-postgres", not(feature = "storage-sqlite")))]
impl From<sqlx::Error> for Error {
    fn from(e: sqlx::Error) -> Self {
        match &e {
            sqlx::Error::RowNotFound => Error::NotFound,
            sqlx::Error::Database(db) => {
                let msg = db.message().to_string();
                if db.is_unique_violation() {
                    Error::Conflict(msg)
                } else if db.is_foreign_key_violation() {
                    Error::ForeignKeyViolation(msg)
                } else {
                    Error::Database(msg)
                }
            }
            _ => Error::Database(e.to_string()),
        }
    }
}
