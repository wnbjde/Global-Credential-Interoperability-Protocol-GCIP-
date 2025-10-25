(define-constant ERR-NOT-AUTHORIZED u100)
(define-constant ERR-INVALID-CREDENTIAL u101)
(define-constant ERR-REVOKED u102)
(define-constant ERR-INVALID-ISSUER u103)
(define-constant ERR-INVALID-HASH u104)
(define-constant ERR-INVALID-FEE u105)
(define-constant ERR-VERIFICATION-FAILED u106)
(define-constant ERR-CREDENTIAL-EXPIRED u107)
(define-constant ERR-INVALID-EXPIRATION u108)
(define-constant ERR-INVALID-SIGNATURE u109)
(define-constant ERR-AUDIT-LOG-FAIL u110)
(define-constant ERR-INVALID-VERIFIER u111)
(define-constant ERR-FEE-TRANSFER-FAIL u112)
(define-constant ERR-INVALID-BATCH-SIZE u113)
(define-constant ERR-BATCH-VERIFICATION-FAIL u114)
(define-constant ERR-INVALID-CREDENTIAL-TYPE u115)
(define-constant ERR-INVALID-STATUS u116)
(define-constant ERR-MAX-VERIFICATIONS-EXCEEDED u117)
(define-constant ERR-INVALID-TIMESTAMP u118)
(define-constant ERR-AUTHORITY-NOT-VERIFIED u119)
(define-constant ERR-INVALID-MIN-FEE u120)

(define-data-var next-verification-id uint u0)
(define-data-var min-verification-fee uint u100)
(define-data-var max-batch-size uint u10)
(define-data-var authority-contract (optional principal) none)
(define-data-var verification-count uint u0)
(define-data-var max-verifications uint u10000)

(define-map verifications
  uint
  {
    credential-id: uint,
    issuer: principal,
    hash: (buff 32),
    verifier: principal,
    timestamp: uint,
    status: bool,
    expiration: uint,
    signature: (buff 65),
    credential-type: (string-utf8 50),
    fee-paid: uint
  }
)

(define-map verification-by-credential
  uint
  uint
)

(define-map batch-verifications
  uint
  (list 10 uint)
)

(define-read-only (get-verification (id uint))
  (map-get? verifications id)
)

(define-read-only (get-verification-by-credential (cred-id uint))
  (map-get? verification-by-credential cred-id)
)

(define-read-only (is-credential-verified (cred-id uint))
  (is-some (map-get? verification-by-credential cred-id))
)

(define-private (validate-credential-id (id uint))
  (if (> id u0)
      (ok true)
      (err ERR-INVALID-CREDENTIAL))
)

(define-private (validate-issuer (issuer principal))
  (if (not (is-eq issuer tx-sender))
      (ok true)
      (err ERR-INVALID-ISSUER))
)

(define-private (validate-hash (hash (buff 32)))
  (if (is-eq (len hash) u32)
      (ok true)
      (err ERR-INVALID-HASH))
)

(define-private (validate-fee (fee uint))
  (if (>= fee (var-get min-verification-fee))
      (ok true)
      (err ERR-INVALID-FEE))
)

(define-private (validate-expiration (exp uint))
  (if (> exp block-height)
      (ok true)
      (err ERR-INVALID-EXPIRATION))
)

(define-private (validate-signature (sig (buff 65)))
  (if (is-eq (len sig) u65)
      (ok true)
      (err ERR-INVALID-SIGNATURE))
)

(define-private (validate-credential-type (type (string-utf8 50)))
  (if (or (is-eq type "education") (is-eq type "certification") (is-eq type "work-history"))
      (ok true)
      (err ERR-INVALID-CREDENTIAL-TYPE))
)

(define-private (validate-timestamp (ts uint))
  (if (>= ts block-height)
      (ok true)
      (err ERR-INVALID-TIMESTAMP))
)

(define-private (validate-batch-size (size uint))
  (if (and (> size u0) (<= size (var-get max-batch-size)))
      (ok true)
      (err ERR-INVALID-BATCH-SIZE))
)

(define-private (validate-principal (p principal))
  (if (not (is-eq p 'SP000000000000000000002Q6VF78))
      (ok true)
      (err ERR-NOT-AUTHORIZED))
)

(define-public (set-authority-contract (contract-principal principal))
  (begin
    (try! (validate-principal contract-principal))
    (asserts! (is-none (var-get authority-contract)) (err ERR-AUTHORITY-NOT-VERIFIED))
    (var-set authority-contract (some contract-principal))
    (ok true)
  )
)

(define-public (set-min-verification-fee (new-fee uint))
  (begin
    (asserts! (>= new-fee u0) (err ERR-INVALID-MIN-FEE))
    (asserts! (is-some (var-get authority-contract)) (err ERR-AUTHORITY-NOT-VERIFIED))
    (var-set min-verification-fee new-fee)
    (ok true)
  )
)

(define-public (set-max-batch-size (new-size uint))
  (begin
    (asserts! (> new-size u0) (err ERR-INVALID-BATCH-SIZE))
    (asserts! (is-some (var-get authority-contract)) (err ERR-AUTHORITY-NOT-VERIFIED))
    (var-set max-batch-size new-size)
    (ok true)
  )
)

(define-public (verify-credential
  (credential-id uint)
  (issuer principal)
  (credential-hash (buff 32))
  (expiration uint)
  (signature (buff 65))
  (credential-type (string-utf8 50))
)
  (let (
        (next-id (var-get next-verification-id))
        (authority (var-get authority-contract))
        (issuer-data (contract-call? .IssuerRegistryContract get-issuer issuer))
        (credential-data (contract-call? .CredentialHolderContract get-credential-details credential-id))
        (revocation-status (contract-call? .RevocationContract is-revoked credential-id))
      )
    (try! (validate-credential-id credential-id))
    (try! (validate-issuer issuer))
    (try! (validate-hash credential-hash))
    (try! (validate-expiration expiration))
    (try! (validate-signature signature))
    (try! (validate-credential-type credential-type))
    (asserts! (is-some issuer-data) (err ERR-INVALID-ISSUER))
    (asserts! (is-some credential-data) (err ERR-INVALID-CREDENTIAL))
    (asserts! (is-eq (get hash credential-data) credential-hash) (err ERR-INVALID-HASH))
    (asserts! (not revocation-status) (err ERR-REVOKED))
    (asserts! (< (var-get verification-count) (var-get max-verifications)) (err ERR-MAX-VERIFICATIONS-EXCEEDED))
    (map-set verifications next-id
      {
        credential-id: credential-id,
        issuer: issuer,
        hash: credential-hash,
        verifier: tx-sender,
        timestamp: block-height,
        status: true,
        expiration: expiration,
        signature: signature,
        credential-type: credential-type,
        fee-paid: u0
      }
    )
    (map-set verification-by-credential credential-id next-id)
    (try! (contract-call? .AuditLogContract log-verification credential-id tx-sender block-height))
    (var-set next-verification-id (+ next-id u1))
    (var-set verification-count (+ (var-get verification-count) u1))
    (print { event: "credential-verified", id: next-id })
    (ok next-id)
  )
)

(define-public (verify-credential-with-fee
  (credential-id uint)
  (issuer principal)
  (credential-hash (buff 32))
  (expiration uint)
  (signature (buff 65))
  (credential-type (string-utf8 50))
  (fee uint)
)
  (let (
        (authority-recipient (unwrap! (var-get authority-contract) (err ERR-AUTHORITY-NOT-VERIFIED)))
      )
    (try! (validate-fee fee))
    (try! (stx-transfer? fee tx-sender authority-recipient))
    (let ((result (try! (verify-credential credential-id issuer credential-hash expiration signature credential-type))))
      (map-set verifications (get id result)
        (merge (unwrap-panic (map-get? verifications (get id result)))
          { fee-paid: fee }
        )
      )
      (ok result)
    )
  )
)

(define-public (batch-verify-credentials
  (credentials (list 10 { cred-id: uint, issuer: principal, hash: (buff 32), exp: uint, sig: (buff 65), type: (string-utf8 50) }))
)
  (let (
        (batch-id (var-get next-verification-id))
        (len (len credentials))
        (results (fold process-batch-verify credentials (ok (list))))
      )
    (try! (validate-batch-size len))
    (match results
      res
        (begin
          (map-set batch-verifications batch-id res)
          (var-set next-verification-id (+ batch-id u1))
          (print { event: "batch-verified", id: batch-id })
          (ok batch-id)
        )
      err
        (err ERR-BATCH-VERIFICATION-FAIL)
    )
  )
)

(define-private (process-batch-verify
  (item { cred-id: uint, issuer: principal, hash: (buff 32), exp: uint, sig: (buff 65), type: (string-utf8 50) })
  (acc (response (list 10 uint) uint))
)
  (match acc
    res-list
      (match (verify-credential (get cred-id item) (get issuer item) (get hash item) (get exp item) (get sig item) (get type item))
        success (ok (append res-list success))
        error (err ERR-VERIFICATION-FAILED)
      )
    err
      (err err)
  )
)

(define-public (get-verification-count)
  (ok (var-get verification-count))
)

(define-public (check-credential-verified (cred-id uint))
  (ok (is-credential-verified cred-id))
)