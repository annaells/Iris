;; Iris Biometric Authentication Smart Contract
;; A secure biometric authentication system built on Stacks blockchain

;; Error constants
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-ALREADY-REGISTERED (err u101))
(define-constant ERR-NOT-REGISTERED (err u102))
(define-constant ERR-INVALID-SIGNATURE (err u103))
(define-constant ERR-SESSION-EXPIRED (err u104))
(define-constant ERR-INVALID-BIOMETRIC (err u105))
(define-constant ERR-RATE-LIMITED (err u106))

;; Contract owner
(define-constant CONTRACT-OWNER tx-sender)

;; Data structures
(define-map biometric-registry
  { user: principal }
  {
    biometric-hash: (buff 32),
    public-key: (buff 33),
    registered-at: uint,
    is-active: bool,
    nonce: uint
  }
)

(define-map authentication-sessions
  { session-id: (buff 32) }
  {
    user: principal,
    created-at: uint,
    expires-at: uint,
    is-valid: bool
  }
)

(define-map rate-limits
  { user: principal }
  {
    last-attempt: uint,
    attempt-count: uint
  }
)

;; Contract configuration
(define-data-var session-duration uint u3600) ;; 1 hour in seconds
(define-data-var max-attempts-per-hour uint u5)
(define-data-var contract-paused bool false)

;; Read-only functions
(define-read-only (get-user-registration (user principal))
  (map-get? biometric-registry { user: user })
)

(define-read-only (get-session-info (session-id (buff 32)))
  (map-get? authentication-sessions { session-id: session-id })
)

(define-read-only (is-session-valid (session-id (buff 32)))
  (match (map-get? authentication-sessions { session-id: session-id })
    session
    (and
      (get is-valid session)
      (> (get expires-at session) block-height)
    )
    false
  )
)

(define-read-only (get-contract-info)
  {
    session-duration: (var-get session-duration),
    max-attempts-per-hour: (var-get max-attempts-per-hour),
    contract-paused: (var-get contract-paused)
  }
)

(define-read-only (check-rate-limit (user principal))
  (match (map-get? rate-limits { user: user })
    limit-info
    (let
      (
        (current-time block-height)
        (last-attempt (get last-attempt limit-info))
        (attempt-count (get attempt-count limit-info))
        (time-diff (- current-time last-attempt))
      )
      ;; Reset counter if more than 1 hour has passed
      (if (> time-diff u3600)
        { can-attempt: true, attempts-remaining: (var-get max-attempts-per-hour) }
        {
          can-attempt: (< attempt-count (var-get max-attempts-per-hour)),
          attempts-remaining: (- (var-get max-attempts-per-hour) attempt-count)
        }
      )
    )
    ;; No previous attempts
    { can-attempt: true, attempts-remaining: (var-get max-attempts-per-hour) }
  )
)

;; Private helper functions
(define-private (update-rate-limit (user principal))
  (let
    (
      (current-time block-height)
      (existing-limit (default-to 
        { last-attempt: u0, attempt-count: u0 }
        (map-get? rate-limits { user: user })
      ))
      (time-diff (- current-time (get last-attempt existing-limit)))
    )
    (map-set rate-limits
      { user: user }
      {
        last-attempt: current-time,
        attempt-count: (if (> time-diff u3600) u1 (+ (get attempt-count existing-limit) u1))
      }
    )
  )
)

(define-private (increment-nonce (user principal))
  (match (map-get? biometric-registry { user: user })
    user-data
    (map-set biometric-registry
      { user: user }
      (merge user-data { nonce: (+ (get nonce user-data) u1) })
    )
    false
  )
)

;; Public functions
(define-public (register-biometric (biometric-hash (buff 32)) (public-key (buff 33)))
  (begin
    ;; Check if contract is paused
    (asserts! (not (var-get contract-paused)) ERR-NOT-AUTHORIZED)
    
    ;; Check if user is already registered
    (asserts! (is-none (map-get? biometric-registry { user: tx-sender })) ERR-ALREADY-REGISTERED)
    
    ;; Validate inputs
    (asserts! (> (len biometric-hash) u0) ERR-INVALID-BIOMETRIC)
    (asserts! (> (len public-key) u0) ERR-INVALID-SIGNATURE)
    
    ;; Register the user
    (map-set biometric-registry
      { user: tx-sender }
      {
        biometric-hash: biometric-hash,
        public-key: public-key,
        registered-at: block-height,
        is-active: true,
        nonce: u0
      }
    )
    
    (ok true)
  )
)

(define-public (authenticate (biometric-hash (buff 32)) (signature (buff 65)) (session-id (buff 32)))
  (begin
    ;; Check if contract is paused
    (asserts! (not (var-get contract-paused)) ERR-NOT-AUTHORIZED)
    
    ;; Check rate limiting
    (let ((rate-check (check-rate-limit tx-sender)))
      (asserts! (get can-attempt rate-check) ERR-RATE-LIMITED)
    )
    
    ;; Update rate limit
    (update-rate-limit tx-sender)
    
    ;; Get user registration
    (match (map-get? biometric-registry { user: tx-sender })
      user-data
      (begin
        ;; Check if user is active
        (asserts! (get is-active user-data) ERR-NOT-AUTHORIZED)
        
        ;; Verify biometric hash matches
        (asserts! (is-eq biometric-hash (get biometric-hash user-data)) ERR-INVALID-BIOMETRIC)
        
        ;; Create authentication session
        (let
          (
            (expires-at (+ block-height (var-get session-duration)))
          )
          (map-set authentication-sessions
            { session-id: session-id }
            {
              user: tx-sender,
              created-at: block-height,
              expires-at: expires-at,
              is-valid: true
            }
          )
          
          ;; Increment user nonce
          (increment-nonce tx-sender)
          
          (ok { 
            session-id: session-id,
            expires-at: expires-at,
            user: tx-sender
          })
        )
      )
      ERR-NOT-REGISTERED
    )
  )
)

(define-public (revoke-session (session-id (buff 32)))
  (begin
    ;; Get session info
    (match (map-get? authentication-sessions { session-id: session-id })
      session
      (begin
        ;; Check if caller is session owner
        (asserts! (is-eq tx-sender (get user session)) ERR-NOT-AUTHORIZED)
        
        ;; Revoke session
        (map-set authentication-sessions
          { session-id: session-id }
          (merge session { is-valid: false })
        )
        
        (ok true)
      )
      ERR-NOT-REGISTERED
    )
  )
)

(define-public (update-biometric (new-biometric-hash (buff 32)) (new-public-key (buff 33)))
  (begin
    ;; Check if contract is paused
    (asserts! (not (var-get contract-paused)) ERR-NOT-AUTHORIZED)
    
    ;; Get existing registration
    (match (map-get? biometric-registry { user: tx-sender })
      user-data
      (begin
        ;; Check if user is active
        (asserts! (get is-active user-data) ERR-NOT-AUTHORIZED)
        
        ;; Validate inputs
        (asserts! (> (len new-biometric-hash) u0) ERR-INVALID-BIOMETRIC)
        (asserts! (> (len new-public-key) u0) ERR-INVALID-SIGNATURE)
        
        ;; Update registration
        (map-set biometric-registry
          { user: tx-sender }
          (merge user-data {
            biometric-hash: new-biometric-hash,
            public-key: new-public-key,
            nonce: (+ (get nonce user-data) u1)
          })
        )
        
        (ok true)
      )
      ERR-NOT-REGISTERED
    )
  )
)

(define-public (deactivate-user)
  (begin
    ;; Get user registration
    (match (map-get? biometric-registry { user: tx-sender })
      user-data
      (begin
        ;; Deactivate user
        (map-set biometric-registry
          { user: tx-sender }
          (merge user-data { is-active: false })
        )
        
        (ok true)
      )
      ERR-NOT-REGISTERED
    )
  )
)

;; Admin functions (only contract owner)
(define-public (pause-contract)
  (begin
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
    (var-set contract-paused true)
    (ok true)
  )
)

(define-public (unpause-contract)
  (begin
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
    (var-set contract-paused false)
    (ok true)
  )
)

(define-public (set-session-duration (new-duration uint))
  (begin
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
    (asserts! (> new-duration u0) ERR-NOT-AUTHORIZED)
    (var-set session-duration new-duration)
    (ok true)
  )
)

(define-public (set-max-attempts (new-max uint))
  (begin
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
    (asserts! (> new-max u0) ERR-NOT-AUTHORIZED)
    (var-set max-attempts-per-hour new-max)
    (ok true)
  )
)

(define-public (admin-deactivate-user (user principal))
  (begin
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
    
    ;; Validate user principal is not contract owner
    (asserts! (not (is-eq user CONTRACT-OWNER)) ERR-NOT-AUTHORIZED)
    
    ;; Get user registration
    (match (map-get? biometric-registry { user: user })
      user-data
      (begin
        ;; Deactivate user
        (map-set biometric-registry
          { user: user }
          (merge user-data { is-active: false })
        )
        
        (ok true)
      )
      ERR-NOT-REGISTERED
    )
  )
)