# Iris - Biometric Authentication on Stacks

Iris is a secure, decentralized biometric authentication system built on the Stacks blockchain. It enables users to register their biometric data on-chain and authenticate using cryptographic proofs, providing a privacy-preserving alternative to traditional authentication methods.

## Features

- **Decentralized Biometric Registration**: Store biometric hashes securely on the blockchain
- **Session-Based Authentication**: Generate time-limited authentication sessions
- **Rate Limiting**: Prevent brute force attacks with configurable rate limits
- **Privacy-First**: Only biometric hashes are stored, never raw biometric data
- **Admin Controls**: Contract owner can pause/unpause and configure parameters
- **Nonce-Based Security**: Prevent replay attacks with incremental nonces
- **User Management**: Users can update their biometric data and deactivate accounts

## Table of Contents

- [Architecture](#architecture)
- [Smart Contract Functions](#smart-contract-functions)
- [Installation](#installation)
- [Usage](#usage)
- [Security Considerations](#security-considerations)
- [API Reference](#api-reference)
- [Contributing](#contributing)

## Architecture

### Core Components

1. **Biometric Registry**: Stores user biometric hashes and public keys
2. **Authentication Sessions**: Manages temporary authentication tokens
3. **Rate Limiting**: Controls authentication attempt frequency
4. **Admin Controls**: Owner-only functions for contract management

### Data Structures

#### Biometric Registry
```clarity
{
  user: principal,
  biometric-hash: (buff 32),
  public-key: (buff 33),
  registered-at: uint,
  is-active: bool,
  nonce: uint
}
```

#### Authentication Sessions
```clarity
{
  session-id: (buff 32),
  user: principal,
  created-at: uint,
  expires-at: uint,
  is-valid: bool
}
```

## Smart Contract Functions

### Public Functions

#### Registration
- `register-biometric`: Register new biometric data
- `update-biometric`: Update existing biometric data
- `deactivate-user`: Deactivate user account

#### Authentication
- `authenticate`: Perform biometric authentication and create session
- `revoke-session`: Revoke an active authentication session

#### Admin Functions
- `pause-contract` / `unpause-contract`: Emergency controls
- `set-session-duration`: Configure session timeout
- `set-max-attempts`: Configure rate limiting
- `admin-deactivate-user`: Admin user deactivation

### Read-Only Functions

- `get-user-registration`: Get user registration details
- `get-session-info`: Get session information
- `is-session-valid`: Check if session is valid
- `get-contract-info`: Get contract configuration
- `check-rate-limit`: Check user's rate limit status

## Installation

### Prerequisites

- [Clarinet](https://docs.hiro.so/clarinet) CLI tool
- Node.js (v14 or higher)
- Stacks wallet for deployment

### Clone the Repository

```bash
git clone https://github.com/annaells/Iris.git
cd Iris
```

### Initialize Clarinet Project

```bash
clarinet new iris-project
cd iris-project
```

### Add the Contract

Copy the `iris.clar` file to the `contracts` directory.

### Configure Clarinet.toml

```toml
[project]
name = "iris"
description = "Biometric authentication system on Stacks"
authors = ["Your Name <your.email@example.com>"]
telemetry = false
cache_dir = ".cache"

[repl]
costs = true
parser = "v2"

[contracts.iris-biometric-auth]
path = "contracts/iris-biometric-auth.clar"
clarity_version = 2

[[repl.costs.mainnet]]
contract = "SP000000000000000000002Q6VF78.pox-4"
```

## Usage

### 1. Deploy the Contract

```bash
clarinet deploy --testnet
```

### 2. Register Biometric Data

```javascript
// Example using @stacks/transactions
import { makeContractCall, broadcastTransaction } from '@stacks/transactions';

const registerBiometric = async (biometricHash, publicKey) => {
  const txOptions = {
    contractAddress: 'ST1HTBVD3JG9C05J7HBJTHGR0GGW7KXW28M5JS8QE',
    contractName: 'iris-biometric-auth',
    functionName: 'register-biometric',
    functionArgs: [
      bufferCV(biometricHash),
      bufferCV(publicKey)
    ],
    senderKey: privateKey,
    network: network,
  };
  
  const transaction = await makeContractCall(txOptions);
  return await broadcastTransaction(transaction, network);
};
```

### 3. Authenticate User

```javascript
const authenticate = async (biometricHash, signature, sessionId) => {
  const txOptions = {
    contractAddress: 'ST1HTBVD3JG9C05J7HBJTHGR0GGW7KXW28M5JS8QE',
    contractName: 'iris-biometric-auth',
    functionName: 'authenticate',
    functionArgs: [
      bufferCV(biometricHash),
      bufferCV(signature),
      bufferCV(sessionId)
    ],
    senderKey: privateKey,
    network: network,
  };
  
  const transaction = await makeContractCall(txOptions);
  return await broadcastTransaction(transaction, network);
};
```

### 4. Check Session Validity

```javascript
const checkSession = async (sessionId) => {
  const result = await callReadOnlyFunction({
    contractAddress: 'ST1HTBVD3JG9C05J7HBJTHGR0GGW7KXW28M5JS8QE',
    contractName: 'iris-biometric-auth',
    functionName: 'is-session-valid',
    functionArgs: [bufferCV(sessionId)],
    network: network,
  });
  
  return result;
};
```

## Security Considerations

### Biometric Data Privacy

- **Never store raw biometric data** on-chain
- Use cryptographically secure hash functions (SHA-256 minimum)
- Implement proper key derivation for biometric templates

### Rate Limiting

- Default: 5 attempts per hour per user
- Configurable by contract owner
- Prevents brute force attacks

### Session Management

- Sessions expire after 1 hour by default
- Sessions can be revoked by users
- Expired sessions are automatically invalid

### Access Control

- Users can only modify their own data
- Admin functions restricted to contract owner
- Emergency pause functionality available

### Replay Attack Prevention

- Nonce-based system prevents replay attacks
- Nonces increment with each authentication
- Session IDs should be cryptographically random

## API Reference

### Error Codes

| Code | Constant | Description |
|------|----------|-------------|
| 100 | ERR-NOT-AUTHORIZED | Insufficient permissions |
| 101 | ERR-ALREADY-REGISTERED | User already registered |
| 102 | ERR-NOT-REGISTERED | User not found |
| 103 | ERR-INVALID-SIGNATURE | Invalid signature provided |
| 104 | ERR-SESSION-EXPIRED | Authentication session expired |
| 105 | ERR-INVALID-BIOMETRIC | Invalid biometric data |
| 106 | ERR-RATE-LIMITED | Too many attempts |

### Configuration Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| session-duration | 3600 blocks | Session validity period |
| max-attempts-per-hour | 5 | Maximum authentication attempts |
| contract-paused | false | Emergency pause state |

## Testing

### Run Unit Tests

```bash
clarinet test
```

### Test Coverage

The test suite covers:
- User registration flows
- Authentication scenarios
- Rate limiting functionality
- Session management
- Admin controls
- Error conditions

### Example Tests

```clarity
;; Test user registration
(define-public (test-register-biometric)
  (let
    ((result (contract-call? .iris-biometric-auth register-biometric 
               0x1234567890abcdef1234567890abcdef12345678 
               0x021234567890abcdef1234567890abcdef1234567890abcdef)))
    (asserts! (is-ok result) (err u1))
    (ok true)))

;; Test authentication
(define-public (test-authenticate)
  (let
    ((session-id 0xdeadbeefdeadbeefdeadbeefdeadbeef)
     (result (contract-call? .iris-biometric-auth authenticate
               0x1234567890abcdef1234567890abcdef12345678
               0x1234567890abcdef1234567890abcdef12345678901234567890abcdef1234567890
               session-id)))
    (asserts! (is-ok result) (err u2))
    (ok true)))
```

## Contributing

We welcome contributions to the Iris project! Please follow these guidelines:

### Development Process

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

### Code Standards

- Follow Clarity best practices
- Include comprehensive tests
- Document all public functions
- Use descriptive variable names
- Add error handling for edge cases

### Security Reviews

All security-related changes require:
- Thorough testing
- Code review by multiple maintainers
- Security audit for major changes

## 🔗 Links

- [Stacks Documentation](https://docs.stacks.co/)
- [Clarity Language Guide](https://docs.stacks.co/clarity)
- [Clarinet CLI](https://docs.hiro.so/clarinet)
- [Stacks.js Library](https://stacks.js.org/)