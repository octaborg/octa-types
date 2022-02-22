# Mina Snapp: Octa Types

This template uses TypeScript.

## How to build

```sh
npm run build
```

## How to run tests

```sh
npm run test
npm run testw # watch mode
```

## How to run coverage

```sh
npm run coverage
```

## How to install locally

### In this repository

```sh
npm run prepare
npm run build
```

### In target project directory

```
npm link /path/to/octa-types/directory
```

or

```
npm install /path/to/octa-types/directory
```

## Using

Simply

```javascript
import {
  AccountStatement,
  AccountStatementSigned,
  RequiredProofs,
  Transaction,
  TransactionalProof,
  TransactionType,
  RequiredProof,
  RequiredProofType,
} from 'octa-types';

// awesome code here
```

## License

[Apache-2.0](LICENSE)
