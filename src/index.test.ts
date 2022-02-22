import {
  Field,
  UInt64,
  Int64,
  Bool,
  isReady,
  shutdown,
  Poseidon,
  PrivateKey,
  PublicKey,
  Signature,
} from 'snarkyjs';

import { AccountStatement, Transaction, TransactionType } from './index';

describe('index.ts', () => {
  describe('foo()', () => {
    beforeAll(async () => {
      await isReady;
    });
    afterAll(async () => {
      await shutdown();
    });
    it('should be correct', async () => {
      expect(Field(1).add(1)).toEqual(Field(2));
    });
  });
});

describe('serialization/deserialization', () => {
  beforeAll(async () => {
    await isReady;
  });
  afterAll(async () => {
    await shutdown();
  });
  it('should be isomorphic', async () => {
    const transactions: Transaction[] = [];
    for (let j = 0; j < 100; ++j) {
      transactions.push(
        new Transaction(
          new Field(1),
          new Int64(new Field(5000)), // TODO adjust timestamp to pass tests
          new TransactionType(
            new Bool(true),
            new Bool(false),
            new Bool(false),
            new Bool(false)
          ),
          new Int64(new Field(0))
        )
      );
    }
    const account: AccountStatement = new AccountStatement(
      new Field(0),
      new UInt64(new Field(10000)),
      new Int64(new Field(100)), // timestamp
      new Int64(new Field(100)),
      new Int64(new Field(100)),
      transactions
    );
    const serialized: Field[] = account.serialize();
    const deserialized: Field[] =
      AccountStatement.deserialize(serialized).serialize();
    const hash1 = Poseidon.hash(serialized);
    const hash2 = Poseidon.hash(deserialized);
    expect(hash1).toEqual(hash2);
  });
});

describe('producing and verifying signatures', () => {
  beforeAll(async () => {
    await isReady;
  });
  afterAll(async () => {
    await shutdown();
  });
  it('should be pass for valid signature and fail for tampered one', async () => {
    const transactions: Transaction[] = [];
    for (let j = 0; j < 100; ++j) {
      transactions.push(
        new Transaction(
          new Field(1),
          new Int64(new Field(5000)), // TODO adjust timestamp to pass tests
          new TransactionType(
            new Bool(true),
            new Bool(false),
            new Bool(false),
            new Bool(false)
          ),
          new Int64(new Field(0))
        )
      );
    }
    const account: AccountStatement = new AccountStatement(
      new Field(0),
      new UInt64(new Field(10000)),
      new Int64(new Field(100)), // timestamp
      new Int64(new Field(100)),
      new Int64(new Field(100)),
      transactions
    );
    const authorityPrivateKey: PrivateKey = PrivateKey.random();
    const signature: Signature = account.sign(authorityPrivateKey);
    const authorityPublicKey: PublicKey = authorityPrivateKey.toPublicKey();
    const is_valid: Bool = account.verifySignature(
      authorityPublicKey,
      signature
    );
    expect(is_valid.toBoolean()).toBe(true);
    const impostorPrivateKey: PrivateKey = PrivateKey.random();
    const impostorPublicKey: PublicKey = impostorPrivateKey.toPublicKey();
    const impostor_is_valid: Bool = account.verifySignature(
      impostorPublicKey,
      signature
    );
    expect(impostor_is_valid.toBoolean()).toBe(false);
  });
});
