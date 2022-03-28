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
  Circuit,
} from 'snarkyjs';

import {
  AccountStatement,
  RequiredProofs,
  Transaction,
  TransactionalProof,
  TransactionType,
  RequiredProof,
  RequiredProofType,
  generateDummyAccount,
} from './index';

describe('TransactionDataProof', () => {
  beforeAll(async () => {
    await isReady;
  });
  afterAll(async () => {
    await shutdown();
  });

  describe('validate()', () => {
    // TODO temporarily skipping as first need to fix validateAvgMonthlyBalanceProof
    it('Should succeed when average monthly income is sufficient', async () => {
      let account = await generateDummyAccount(0, 1000, 88, 5000);
      const tdp = new TransactionalProof(
        account,
        testRequiredProofsAVGIncome(900, 5000)
      );
      const authorityPrivateKey: PrivateKey = PrivateKey.random();
      const signature: Signature = account.sign(authorityPrivateKey);
      const authorityPublicKey: PublicKey = authorityPrivateKey.toPublicKey();
      await Circuit.runAndCheck(() =>
        Promise.resolve(() => tdp.validate(authorityPublicKey, signature))
      );
    });
    it('Should fail when average monthly income is not sufficient', async () => {
      let account = await generateDummyAccount(0, 1000, 88, 5000);
      const tdp = new TransactionalProof(
        account,
        testRequiredProofsAVGIncome(1001, 5000)
      );
      const authorityPrivateKey: PrivateKey = PrivateKey.random();
      const signature: Signature = account.sign(authorityPrivateKey);
      const authorityPublicKey: PublicKey = authorityPrivateKey.toPublicKey();
      const res = await Circuit.runAndCheck(() =>
        Promise.resolve(() => {
          try {
            tdp.validate(authorityPublicKey, signature);
          } catch (error) {
            return false;
          }
          return true;
        })
      );
      expect(res).toBe(false);
    });
    it('Should succeed when average balance is sufficient', async () => {
      let account = await generateDummyAccount(0, 1000, 88, 5000);
      const tdp = new TransactionalProof(
        account,
        testRequiredProofsAVGBalance(4000, 8000)
      );
      const authorityPrivateKey: PrivateKey = PrivateKey.random();
      const signature: Signature = account.sign(authorityPrivateKey);
      const authorityPublicKey: PublicKey = authorityPrivateKey.toPublicKey();
      await Circuit.runAndCheck(() =>
        Promise.resolve(() => tdp.validate(authorityPublicKey, signature))
      );
    });
    it('Should fail when average balance is not sufficient', async () => {
      let account = await generateDummyAccount(0, 1000, 88, 5000);
      const tdp = new TransactionalProof(
        account,
        testRequiredProofsAVGBalance(8000, 9000)
      );
      const authorityPrivateKey: PrivateKey = PrivateKey.random();
      const signature: Signature = account.sign(authorityPrivateKey);
      const authorityPublicKey: PublicKey = authorityPrivateKey.toPublicKey();
      const res = await Circuit.runAndCheck(() =>
        Promise.resolve(() => {
          try {
            tdp.validate(authorityPublicKey, signature);
          } catch (error) {
            return false;
          }
          return true;
        })
      );
      expect(res).toBe(false);
    });
  });

  describe('updateIncome()', () => {
    it('Should update the income correctly', async () => {
      let account = await testAccountStatement1();
      const tdp = new TransactionalProof(
        account,
        testRequiredProofsAVGIncome(1000, 2000)
      );
      let incomeMap = new Map();
      let totalIncome = await Circuit.runAndCheck(() =>
        Promise.resolve(() =>
          tdp.updateIncome(
            new Int64(new Field(0)),
            new Field(1),
            incomeMap,
            account.transactions[0]
          )
        )
      );
      expect(totalIncome).toEqual(account.transactions[0].amount);
    });
  });

  describe('arithmatic', () => {
    it.skip('Should calculate division correctly', async () => {
      expect(new Field(3000).div(3)).toEqual(new Field(1000)); // works
      expect(new Field(3).div(3)).toEqual(new Field(1)); // works
      expect(new Field(10).div(3)).toEqual(new Field(4)); // 9649340769776349618630915417390658987787685493980520238651558921449989211779
      expect(new Field(5000).div(3)).toEqual(new Field(0)); // 9649340769776349618630915417390658987787685493980520238651558921449989211779
    });
    it('Should compute balance after ith transaction', async () => {
      const dummy: AccountStatement = makeDummy();
      expect(dummy.balanceAfterTX(2)).toEqual(new Int64(new Field(10000)));
      expect(dummy.balanceAfterTX(1)).toEqual(new Int64(new Field(9999)));
      expect(dummy.balanceAfterTX(0)).toEqual(new Int64(new Field(9998)));
    });
    it('Should integrate account balances within given interval range', async () => {
      const dummy: AccountStatement = makeDummy();
      expect(dummy.balanceIntegral(0, 4)).toEqual(
        new Int64(new Field(10000 + 9999 + 9998))
      );
      expect(dummy.balanceIntegral(1, 3)).toEqual(
        new Int64(new Field(10000 + 9999 + 9998))
      );
      expect(dummy.balanceIntegral(2, 3)).toEqual(
        new Int64(new Field(10000 + 9999))
      );
      expect(dummy.balanceIntegral(3, 3)).toEqual(new Int64(new Field(10000)));
      expect(dummy.balanceIntegral(2, 2)).toEqual(new Int64(new Field(9999)));
      expect(dummy.balanceIntegral(1, 1)).toEqual(new Int64(new Field(9998)));
    });
    it('Should count transactions within given interval range', async () => {
      const dummy: AccountStatement = makeDummy();
      expect(dummy.txCount(0, 4)).toEqual(new Int64(new Field(3)));
      expect(dummy.txCount(1, 3)).toEqual(new Int64(new Field(3)));
      expect(dummy.txCount(2, 3)).toEqual(new Int64(new Field(2)));
      expect(dummy.txCount(3, 3)).toEqual(new Int64(new Field(1)));
      expect(dummy.txCount(2, 2)).toEqual(new Int64(new Field(1)));
      expect(dummy.txCount(1, 1)).toEqual(new Int64(new Field(1)));
    });
  });
});

function testRequiredProofsAVGIncome(
  _min: number,
  _max: number
): RequiredProofs {
  return new RequiredProofs([
    new RequiredProof(
      RequiredProofType.avgMonthlyIncomeProof(),
      new Int64(new Field(_max)),
      new Int64(new Field(_min))
    ),
  ]);
}

function testRequiredProofsAVGBalance(
  _min: number,
  _max: number
): RequiredProofs {
  return new RequiredProofs([
    new RequiredProof(
      RequiredProofType.avgMonthlyBalanceProof(),
      new Int64(new Field(_max)),
      new Int64(new Field(_min))
    ),
  ]);
}

function makeDummy(): AccountStatement {
  return new AccountStatement(
    new Field(0),
    new UInt64(new Field(10000)),
    new UInt64(new Field(100)), // timestamp
    new UInt64(new Field(100)),
    new UInt64(new Field(100)),
    [
      new Transaction(
        new Field(1),
        new Int64(new Field(1)),
        new TransactionType(
          new Bool(false),
          new Bool(true),
          new Bool(false),
          new Bool(false)
        ),
        new UInt64(new Field(1))
      ),
      new Transaction(
        new Field(2),
        new Int64(new Field(1)),
        new TransactionType(
          new Bool(false),
          new Bool(true),
          new Bool(false),
          new Bool(false)
        ),
        new UInt64(new Field(2))
      ),
      new Transaction(
        new Field(3),
        new Int64(new Field(1)),
        new TransactionType(
          new Bool(false),
          new Bool(true),
          new Bool(false),
          new Bool(false)
        ),
        new UInt64(new Field(3))
      ),
    ]
  );
}

function makeOtherDummy(): AccountStatement {
  return new AccountStatement(
    new Field(0),
    new UInt64(new Field(10000)),
    new UInt64(new Field(100)), // timestamp
    new UInt64(new Field(100)),
    new UInt64(new Field(100)),
    [
      new Transaction(
        new Field(1),
        new Int64(new Field(1)),
        new TransactionType(
          new Bool(false),
          new Bool(true),
          new Bool(false),
          new Bool(false)
        ),
        new UInt64(new Field(1))
      ),
      new Transaction(
        new Field(2),
        new Int64(new Field(1)),
        new TransactionType(
          new Bool(false),
          new Bool(true),
          new Bool(false),
          new Bool(false)
        ),
        new UInt64(new Field(18))
      ),
      new Transaction(
        new Field(3),
        new Int64(new Field(1)),
        new TransactionType(
          new Bool(false),
          new Bool(true),
          new Bool(true),
          new Bool(false)
        ),
        new UInt64(new Field(3))
      ),
    ]
  );
}

describe('deep equality test', () => {
  beforeAll(async () => {
    await isReady;
  });
  afterAll(async () => {
    await shutdown();
  });
  it('of TransactionType', async () => {
    const first: TransactionType = new TransactionType(
      new Bool(true),
      new Bool(false),
      new Bool(false),
      new Bool(false)
    );
    const other: TransactionType = new TransactionType(
      new Bool(true),
      new Bool(false),
      new Bool(false),
      new Bool(false)
    );
    const yetother: TransactionType = new TransactionType(
      new Bool(true),
      new Bool(false),
      new Bool(true),
      new Bool(false)
    );
    expect(first).toEqual(other);
    expect(first).not.toEqual(yetother);
  });
  it('of Transaction', async () => {
    const first: Transaction = new Transaction(
      new Field(2),
      new Int64(new Field(1)),
      new TransactionType(
        new Bool(false),
        new Bool(true),
        new Bool(false),
        new Bool(false)
      ),
      new UInt64(new Field(2))
    );
    const other: Transaction = new Transaction(
      new Field(2),
      new Int64(new Field(1)),
      new TransactionType(
        new Bool(false),
        new Bool(true),
        new Bool(false),
        new Bool(false)
      ),
      new UInt64(new Field(2))
    );
    const yetother: Transaction = new Transaction(
      new Field(3),
      new Int64(new Field(2)),
      new TransactionType(
        new Bool(false),
        new Bool(true),
        new Bool(true),
        new Bool(false)
      ),
      new UInt64(new Field(1))
    );
    expect(first).toEqual(other);
    expect(first).not.toEqual(yetother);
  });
  it('of AccountStatement', async () => {
    const first: AccountStatement = makeDummy();
    const other: AccountStatement = makeDummy();
    const yetother: AccountStatement = makeOtherDummy();
    expect(first).toEqual(other);
    expect(first).not.toEqual(yetother);
  });
});

async function testAccountStatement1(): Promise<AccountStatement> {
  const snappPrivkey = PrivateKey.random();
  let pubkey = snappPrivkey.toPublicKey();
  let sign = Signature.create(snappPrivkey, [new Field(1)]);
  return Promise.resolve(
    new AccountStatement(
      new Field(0),
      new UInt64(new Field(10000)),
      new UInt64(new Field(100)), // timestamp
      new UInt64(new Field(100)),
      new UInt64(new Field(100)),
      [
        new Transaction(
          new Field(1),
          new Int64(new Field(5000)),
          new TransactionType(
            new Bool(false),
            new Bool(true),
            new Bool(false),
            new Bool(false)
          ),
          new UInt64(new Field(new Date().getTime() - 2592000000))
        ),
      ]
    )
  );
}

describe('serialization/deserialization', () => {
  beforeAll(async () => {
    await isReady;
  });
  afterAll(async () => {
    await shutdown();
  });
  it('should be isomorphic', async () => {
    const transactions: Transaction[] = [];
    for (let j = 0; j < 30; ++j) {
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
          new UInt64(new Field(0))
        )
      );
    }
    const account: AccountStatement = new AccountStatement(
      new Field(0),
      new UInt64(new Field(10000)),
      new UInt64(new Field(100)), // timestamp
      new UInt64(new Field(100)),
      new UInt64(new Field(100)),
      transactions
    );
    const serialized: Field[] = account.serialize();
    const deserialized: AccountStatement =
      AccountStatement.deserialize(serialized);
    expect(account).toEqual(deserialized);
    const serialized_again: Field[] = deserialized.serialize();
    const hash1 = Poseidon.hash(serialized);
    const hash2 = Poseidon.hash(serialized_again);
    expect(hash1).toEqual(hash2);
  });
  it('should be isomorphic for dummy account as well', async () => {
    const account: AccountStatement = await generateDummyAccount(
      0,
      1000,
      10,
      10000
    );
    const serialized: Field[] = account.serialize();
    const deserialized: AccountStatement =
      AccountStatement.deserialize(serialized);
    expect(account).toEqual(deserialized);
    expect(account.transactions.length).toEqual(30);

    const serialized_again: Field[] =
      AccountStatement.deserialize(serialized).serialize();
    const hash1 = Poseidon.hash(serialized);
    const hash2 = Poseidon.hash(serialized_again);
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
          new UInt64(new Field(0))
        )
      );
    }
    const account: AccountStatement = new AccountStatement(
      new Field(0),
      new UInt64(new Field(10000)),
      new UInt64(new Field(100)), // timestamp
      new UInt64(new Field(100)),
      new UInt64(new Field(100)),
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
