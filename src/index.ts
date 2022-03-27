import {
  Field,
  Scalar,
  Group,
  PublicKey,
  PrivateKey,
  UInt64,
  CircuitValue,
  prop,
  Bool,
  Int64,
  Signature,
  Circuit,
  arrayProp,
  isReady,
  JSONValue,
} from 'snarkyjs';

import { endOfMonth, startOfMonth, subMonths } from 'date-fns';

await isReady;

export function castField(f: Field | null): Field {
  if (f === null) {
    console.log('throwing error');
    throw Error();
  }
  return f;
}

export function castScalar(f: Scalar | null): Scalar {
  if (f === null) {
    throw Error();
  }
  return f;
}

export function castJSONValue(f: JSONValue | null): JSONValue {
  if (f === null) {
    throw Error();
  }
  return f;
}

// necessary definitions

interface TransactionTypeDefinition {
  purchase: String;
  deposit: String;
  transferIn: String;
  transaferOut: String;
}

interface TransactionDefinition {
  id: String;
  amount: String;
  transactionType: TransactionTypeDefinition;
  timestamp: String;
}

interface AccountStatementDefinition {
  id: String;
  balance: String;
  timestamp: String;
  fromTimestamp: String;
  toTimestamp: String;
  transactions: TransactionDefinition[];
}

interface SignatureDefinition {
  s: String;
  r: String;
}

interface GroupDefinition {
  x: String;
  y: String;
}

interface PublicKeyDefinition {
  g: GroupDefinition;
}

interface AccountStatementSignedDefinition {
  statement: AccountStatementDefinition;
  authorityPublicKey: PublicKeyDefinition;
  signature: SignatureDefinition;
}

// This is an enum written as a class, is there a way to just define an enum in a
// Snarky compatible way?
export class TransactionType extends CircuitValue {
  @prop purchase: Bool;
  @prop deposit: Bool;
  @prop transferIn: Bool;
  @prop transaferOut: Bool;

  constructor(
    purchase: Bool,
    deposit: Bool,
    transferIn: Bool,
    transaferOut: Bool
  ) {
    super();
    this.purchase = purchase;
    this.deposit = deposit;
    this.transferIn = transferIn;
    this.transaferOut = transaferOut;
  }

  isIncome(): Bool {
    return this.deposit.and(this.transferIn);
  }
}

export class Transaction extends CircuitValue {
  @prop id: Field;
  @prop amount: Int64;
  @prop transactionType: TransactionType;
  @prop timestamp: UInt64;

  constructor(
    id: Field,
    amount: Int64,
    transactionType: TransactionType,
    timestamp: UInt64
  ) {
    super();
    this.id = id;
    this.amount = amount;
    this.transactionType = transactionType;
    this.timestamp = timestamp;
  }
}

// normally only for this one we need to re-implement toJSON and fromJSON
// as only this one has an @arrayProp
export class AccountStatement extends CircuitValue {
  @prop id: Field;
  @prop balance: UInt64;
  @prop timestamp: UInt64;
  @prop fromTimestamp: UInt64;
  @prop toTimestamp: UInt64;
  @arrayProp(Transaction, 30) transactions: Transaction[];

  constructor(
    id: Field,
    balance: UInt64,
    timestamp: UInt64,
    from: UInt64,
    to: UInt64,
    transactions: Array<Transaction>
  ) {
    super();
    this.id = id;
    this.balance = balance;
    this.timestamp = timestamp;
    this.fromTimestamp = from;
    this.toTimestamp = to;
    this.transactions = transactions;
  }

  serialize(): Field[] {
    return this.toFields();
  }

  static deserialize(serialized: Field[]): AccountStatement {
    const deserialized = AccountStatement.ofFields(serialized);
    if (deserialized === null) {
      throw Error();
    }
    return deserialized;
  }

  sign(authorityPrivateKey: PrivateKey): Signature {
    const signature: Signature = Signature.create(
      authorityPrivateKey,
      this.toFields()
    );
    return signature;
  }

  verifySignature(authorityPublicKey: PublicKey, signature: Signature): Bool {
    return signature.verify(authorityPublicKey, this.toFields());
  }

  balanceAfterTX(j: number): Int64 {
    let balance: Int64 = new Int64(this.balance.value);
    for (let i = this.transactions.length - 1; i > j; i--) {
      const tx = this.transactions[i];
      const balance_sub = balance.sub(tx.amount);
      const balance_add = balance.add(tx.amount);
      balance = Circuit.if(tx.transactionType.purchase, balance_add, balance);
      balance = Circuit.if(tx.transactionType.deposit, balance_sub, balance);
      balance = Circuit.if(tx.transactionType.transferIn, balance_sub, balance);
      balance = Circuit.if(
        tx.transactionType.transaferOut,
        balance_add,
        balance
      );
    }
    return balance;
  }

  balanceIntegral(_t0: number, _tf: number): Int64 {
    let integral: Int64 = new Int64(new Field(0));
    let t0: UInt64 = new UInt64(new Field(_t0));
    let tf: UInt64 = new UInt64(new Field(_tf));
    for (let i = 0; i < this.transactions.length; i++) {
      const tx = this.transactions[i];
      const cond: Bool = t0.value
        .lte(tx.timestamp.value)
        .and(tf.value.gte(tx.timestamp.value));
      const balance: Int64 = this.balanceAfterTX(i);
      const dintegral: Int64 = integral.add(balance);
      integral = Circuit.if(cond, dintegral, integral);
    }
    return integral;
  }

  txCount(_t0: number, _tf: number): UInt64 {
    let n: UInt64 = new UInt64(new Field(0));
    const one: UInt64 = new UInt64(new Field(1));
    let t0: UInt64 = new UInt64(new Field(_t0));
    let tf: UInt64 = new UInt64(new Field(_tf));
    for (let i = 0; i < this.transactions.length; i++) {
      const tx = this.transactions[i];
      const cond: Bool = t0.value
        .lte(tx.timestamp.value)
        .and(tf.value.gte(tx.timestamp.value));
      const nn: UInt64 = n.add(one);
      n = Circuit.if(cond, nn, n);
    }
    return n;
  }
}

export class TransactionalProof {
  account: AccountStatement;
  requiredProofs: RequiredProofs;

  constructor(account: AccountStatement, requiredProofs: RequiredProofs) {
    this.account = account;
    this.requiredProofs = requiredProofs;
  }

  validate(authorityPublicKey: PublicKey, signature: Signature) {
    this.account.verifySignature(authorityPublicKey, signature);
    // TODO prevent same proof from being calculated multiple times
    const tautology: Bool = new Bool(true);
    let validated = new Bool(true);
    for (let i = 0; i < this.requiredProofs.requiredProofs.length; i++) {
      const valid_balance: Bool = this.validateAvgMonthlyBalanceProof(
        this.requiredProofs.requiredProofs[i]
      );
      const cond_balance: Bool = this.requiredProofs.requiredProofs[
        i
      ].requiredProofType.equals(RequiredProofType.avgMonthlyBalanceProof());
      const valid_income: Bool = this.validateAvgMonthlyIncomeProof(
        this.requiredProofs.requiredProofs[i]
      );
      const cond_income: Bool = this.requiredProofs.requiredProofs[
        i
      ].requiredProofType.equals(RequiredProofType.avgMonthlyIncomeProof());

      validated = Circuit.if(cond_balance, valid_balance, validated);
      validated = Circuit.if(cond_income, valid_income, validated);
    }
    validated.assertEquals(tautology);
  }

  validateAvgMonthlyBalanceProof(requiredProof: RequiredProof): Bool {
    const zero: Field = new Field(0);
    const numMonthsToTakeIntoAccount: number = 3;
    const sdelta: number = numMonthsToTakeIntoAccount * 30 * 24 * 60 * 60;
    // calculate the average monthly balance
    const today = new Date();
    const tf = Math.floor(today.getTime() / 1000);
    const t0: number = tf - sdelta;
    let S: Int64 = this.account.balanceIntegral(t0, tf);
    console.log(S.toString());
    let n: UInt64 = this.account.txCount(t0, tf);
    let L: Field = requiredProof.lowerBound.value.mul(n.value);
    let U: Field = requiredProof.upperBound.value.mul(n.value);
    const valid: Bool = L.lte(S.value)
      .and(U.gte(S.value))
      .and(n.value.gte(zero));
    return valid;
  }

  validateAvgMonthlyIncomeProof(requiredProof: RequiredProof): Bool {
    // calculate the average monthly income for the past 3 months
    const numMonthsToTakeIntoAccount = 3;
    let startOfMonths: Field[] = []; // starts of months to take into account in reverse chronological order.
    const today = new Date();
    for (let i = 0; i <= numMonthsToTakeIntoAccount; i++) {
      startOfMonths.push(
        new Field(startOfMonth(subMonths(today, i)).getTime())
      );
    }
    // calculate the avg income (Monthly incomes are calculated for later use)
    let monthlyIncomes = new Map<Field, Field>();
    let totalIncome = new Int64(Field.zero);
    for (let i = 0; i < this.account.transactions.length; i++) {
      let tx = this.account.transactions[i];
      for (let j = startOfMonths.length - 1; j > 0; j--) {
        totalIncome = Circuit.if(
          startOfMonths[j]
            .gte(tx.timestamp.value)
            .and(startOfMonths[j - 1].lt(tx.timestamp.value))
            .and(tx.transactionType.isIncome()),
          this.updateIncome(
            totalIncome,
            startOfMonths[j - 1],
            monthlyIncomes,
            tx
          ),
          totalIncome
        );
      }
    }

    let avgMonthlyIncome = new Int64(
      totalIncome.value.div(numMonthsToTakeIntoAccount)
    );
    return requiredProof.lowerBound.value
      .lte(avgMonthlyIncome.value)
      .and(requiredProof.upperBound.value.gt(avgMonthlyIncome.value));
  }

  updateIncome(
    totalIncome: Int64,
    month: Field,
    monthlyIncomes: Map<Field, Field>,
    tx: Transaction
  ): Int64 {
    let previous = monthlyIncomes.get(month);
    if (previous == null) {
      monthlyIncomes.set(month, tx.amount.value);
    } else {
      monthlyIncomes.set(month, previous.add(tx.amount.value));
    }
    return totalIncome.add(tx.amount);
  }
}

// This is an enum written as a class, is there a way to just define an enum in a
// Snarky compatible way?
export class RequiredProofType extends CircuitValue {
  // Calculated based on the amount of incoming
  // transactions over the past 3 months
  @prop avgMonthlyIncomeProof: Bool;

  // Calculated based on the end of month balance
  // for the past 3 months
  @prop avgMonthlyBalanceProof: Bool;

  private constructor(
    avgMonthlyIncomeProof: Bool,
    avgMonthlyBalanceProof: Bool
  ) {
    super();
    this.avgMonthlyBalanceProof = avgMonthlyBalanceProof;
    this.avgMonthlyIncomeProof = avgMonthlyIncomeProof;
  }

  static avgMonthlyIncomeProof(): RequiredProofType {
    return new RequiredProofType(new Bool(true), new Bool(false));
  }

  static avgMonthlyBalanceProof(): RequiredProofType {
    return new RequiredProofType(new Bool(false), new Bool(true));
  }
}

export class RequiredProof extends CircuitValue {
  // TODO can be encoded in a better way with a binary encoding
  @prop requiredProofType: RequiredProofType;
  @prop upperBound: Int64;
  @prop lowerBound: Int64;

  constructor(
    requiredProofType: RequiredProofType,
    upperBound: Int64,
    lowerBound: Int64
  ) {
    super();
    this.requiredProofType = requiredProofType;
    this.upperBound = upperBound;
    this.lowerBound = lowerBound;
  }
}

const MAX_REQUIRED_PROOFS = 10;
export class RequiredProofs extends CircuitValue {
  @arrayProp(RequiredProof, MAX_REQUIRED_PROOFS)
  requiredProofs: Array<RequiredProof>;

  constructor(requiredProofs: Array<RequiredProof>) {
    super();
    this.requiredProofs = requiredProofs;
  }
}

export function makeDummyPurchases(
  value: number,
  n: number,
  s: number,
  tstart: number,
  tdelta: number
): Transaction[] {
  let transactions: Transaction[] = [];
  for (let j = 0; j < n - 2; ++j) {
    transactions.push(
      new Transaction(
        new Field(s + 1 + j),
        new Int64(new Field(value)),
        new TransactionType(
          new Bool(true),
          new Bool(false),
          new Bool(false),
          new Bool(false)
        ),
        new UInt64(new Field(tstart + tdelta * j))
      )
    );
  }
  return transactions;
}

export async function generateDummyAccount(
  _id: number,
  income: number,
  daily_expense: number,
  final_balance: number
): Promise<AccountStatement> {
  const today = new Date();
  const now: number = Math.floor(today.getTime() / 1000);
  const snappPrivkey = PrivateKey.random();
  const months: number = 3;
  let start_id: number = 0;
  const delta: number = 24 * 60 * 60; // one day
  let pubkey = snappPrivkey.toPublicKey();
  let sign = Signature.create(snappPrivkey, [new Field(1)]);
  let transactions: Transaction[] = [];
  for (let j = months; j > 0; --j) {
    const s: number = now - j * 30 * 24 * 60 * 60;
    start_id = start_id + 1;
    transactions.push(
      new Transaction(
        new Field(start_id),
        new Int64(new Field(income)),
        new TransactionType(
          new Bool(false),
          new Bool(true),
          new Bool(true),
          new Bool(false)
        ),
        new UInt64(new Field(s))
      )
    );
    transactions = transactions.concat(
      makeDummyPurchases(
        daily_expense,
        30 - transactions.length,
        start_id,
        s,
        delta
      )
    );
    start_id = start_id + 30;
  }
  return Promise.resolve(
    new AccountStatement(
      new Field(_id),
      new UInt64(new Field(final_balance)),
      new UInt64(new Field(now)), // timestamp
      new UInt64(new Field(now - months * 30 * 24 * 60 * 60 - 1)),
      new UInt64(new Field(now + 1)),
      transactions
    )
  );
}
