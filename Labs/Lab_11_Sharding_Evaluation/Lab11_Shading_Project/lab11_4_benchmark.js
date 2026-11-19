const dbx = db.getSiblingDB("cti_shard");
const accounts = dbx.accounts;

function runBenchmark(from, to, label) {
    const times = [];
    const totalStart = Date.now();

    for (let i = 0; i < 48; i++) {
        const session = db.getMongo().startSession();

        try {
            session.startTransaction({
                readConcern: { level: "snapshot" },
                writeConcern: { w: "majority" }
            });

            const coll = session.getDatabase("cti_shard").accounts;

            const debit = coll.updateOne(
                { account_id: from, balance: { $gte: 1 } },
                { $inc: { balance: -1 } }
            );

            if (debit.matchedCount !== 1) {
                throw new Error("Debit failed");
            }

            const credit = coll.updateOne(
                { account_id: to },
                { $inc: { balance: 1 } }
            );

            if (credit.matchedCount !== 1) {
                throw new Error("Credit failed");
            }

            session.commitTransaction();
        } catch (err) {
            try { session.abortTransaction(); } catch (e) {}
            print("Transaction failed: " + err);
            throw err;
        } finally {
            session.endSession();
        }
    }

    const totalMs = Date.now() - totalStart;

    return {
        test: label,
        transactions: 48,
        totalMs: totalMs,
        averageMs: totalMs / 48
    };
}

const sameShard = runBenchmark("acct-0001", "acct-0002", "Same-shard");
const crossShard = runBenchmark("acct-0001", "acct-0007", "Cross-shard");

printjson({
    sameShard: sameShard,
    crossShard: crossShard
});

print("Final account count: " + accounts.countDocuments());
