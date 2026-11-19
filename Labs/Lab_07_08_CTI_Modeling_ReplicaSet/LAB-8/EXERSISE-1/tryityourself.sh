// Check current replica-set configuration
rs.status()

// Add the third MongoDB node as an arbiter
rs.addArb("mongo-rs0-3:27019")

// Verify replica-set members
rs.status().members.forEach(m =>
    print(m.name, m.stateStr, m.health)
)

// Verify that the third member is an arbiter
rs.conf().members.forEach(m =>
    print(m._id, m.host, "arbiterOnly:", m.arbiterOnly)
)