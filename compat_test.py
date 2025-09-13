# compat_test.py
# Verifies BECS compatibility rules against the table.

BLOOD_TYPES = ["O-", "O+", "A-", "A+", "B-", "B+", "AB-", "AB+"]

# Expected "Receive Blood From" based on the table you showed
expected_donors_for_recipient = {
    "A+":  ["A+", "A-", "O+", "O-"],
    "O+":  ["O+", "O-"],
    "B+":  ["B+", "B-", "O+", "O-"],
    "AB+": ["O-", "O+", "A-", "A+", "B-", "B+", "AB-", "AB+"],  # Everyone
    "A-":  ["A-", "O-"],
    "O-":  ["O-"],
    "B-":  ["B-", "O-"],
    "AB-": ["AB-", "A-", "B-", "O-"],
}

# Expected "Donate Blood To" from the same table
expected_recipients_for_donor = {
    "A+":  ["A+", "AB+"],
    "O+":  ["O+", "A+", "B+", "AB+"],
    "B+":  ["B+", "AB+"],
    "AB+": ["AB+"],
    "A-":  ["A+", "A-", "AB+", "AB-"],
    "O-":  ["O-", "O+", "A-", "A+", "B-", "B+", "AB-", "AB+"],  # Everyone
    "B-":  ["B+", "B-", "AB+", "AB-"],
    "AB-": ["AB+", "AB-"],
}

# === YOUR APP'S MAP (from your code) ===
donors_that_can_supply = {
    "O-":  ["O-"],
    "O+":  ["O-", "O+"],
    "A-":  ["O-", "A-"],
    "A+":  ["O-", "O+", "A-", "A+"],
    "B-":  ["O-", "B-"],
    "B+":  ["O-", "O+", "B-", "B+"],
    "AB-": ["O-", "A-", "B-", "AB-"],
    "AB+": ["O-", "O+", "A-", "A+", "B-", "B+", "AB-", "AB+"],
}

def normalize(lst):
    return sorted(lst)

def invert(donors_for_recipient):
    donate_to = {bt: [] for bt in BLOOD_TYPES}
    for recipient, donors in donors_for_recipient.items():
        for d in donors:
            donate_to[d].append(recipient)
    return {k: normalize(v) for k, v in donate_to.items()}

def assert_equal(label, got, exp):
    g, e = normalize(got), normalize(exp)
    if g != e:
        print(f"❌ {label} mismatch:\n  got: {g}\n  expected: {e}")
    else:
        print(f"✅ {label} OK")

if __name__ == "__main__":
    # Check Receive-from
    for r in BLOOD_TYPES:
        assert_equal(f"Receive-from {r}", donors_that_can_supply[r], expected_donors_for_recipient[r])

    # Check Donate-to (derived from your map)
    derived_donate_to = invert(donors_that_can_supply)
    for d in BLOOD_TYPES:
        assert_equal(f"Donate-to {d}", derived_donate_to[d], expected_recipients_for_donor[d])
