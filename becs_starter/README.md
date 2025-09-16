# BECS Starter (Tkinter + SQLite)
## How to run
1. Install Python 3.12+
2. Run: `python becs_app.py`
3. Use the three tabs to add donations, issue routine units, and emergency O- dispensing.

## Where is the database?
A local file `becs.db` will be created next to `becs_app.py` when you run the app.

## Next steps
- Replace the compatibility dictionary and rarity weights with the exact values from your assignment document.
- Add input validation for dates and IDs if required by your course.

## Default admin login
- Username: admin
- Password: admin
- National ID (for self-reset): 000000001

## Roles (short)
- admin – full access: Donations, Routine Issue, Emergency (MCI), Audit Log, Export, Issued by Users, Donor Report, and Manage Users…
- user – operations staff: Donations, Routine Issue, Emergency (MCI). All actions are audited.
- research – read-only: Inventory View only.