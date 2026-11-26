# CampusFind — Intelligent Item Recovery

**Data Structures capstone** · Aruthran T · Register No. 192525416

CampusFind uses a C17 web server, SQLite SQL storage, and HTML, CSS, and vanilla JavaScript. The demo database is local and contains 40 fictional reports, 8 campus locations, and a pending claim. Antigravity and VS Code are optional.

## Run on Windows

1. Extract this ZIP and open the CampusFind folder.
2. For first-time setup, install [MSYS2](https://www.msys2.org/) in its default folder, `C:\msys64`. Open **MSYS2 UCRT64** from the Start menu and run this command. Accept the package prompts.

   ```bash
   pacman -S --needed mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-sqlite3 mingw-w64-ucrt-x86_64-openssl
   ```

3. Open PowerShell in the extracted CampusFind folder. Run:

   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File .\Start-CampusFind.ps1 -Demo
   ```

4. Open <http://127.0.0.1:8080/> in your browser. Keep the PowerShell window open.

To restart later, repeat step 3. It reuses the executable unless a source file changed and retains the demo database. To use another port, add `-Port 8081` and open <http://127.0.0.1:8081/>. For a non-default MSYS2 install, add `-MsysRoot 'D:\msys64'`.

## Upgrade an existing CampusFind install

Stop the app with Ctrl+C and back up any `campusfind*.db` files. Copy the
updated `server.c`, `public/style.css`, and `public/app.js` into your existing
CampusFind folder. In PowerShell from that folder, run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Start-CampusFind.ps1 -Demo -Rebuild
```

Keep your existing database in the same folder. In demo mode, the new version
updates the original sample rows in place and keeps IDs, recovery decisions,
and rows submitted by users. Regular mode uses a separate database.
The original capstone documents in `docs/` predate the dashboard refresh.

## Dashboard controls

- Select a summary card or the Lost and Found tabs to filter the report table.
- Switch between 7 and 14 days in the report activity chart. Hover over the
  chart for daily counts, or expand Daily totals to read them as a table.
- Use the calendar arrows to change months and select a date to filter reports.
- Switch light and dark mode from the top bar. The browser remembers your choice.
- On Campus routes, use Swap locations to reverse the chosen endpoints.

## Demo accounts

| Role | Email | Password |
|---|---|---|
| Student | student@campus.test | CampusStudent2026 |
| Finder | finder@campus.test | CampusFinder2026 |
| Administrator | admin@campus.test | CampusAdmin2026 |

Run with `-Demo` to use the seeded database. Run without it to use a separate empty database for ordinary registrations. Demo accounts are available only in demo mode. The app listens on the loopback interface and is designed for local demonstration.

## Four modules

| Module | Browser workflow | C implementation |
|---|---|---|
| 1. Account and Item Reporting | Register or sign in, submit a lost or found item, browse records, view personal reports | `server.c` authentication, report handlers and SQLite writes |
| 2. Search and Match Ranking | Search by item name prefix or report ID, then open a report to see ranked matches | `dsa.c` hash table, Trie, weighted scoring and merge sort |
| 3. Claims and Recovery | Submit private evidence, review pending claims as admin and record a decision | `server.c` FIFO linked queue and transactional decision |
| 4. Campus Navigation | Find the shortest walking route between two demo locations | `dsa.c` weighted adjacency matrix and Dijkstra |

## Five-minute review demo

1. Sign in as the student and search for `Lab record`. Open Lost report #1. Show Found report #2 with a score of 100.
2. Submit a new lost item. Open **My activity** to show the saved report.
3. In another browser profile, sign in as admin. Open **Review claims** and approve the seeded lab record file claim. Refresh Found report #2 in the student view to show it as Recovered.
4. Open **Campus routes** and select Main Gate and Admin Office. The demonstration route is Main Gate → Library → Block A → Admin Office, 260 m. Choose Remote Annex to show the disconnected case.
5. Restart and check that the new report and claim decision are still present.

## Linux build and tests

Install GCC, SQLite development libraries, and OpenSSL development libraries. On Debian or Ubuntu these are `build-essential libsqlite3-dev libssl-dev`.

```sh
gcc -std=c17 -Wall -Wextra -O2 server.c dsa.c -o campusfind -lsqlite3 -lcrypto
./campusfind --demo
```

From the project folder, the tests are:

```sh
gcc -std=c17 -Wall -Wextra -I. tests/dsa_test.c dsa.c -o dsa-test
./dsa-test
bash tests/smoke.sh ./campusfind
```

The smoke test uses curl and an isolated temporary database. Database schema is in `schema.sql`. The matching score is calculated on demand, and hash and Trie indexes are rebuilt from current SQL rows for each relevant request. This keeps indexes consistent with persisted state in the local demo. Closing the server preserves the SQL database file.

PowerPoint and Word report are in `docs/`. Linux build, C algorithm tests, and HTTP workflow tests were verified. Windows execution remains unverified.
