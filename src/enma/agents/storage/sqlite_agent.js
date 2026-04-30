"use strict";
/**
 * SQLite Monitor Agent
 *
 * Hooks all SQLiteDatabase operations to capture:
 *   - execSQL (raw DDL / DML)
 *   - query / rawQuery (SELECT)
 *   - insert / update / delete
 *   - SQLiteStatement execution (compiled statements)
 *
 * Output: sqlite_log.json
 */

function log(msg) { send({ event: "log", message: msg }); }
function sendJson(name, data) { send({ event: "json", name: name, data: data }); }

const sqlLog = [];
const MAX    = 5000;

function record(op, db, sql, args, rowCount) {
    if (sqlLog.length >= MAX) return;
    sqlLog.push({ ts: Date.now(), op, db, sql, args: args ?? null, rowCount: rowCount ?? null });
    log(`[sqlite] ${op} [${db}] ${(sql ?? "").slice(0, 100)}`);
}

function dbPath(db) {
    try { return db.getPath().toString(); } catch (_) { return "?"; }
}

function bindingsToArray(bindings) {
    if (!bindings) return null;
    try {
        const arr = [];
        for (let i = 0; i < bindings.length; i++) {
            arr.push(bindings[i]?.toString() ?? null);
        }
        return arr;
    } catch (_) { return null; }
}

// ── Hook SQLiteDatabase ───────────────────────────────────────────────────────

function hookSQLiteDatabase() {
    Java.perform(() => {
        try {
            const DB = Java.use("android.database.sqlite.SQLiteDatabase");

            // execSQL
            DB.execSQL.overload("java.lang.String").implementation = function (sql) {
                record("execSQL", dbPath(this), sql.toString(), null, null);
                return this.execSQL(sql);
            };
            DB.execSQL.overload("java.lang.String", "[Ljava.lang.Object;").implementation = function (sql, args) {
                record("execSQL", dbPath(this), sql.toString(), bindingsToArray(args), null);
                return this.execSQL(sql, args);
            };

            // rawQuery
            DB.rawQuery.overload("java.lang.String", "[Ljava.lang.String;").implementation = function (sql, sel) {
                const cursor = this.rawQuery(sql, sel);
                record("rawQuery", dbPath(this), sql.toString(), bindingsToArray(sel), cursor ? cursor.getCount() : null);
                return cursor;
            };

            // insert
            DB.insert.implementation = function (table, nullHack, values) {
                const rowId = this.insert(table, nullHack, values);
                record("insert", dbPath(this), `INSERT INTO ${table}`, values ? [values.toString()] : null, rowId === -1 ? 0 : 1);
                return rowId;
            };

            // update
            DB.update.overload(
                "java.lang.String",
                "android.content.ContentValues",
                "java.lang.String",
                "[Ljava.lang.String;"
            ).implementation = function (table, values, where, whereArgs) {
                const count = this.update(table, values, where, whereArgs);
                record("update", dbPath(this), `UPDATE ${table} WHERE ${where ?? ""}`, bindingsToArray(whereArgs), count);
                return count;
            };

            // delete
            DB.delete.implementation = function (table, where, whereArgs) {
                const count = this.delete(table, where, whereArgs);
                record("delete", dbPath(this), `DELETE FROM ${table} WHERE ${where ?? ""}`, bindingsToArray(whereArgs), count);
                return count;
            };

            log("[sqlite] SQLiteDatabase hooks installed");
        } catch (e) { log(`[sqlite] SQLiteDatabase hook failed: ${e}`); }

        // SQLiteStatement.execute / executeInsert / simpleQueryForLong
        try {
            const Stmt = Java.use("android.database.sqlite.SQLiteStatement");
            Stmt.execute.implementation = function () {
                record("statement.execute", "?", this.toString(), null, null);
                return this.execute();
            };
            Stmt.executeInsert.implementation = function () {
                const rowId = this.executeInsert();
                record("statement.executeInsert", "?", this.toString(), null, rowId >= 0 ? 1 : 0);
                return rowId;
            };
            Stmt.executeUpdateDelete.implementation = function () {
                const n = this.executeUpdateDelete();
                record("statement.executeUpdateDelete", "?", this.toString(), null, n);
                return n;
            };
        } catch (_) {}

        // Room (Jetpack) — hooks SupportSQLiteDatabase
        try {
            const Room = Java.use("androidx.room.RoomDatabase");
            if (Room.query) {
                Room.query.overloads.forEach(ovl => {
                    ovl.implementation = function (...args) {
                        try { record("room.query", "RoomDB", args[0]?.toString() ?? "?", null, null); } catch (_) {}
                        return ovl.apply(this, args);
                    };
                });
            }
        } catch (_) {}
    });
}

// ── Flush ─────────────────────────────────────────────────────────────────────

function flush() {
    if (sqlLog.length > 0) sendJson("sqlite_log.json", sqlLog);
}

// ── Entry point ───────────────────────────────────────────────────────────────

log("[sqlite] Agent loaded");
Java.performNow(hookSQLiteDatabase);

setInterval(flush, 10000);
setTimeout(flush, 60000);
