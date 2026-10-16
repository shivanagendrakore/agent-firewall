/**
 * What a SQL text does, statement by statement: only reads, writes, destroys,
 * or reaches the network or the server's shell. Comments and string literals
 * are removed first so `SELECT '; DROP TABLE x'` reads, and a hidden
 * `/* x *\/ DROP` destroys.
 */

export interface SqlEffects {
  reads: boolean;
  writes: boolean;
  destroys: boolean;
  /** Reaches outside the database: HTTP extensions, COPY TO PROGRAM, dblink, file export. */
  external: boolean;
  /** Could not be judged (unterminated literal, dynamic SQL). */
  opaque: boolean;
}

/**
 * A backslash before a quote escapes it in MySQL but not in PostgreSQL (standard strings) or SQLite: `'x\'; DROP
 * TABLE t; --'` is one literal in the first and a literal followed by a statement in the others. When the text
 * has that shape both readings are scanned and their statements joined, and it is reported as not fully
 * understood (`ok` false, so a caller treats it as opaque).
 */
export function stripSql(sql: string): { text: string; ok: boolean } {
  const a = stripSqlAs(sql, true);
  if (!a.ambiguous) return { text: a.text, ok: a.ok };
  const b = stripSqlAs(sql, false);
  return { text: `${a.text};\n${b.text}`, ok: false };
}

function stripSqlAs(sql: string, backslashEscapes: boolean): { text: string; ok: boolean; ambiguous: boolean } {
  let out = "";
  let ok = true;
  let ambiguous = false;
  // Whether the output's current line is blank so far, kept up to date as text is emitted. Re-reading the line at
  // every "#" was quadratic (review of FZ17); reading `out` by index was too, because indexing a string built by
  // `+=` flattens it every time (regex-timing seeds 25190, 26714: "&#" repeated).
  let blank = true;
  const emit = (t: string): void => {
    out += t;
    for (let k = 0; k < t.length; k++) {
      const ch = t[k] as string;
      if (ch === "\n") blank = true;
      else if (blank && !/\s/.test(ch)) blank = false;
    }
  };
  for (let i = 0; i < sql.length; i++) {
    const c = sql[i] as string;
    const n = sql[i + 1];
    if (c === "-" && n === "-") {
      const e = sql.indexOf("\n", i);
      i = e === -1 ? sql.length : e;
      emit(" ");
      continue;
    }
    if (c === "#" && blank) {
      // MySQL line comment at line start.
      const e = sql.indexOf("\n", i);
      i = e === -1 ? sql.length : e;
      continue;
    }
    if (c === "/" && n === "*") {
      const e = sql.indexOf("*/", i + 2);
      if (e === -1) {
        ok = false;
        break;
      }
      // MySQL executable comments /*! ... */ run; keep their content.
      if (sql[i + 2] === "!") emit(` ${sql.slice(i + 3, e).replace(/^\d+/, "")} `);
      else emit(" ");
      i = e + 1;
      continue;
    }
    if (c === "'" || c === '"' || c === "`") {
      let j = i + 1;
      for (; j < sql.length; j++) {
        if (backslashEscapes && sql[j] === "\\" && c === "'") {
          if (sql[j + 1] === "'") ambiguous = true;
          j++;
          continue;
        }
        if (sql[j] === c) {
          if (sql[j + 1] === c) {
            j++;
            continue;
          }
          break;
        }
      }
      if (j >= sql.length) ok = false;
      // Quoted identifiers stay (as a placeholder name); string literals become a token.
      emit(c === "'" ? " 'S' " : " ident ");
      i = j;
      continue;
    }
    if (c === "$") {
      // PostgreSQL dollar quoting: $$...$$ or $tag$...$tag$. Function bodies are code: keep them.
      const m = /^\$([A-Za-z_][A-Za-z0-9_]*)?\$/.exec(sql.slice(i));
      if (m !== null) {
        const tag = m[0];
        const e = sql.indexOf(tag, i + tag.length);
        if (e === -1) {
          ok = false;
          break;
        }
        emit(` ${sql.slice(i + tag.length, e)} `);
        i = e + tag.length - 1;
        continue;
      }
    }
    emit(c);
  }
  return { text: out, ok, ambiguous };
}

const DESTROY = /^\s*(?:DROP|TRUNCATE)\b|^\s*ALTER\s+\w+(?:\s+\w+)*?\s+DROP\b|\bFLUSHALL\b|\bFLUSHDB\b|^\s*REVOKE\b|\bdropDatabase\s*\(|\.drop\s*\(|\.deleteMany\s*\(\s*\{\s*\}\s*\)|\.remove\s*\(\s*\{\s*\}\s*\)/i;

/**
 * A DELETE or UPDATE that touches every row: no WHERE of its own. A WHERE inside parentheses belongs to a
 * sub-select, and a WHERE that is always true (1=1, true) filters nothing.
 */
function unfiltered(stmt: string): boolean {
  if (!/^\s*(?:DELETE|UPDATE)\b/i.test(stmt)) return false;
  if (/\bWHERE\s+\(*\s*(?:1\s*=\s*1|0\s*=\s*0|TRUE|'S'\s*=\s*'S')\s*\)*\s*(?:$|\b(?:RETURNING|ORDER|LIMIT)\b)/i.test(stmt)) return true;
  let flat = stmt;
  // Innermost groups first; bounded so a deeply nested text costs a fixed number of linear passes.
  for (let i = 0; i < 64 && flat.includes("("); i++) {
    const next = flat.replace(/\([^()]*\)/g, " ");
    if (next === flat) break;
    flat = next;
  }
  return !/\bWHERE\b/i.test(flat);
}

/**
 * Code that runs inside a statement and is not a statement of its own at the top level: the body of a
 * DO block or procedure (the text after `DO`, `BEGIN`, `THEN`...), and a data-modifying statement inside a
 * WITH ... AS ( ... ) CTE. Returned as extra statements to judge beside the original.
 */
function embedded(stmt: string): string[] {
  const out: string[] = [];
  const lead = /^\s*(?:DO(?:\s+LANGUAGE\s+\w+)?|BEGIN(?:\s+ATOMIC)?|DECLARE|THEN|ELSE|LOOP|(?:ELS)?IF\b[^;]*?\bTHEN)\b/i;
  let rest = stmt;
  for (let i = 0; i < 8; i++) {
    const m = lead.exec(rest);
    if (m === null) break;
    rest = rest.slice(m[0].length);
    if (rest.trim() !== "") out.push(rest);
  }
  if (/^\s*WITH\b/i.test(stmt)) {
    const re = /\(\s*(?=(?:DELETE|UPDATE|INSERT|DROP|TRUNCATE)\b)/gi;
    for (let m = re.exec(stmt); m !== null && out.length < 64; m = re.exec(stmt)) {
      let depth = 1;
      let k = m.index + m[0].length;
      for (; k < stmt.length && depth > 0; k++) {
        if (stmt[k] === "(") depth++;
        else if (stmt[k] === ")") depth--;
      }
      out.push(stmt.slice(m.index + m[0].length, depth === 0 ? k - 1 : k));
    }
  }
  return out;
}

/** The statements of a stripped SQL text, with the code embedded in them (DO bodies, CTE bodies) as extra statements. */
export function sqlStatements(text: string): string[] {
  const out: string[] = [];
  for (const stmt of text.split(";")) {
    if (stmt.trim() === "") continue;
    out.push(stmt);
    out.push(...embedded(stmt));
  }
  return out;
}
const WRITE = /^\s*(?:INSERT|UPDATE|DELETE|MERGE|UPSERT|REPLACE|CREATE|ALTER|GRANT|COPY|CALL|DO|EXECUTE|EXEC|SET|LOAD|IMPORT|VACUUM|REINDEX|CLUSTER|COMMENT|SECURITY|REFRESH|LOCK)\b|\b(?:insertOne|insertMany|updateOne|updateMany|replaceOne|deleteOne|deleteMany|bulkWrite|findOneAndUpdate|findOneAndDelete|createIndex)\s*\(/i;
const READ = /^\s*(?:SELECT|WITH|SHOW|EXPLAIN|DESCRIBE|DESC|VALUES|TABLE|PRAGMA)\b|\b(?:find|findOne|aggregate|countDocuments|distinct)\s*\(/i;
const EXTERNAL = /\b(?:net\.http_(?:get|post|put|delete)|http_(?:get|post|put|patch|delete|request)|pg_net|dblink(?:_exec)?|lo_export|pg_read_(?:server_)?file|pg_read_binary_file|INTO\s+(?:OUTFILE|DUMPFILE)|LOAD_FILE\s*\(|xp_cmdshell|sp_OACreate|UTL_HTTP|aws_s3\.|aws_lambda\.|sys_exec|sys_eval)\b/i;
const DYNAMIC = /\bEXECUTE\s+(?:format\s*\(|'|\w+\s*;)|\bPREPARE\b|\bsp_executesql\b/i;

/**
 * COPY ... TO PROGRAM or FROM PROGRAM anywhere after a COPY. Review of FZ17: written as COPY\b[\s\S]*\bTO\s+PROGRAM
 * inside one pattern, every COPY scanned to the end of the text and back (quadratic in a text of many COPYs);
 * the first COPY and one linear search after it say the same.
 */
function copyProgram(text: string): boolean {
  const m = /\bCOPY\b/i.exec(text);
  return m !== null && /\b(?:TO|FROM)\s+PROGRAM\b/i.test(text.slice(m.index));
}

export function classifySql(sql: string): SqlEffects {
  const { text, ok } = stripSql(sql);
  const r: SqlEffects = { reads: false, writes: false, destroys: false, external: false, opaque: !ok };
  if (EXTERNAL.test(text) || copyProgram(text)) r.external = true;
  if (DYNAMIC.test(text)) r.opaque = true;
  for (const stmt of sqlStatements(text)) {
    // A WITH can end in a data-modifying statement.
    const body = /^\s*WITH\b/i.test(stmt) ? stmt.replace(/^\s*WITH\b[\s\S]*?\)\s*(?=(?:SELECT|INSERT|UPDATE|DELETE|MERGE)\b)/i, "") : stmt;
    if (DESTROY.test(body) || unfiltered(body)) r.destroys = true;
    if (WRITE.test(body) || /\b(?:INSERT|UPDATE|DELETE)\b/i.test(stmt.replace(/^\s*(?:SELECT)\b[\s\S]*/i, ""))) r.writes = true;
    else if (READ.test(body)) r.reads = true;
    else if (!/^\s*(?:BEGIN|COMMIT|ROLLBACK|START\s+TRANSACTION|END)\b/i.test(body)) r.writes = true;
  }
  return r;
}
