const fs = require("fs");

function loadModule(name) {
  try {
    return require(name);
  } catch (_err) {
    return null;
  }
}

function decodeB64(value) {
  return Buffer.from(String(value || ""), "base64").toString("utf8");
}

function renderCallee(node) {
  if (!node || typeof node !== "object") {
    return "";
  }
  if (node.type === "Identifier") {
    return node.name || "";
  }
  if (node.type === "ThisExpression") {
    return "this";
  }
  if (node.type === "Literal") {
    return String(node.value || "");
  }
  if (node.type === "PrivateIdentifier") {
    return node.name || "";
  }
  if (node.type === "ChainExpression") {
    return renderCallee(node.expression);
  }
  if (node.type === "MemberExpression") {
    const object = renderCallee(node.object);
    const property = renderCallee(node.property);
    return object && property ? `${object}.${property}` : object || property;
  }
  return "";
}

function snippetFromRange(source, start, end) {
  const safeStart = Math.max(0, Number(start) || 0);
  const safeEnd = Math.max(safeStart, Number(end) || safeStart);
  return String(source.slice(safeStart, safeEnd)).replace(/\s+/g, " ").trim().slice(0, 220);
}

function snippetFromNode(node, source) {
  if (!node || !Array.isArray(node.range) || node.range.length !== 2) {
    return "";
  }
  return snippetFromRange(source, node.range[0], node.range[1]);
}

function buildEvidence(node, source, kind, sink, detail = "") {
  const loc =
    node && node.loc && node.loc.start
      ? node.loc
      : { start: { line: 0, column: 0 }, end: { line: 0, column: 0 } };
  return {
    kind,
    sink,
    detail,
    line: Number(loc.start.line || 0),
    column: Number(loc.start.column || 0) + 1,
    end_line: Number((loc.end && loc.end.line) || loc.start.line || 0),
    end_column: Number((loc.end && loc.end.column) || loc.start.column || 0) + 1,
    snippet: snippetFromNode(node, source),
  };
}

function isDomAssignmentTarget(path) {
  return (
    path === "innerHTML" ||
    path.endsWith(".innerHTML") ||
    path === "outerHTML" ||
    path.endsWith(".outerHTML")
  );
}

function isPrototypeMutationPath(path) {
  if (!path) {
    return false;
  }
  return (
    path === "__proto__" ||
    path.endsWith(".__proto__") ||
    path === "prototype" ||
    path.includes(".prototype.") ||
    path.endsWith(".prototype") ||
    path === "constructor.prototype" ||
    path.includes(".constructor.prototype")
  );
}

function summarizeAst(ast, source) {
  const summary = {
    call_expressions: 0,
    eval_calls: 0,
    new_function_calls: 0,
    dom_sink_calls: 0,
    prototype_pollution_candidates: 0,
    dangerous_sink_count: 0,
  };
  const dangerousSinks = [];
  const prototypePollution = [];
  const sinkBuckets = {
    xss: [],
    eval: [],
    secret: [],
    api_path: [],
    prototype_pollution: [],
  };

  function pushUnique(target, item) {
    const key = `${item.kind}|${item.sink}|${item.line}|${item.column}|${item.snippet}`;
    if (
      !target.some(
        (candidate) =>
          `${candidate.kind}|${candidate.sink}|${candidate.line}|${candidate.column}|${candidate.snippet}` === key
      )
    ) {
      target.push(item);
    }
  }

  function pushBucket(category, item) {
    if (!sinkBuckets[category]) {
      sinkBuckets[category] = [];
    }
    pushUnique(sinkBuckets[category], item);
  }

  function walk(node) {
    if (!node || typeof node !== "object") {
      return;
    }

    if (node.type === "CallExpression") {
      summary.call_expressions += 1;
      const callee = renderCallee(node.callee);
      if (callee === "eval") {
        summary.eval_calls += 1;
        const item = buildEvidence(node, source, "exec", "eval");
        pushUnique(dangerousSinks, item);
        pushBucket("eval", item);
      }
      if (callee === "document.write" || callee.endsWith(".insertAdjacentHTML")) {
        summary.dom_sink_calls += 1;
        const item = buildEvidence(node, source, "dom", callee);
        pushUnique(dangerousSinks, item);
        pushBucket("xss", item);
      }
      if (callee === "setTimeout" || callee === "setInterval") {
        const arg0 = node.arguments && node.arguments[0];
        if (arg0 && arg0.type === "Literal" && typeof arg0.value === "string") {
          summary.eval_calls += 1;
          const item = buildEvidence(node, source, "exec", callee, "string-argument");
          pushUnique(dangerousSinks, item);
          pushBucket("eval", item);
        }
      }
      if (callee === "Object.assign") {
        const target = node.arguments && node.arguments[0];
        const targetPath = renderCallee(target);
        if (isPrototypeMutationPath(targetPath)) {
          summary.prototype_pollution_candidates += 1;
          const item = buildEvidence(node, source, "prototype-pollution", callee, `target=${targetPath}`);
          pushUnique(prototypePollution, item);
          pushBucket("prototype_pollution", item);
        }
      }
      if (
        callee === "fetch" ||
        callee.endsWith(".fetch") ||
        callee.endsWith(".open") ||
        callee.endsWith(".post") ||
        callee.endsWith(".get")
      ) {
        const arg0 = node.arguments && node.arguments[0];
        if (arg0 && arg0.type === "Literal" && typeof arg0.value === "string" && arg0.value.startsWith("/")) {
          pushBucket("api_path", buildEvidence(arg0, source, "api-path", String(arg0.value)));
        }
      }
    }

    if (node.type === "NewExpression") {
      const callee = renderCallee(node.callee);
      if (callee === "Function") {
        summary.new_function_calls += 1;
        const item = buildEvidence(node, source, "exec", "new Function");
        pushUnique(dangerousSinks, item);
        pushBucket("eval", item);
      }
      if (callee === "RegExp") {
        const arg0 = node.arguments && node.arguments[0];
        if (arg0 && arg0.type !== "Literal") {
          pushBucket("eval", buildEvidence(node, source, "redos", "RegExp", "dynamic-pattern"));
        }
      }
    }

    if (node.type === "AssignmentExpression") {
      const left = renderCallee(node.left);
      if (isDomAssignmentTarget(left)) {
        summary.dom_sink_calls += 1;
        const item = buildEvidence(node, source, "dom", left);
        pushUnique(dangerousSinks, item);
        pushBucket("xss", item);
      }
      if (left === "location.href" || left.endsWith(".src") || left.endsWith(".href")) {
        pushBucket("xss", buildEvidence(node, source, "dom", left, "navigation-or-url-sink"));
      }
      if (isPrototypeMutationPath(left)) {
        summary.prototype_pollution_candidates += 1;
        const item = buildEvidence(node, source, "prototype-pollution", left || "assignment", "assignment-target");
        pushUnique(prototypePollution, item);
        pushBucket("prototype_pollution", item);
      }
    }

    if (node.type === "CallExpression") {
      const callee = renderCallee(node.callee);
      if (callee === "Object.setPrototypeOf" || callee === "Reflect.setPrototypeOf") {
        summary.prototype_pollution_candidates += 1;
        const item = buildEvidence(node, source, "prototype-pollution", callee);
        pushUnique(prototypePollution, item);
        pushBucket("prototype_pollution", item);
      }
    }

    if (node.type === "Property" && !node.computed && node.key && node.key.type === "Identifier") {
      const keyName = node.key.name || "";
      if (/(apiKey|secret|token|password|passwd)/i.test(keyName)) {
        pushBucket("secret", buildEvidence(node, source, "secret", keyName, "object-property"));
      }
    }

    if (node.type === "VariableDeclarator" && node.id && node.id.type === "Identifier") {
      const idName = node.id.name || "";
      if (/(apiKey|secret|token|password|passwd)/i.test(idName)) {
        pushBucket("secret", buildEvidence(node, source, "secret", idName, "variable-declarator"));
      }
      if (node.init && node.init.type === "Literal" && typeof node.init.value === "string" && node.init.value.startsWith("/")) {
        pushBucket("api_path", buildEvidence(node.init, source, "api-path", String(node.init.value), "literal-route"));
      }
    }

    for (const value of Object.values(node)) {
      if (Array.isArray(value)) {
        for (const child of value) {
          walk(child);
        }
      } else if (value && typeof value === "object") {
        walk(value);
      }
    }
  }

  walk(ast);
  summary.dangerous_sink_count = dangerousSinks.length;
  return {
    summary,
    dangerousSinks: dangerousSinks.slice(0, 20),
    prototypePollution: prototypePollution.slice(0, 12),
    sinkBuckets,
  };
}

function locFromIndex(source, index) {
  const text = String(source.slice(0, Math.max(0, Number(index) || 0)));
  const lines = text.split(/\r\n?|\n/);
  const line = lines.length;
  const column = (lines[lines.length - 1] || "").length + 1;
  return { line, column };
}

function buildTreeSitterEvidence(node, source, kind, sink, detail = "") {
  const start = node && typeof node.startIndex === "number" ? node.startIndex : 0;
  const end = node && typeof node.endIndex === "number" ? node.endIndex : start;
  const startLoc = locFromIndex(source, start);
  const endLoc = locFromIndex(source, end);
  return {
    kind,
    sink,
    detail,
    line: startLoc.line,
    column: startLoc.column,
    end_line: endLoc.line,
    end_column: endLoc.column,
    snippet: snippetFromRange(source, start, end),
  };
}

function collectTreeSitterRules(source) {
  const Parser = loadModule("tree-sitter");
  const JavaScript = loadModule("tree-sitter-javascript");
  if (!Parser || !JavaScript) {
    return { enabled: false, engine: "disabled", sinkRules: {} };
  }
  try {
    const parser = new Parser();
    parser.setLanguage(JavaScript);
    const tree = parser.parse(source);
    const Query = Parser.Query;
    const rules = {
      xss: `
        (assignment_expression
          left: (member_expression property: (property_identifier) @prop
            (#match? @prop "^(innerHTML|outerHTML)$"))
        ) @vulnerability
        (call_expression
          function: [(identifier) @name (member_expression property: (property_identifier) @name)]
          (#match? @name "^(write|insertAdjacentHTML)$")
        ) @vulnerability
      `,
      eval: `
        (call_expression
          function: [(identifier) @name (member_expression property: (property_identifier) @name)]
          (#match? @name "^(eval|setTimeout|setInterval)$")
        ) @vulnerability
        (new_expression
          constructor: (identifier) @name
          (#eq? @name "Function")
        ) @vulnerability
        (new_expression
          constructor: (identifier) @name
          (#eq? @name "RegExp")
          arguments: (arguments [(identifier) (member_expression)]) @dynamic_regex
        ) @vulnerability
      `,
      secret: `
        (variable_declarator
          name: (identifier) @name
          (#match? @name "(?i)^(apiKey|secret|token|password|passwd|clientSecret)$")
        ) @vulnerability
      `,
      prototype_pollution: `
        (assignment_expression
          left: (member_expression property: (property_identifier) @prop
            (#match? @prop "^(prototype|__proto__)$"))
        ) @vulnerability
      `,
    };
    const sinkRules = {};
    for (const [category, text] of Object.entries(rules)) {
      try {
        const query = new Query(JavaScript, text);
        const matches = query.matches(tree.rootNode);
        sinkRules[category] = matches
          .map((match) => {
            const capture = match.captures.find((item) => item.name === "vulnerability" || item.name === "dynamic_regex");
            if (!capture) {
              return null;
            }
            const detail = capture.name === "dynamic_regex" ? "dynamic-regex-pattern" : "";
            return buildTreeSitterEvidence(capture.node, source, `tree-sitter-${category}`, category, detail);
          })
          .filter(Boolean)
          .slice(0, 10);
      } catch (_err) {
        sinkRules[category] = [];
      }
    }
    return { enabled: true, engine: "tree-sitter", sinkRules };
  } catch (_err) {
    return { enabled: false, engine: "tree-sitter-error", sinkRules: {} };
  }
}

function main() {
  const input = fs.readFileSync(0, "utf8");
  const payload = JSON.parse(input || "{}");
  const espree = loadModule("espree");
  const beautifyPkg = loadModule("js-beautify");
  const beautify =
    beautifyPkg && typeof beautifyPkg.js === "function"
      ? beautifyPkg.js
      : beautifyPkg && typeof beautifyPkg.js_beautify === "function"
        ? beautifyPkg.js_beautify
        : null;

  const response = {
    parser: espree ? "espree" : "regex-fallback",
    beautifier: beautify ? "js-beautify" : "source-original",
    tree_sitter: "disabled",
    scripts: [],
  };

  for (const item of Array.isArray(payload.scripts) ? payload.scripts : []) {
    const source = decodeB64(item.source_b64);
    let parseOk = false;
    let parseError = "";
    let astSummary = {};
    let dangerousSinks = [];
    let prototypePollution = [];
    let sinkRules = {};
    let beautified = source;

    if (beautify) {
      try {
        beautified = beautify(source, { indent_size: 2, preserve_newlines: true });
      } catch (_err) {
        beautified = source;
      }
    }

    if (espree) {
      try {
        const ast = espree.parse(source, {
          ecmaVersion: "latest",
          sourceType: "script",
          loc: true,
          range: true,
          comment: true,
          tolerant: true,
        });
        parseOk = true;
        const analysis = summarizeAst(ast, source);
        astSummary = analysis.summary;
        dangerousSinks = analysis.dangerousSinks;
        prototypePollution = analysis.prototypePollution;
        sinkRules = analysis.sinkBuckets;
      } catch (errScript) {
        try {
          const ast = espree.parse(source, {
            ecmaVersion: "latest",
            sourceType: "module",
            loc: true,
            range: true,
            comment: true,
            tolerant: true,
          });
          parseOk = true;
          const analysis = summarizeAst(ast, source);
          astSummary = analysis.summary;
          dangerousSinks = analysis.dangerousSinks;
          prototypePollution = analysis.prototypePollution;
          sinkRules = analysis.sinkBuckets;
        } catch (errModule) {
          parseError = String((errModule && errModule.message) || (errScript && errScript.message) || "parse failed");
        }
      }
    }

    const treeSitter = collectTreeSitterRules(source);
    response.tree_sitter = treeSitter.engine || response.tree_sitter;
    for (const [category, items] of Object.entries(treeSitter.sinkRules || {})) {
      if (!sinkRules[category]) {
        sinkRules[category] = [];
      }
      for (const evidence of items) {
        const key = `${evidence.kind}|${evidence.sink}|${evidence.line}|${evidence.column}|${evidence.snippet}`;
        if (
          !sinkRules[category].some(
            (candidate) =>
              `${candidate.kind}|${candidate.sink}|${candidate.line}|${candidate.column}|${candidate.snippet}` === key
          )
        ) {
          sinkRules[category].push(evidence);
        }
      }
    }

    response.scripts.push({
      location: String(item.location || ""),
      beautified,
      parse_ok: parseOk,
      parse_error: parseError,
      ast_summary: astSummary,
      dangerous_sinks: dangerousSinks,
      prototype_pollution: prototypePollution,
      sink_rules: sinkRules,
    });
  }

  process.stdout.write(JSON.stringify(response));
}

main();
