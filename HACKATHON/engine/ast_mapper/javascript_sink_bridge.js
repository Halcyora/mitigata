const fs = require("fs");
const path = require("path");
const ts = require("../../app/parsers/javascript_parser/node_modules/typescript");

const root = path.resolve(process.argv[2] || "");
if (!root || !fs.existsSync(root)) {
  console.error("Usage: node javascript_sink_bridge.js <source_dir>");
  process.exit(1);
}

const ignored = new Set([".git", "node_modules", ".venv", "dist", "build"]);
const files = [];
function walk(directory) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!ignored.has(entry.name)) walk(path.join(directory, entry.name));
    } else if (/\.(?:js|jsx|ts|tsx|mjs|cjs)$/.test(entry.name)) {
      files.push(path.join(directory, entry.name));
    }
  }
}
walk(root);

function callName(expression) {
  if (ts.isIdentifier(expression)) return expression.text;
  if (ts.isPropertyAccessExpression(expression)) {
    return `${callName(expression.expression)}.${expression.name.text}`;
  }
  return "";
}

function dynamic(argument) {
  return !ts.isStringLiteral(argument) && !ts.isNoSubstitutionTemplateLiteral(argument);
}

const records = [];
for (const file of files.sort()) {
  const source = fs.readFileSync(file, "utf8");
  const scriptKind = file.endsWith(".tsx") || file.endsWith(".jsx")
    ? ts.ScriptKind.TSX
    : file.endsWith(".ts")
      ? ts.ScriptKind.TS
      : ts.ScriptKind.JS;
  const sourceFile = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, scriptKind);
  function visit(node, currentFunction) {
    let activeFunction = currentFunction;
    if (
      ts.isFunctionDeclaration(node) ||
      ts.isFunctionExpression(node) ||
      ts.isArrowFunction(node) ||
      ts.isMethodDeclaration(node)
    ) {
      activeFunction = node.name && ts.isIdentifier(node.name) ? node.name.text : currentFunction;
    }
    if (ts.isCallExpression(node) && activeFunction) {
      const name = callName(node.expression);
      const shortName = name.split(".").pop();
      let sinkType = null;
      if (["query", "execute", "raw"].includes(shortName) && node.arguments.some(dynamic)) {
        sinkType = "sql_injection";
      } else if (["exec", "execSync", "spawn", "spawnSync"].includes(shortName) &&
                 node.arguments.some(dynamic)) {
        sinkType = "command_injection";
      } else if (shortName === "eval" || shortName === "Function") {
        sinkType = "eval_injection";
      } else if (["deserialize", "unserialize"].includes(shortName)) {
        sinkType = "insecure_deserialisation";
      } else if (shortName === "redirect" && node.arguments.some(dynamic)) {
        sinkType = "open_redirect";
      } else if (["readFile", "readFileSync", "writeFile", "writeFileSync"].includes(shortName) &&
                 node.arguments.length && dynamic(node.arguments[0])) {
        sinkType = "path_traversal";
      } else if (shortName === "send" && node.arguments.some(dynamic)) {
        sinkType = "xss";
      } else if (["render", "renderString"].includes(shortName) &&
                 node.arguments.some(dynamic)) {
        sinkType = "ssti";
      }
      if (sinkType) {
        const line = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1;
        const startLine = sourceFile.getLineAndCharacterOfPosition(
          node.parent.getStart(sourceFile)
        ).line + 1;
        const functionNode = findFunction(node, activeFunction);
        const endLine = functionNode
          ? sourceFile.getLineAndCharacterOfPosition(functionNode.getEnd()).line + 1
          : line;
        records.push({
          file: path.relative(root, file).split(path.sep).join("/"),
          function: activeFunction,
          start_line: functionNode
            ? sourceFile.getLineAndCharacterOfPosition(functionNode.getStart(sourceFile)).line + 1
            : startLine,
          end_line: endLine,
          line,
          evidence: name,
          sink_type: sinkType,
        });
      }
    }
    ts.forEachChild(node, (child) => visit(child, activeFunction));
  }
  function findFunction(node, functionName) {
    let parent = node.parent;
    while (parent && !(
      ts.isFunctionDeclaration(parent) ||
      ts.isFunctionExpression(parent) ||
      ts.isArrowFunction(parent) ||
      ts.isMethodDeclaration(parent)
    )) parent = parent.parent;
    if (!parent) return null;
    if (!parent.name || !ts.isIdentifier(parent.name)) return parent;
    return parent.name.text === functionName ? parent : null;
  }
  visit(sourceFile, "");
}
process.stdout.write(JSON.stringify(records));
