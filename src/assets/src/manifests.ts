/**
 * manifest 解析器：把各生态的依赖清单读成 Component[]。
 *
 * 设计纪律：
 * - 零依赖（不引 toml/xml 解析库），用受控的正则/极简 TOML 子集；
 * - 只解析"声明了什么"，不联网、不执行任何清单内代码；
 * - 解析不了的版本一律留空（version=""），由匹配器按 unknown 处理，不猜。
 */
import type { Component, Ecosystem } from "./types.js";

export interface ManifestParseResult {
  components: Component[];
  languages: string[];
  frameworks: string[];
}

const MANIFEST_ECOSYSTEM: Record<string, Ecosystem> = {
  "package.json": "npm",
  "requirements.txt": "pypi",
  "pyproject.toml": "pypi",
  pipfile: "pypi",
  "go.mod": "go",
  "cargo.toml": "cargo",
  "pom.xml": "maven",
  "composer.json": "composer",
  gemfile: "gem",
  dockerfile: "docker",
  "docker-compose.yml": "docker",
  "docker-compose.yaml": "docker",
  "compose.yml": "docker",
  "compose.yaml": "docker",
};

const LANGUAGE_BY_MANIFEST: Record<string, string> = {
  "package.json": "Node.js",
  "requirements.txt": "Python",
  "pyproject.toml": "Python",
  pipfile: "Python",
  "go.mod": "Go",
  "cargo.toml": "Rust",
  "pom.xml": "Java",
  "composer.json": "PHP",
  gemfile: "Ruby",
  dockerfile: "Docker",
  "docker-compose.yml": "Docker",
  "docker-compose.yaml": "Docker",
  "compose.yml": "Docker",
  "compose.yaml": "Docker",
};

/** 常见框架/工具词典：依赖名（小写）→ 展示名。 */
export const FRAMEWORK_HINTS: Record<string, string> = {
  vue: "Vue", react: "React", angular: "Angular", svelte: "Svelte", "solid-js": "SolidJS",
  next: "Next.js", nuxt: "Nuxt", electron: "Electron", express: "Express", fastify: "Fastify",
  koa: "Koa", "@nestjs/core": "NestJS", vite: "Vite", webpack: "webpack", tailwindcss: "Tailwind CSS",
  typescript: "TypeScript", jest: "Jest", vitest: "Vitest", playwright: "Playwright", cypress: "Cypress",
  django: "Django", flask: "Flask", fastapi: "FastAPI", celery: "Celery", sqlalchemy: "SQLAlchemy",
  pandas: "pandas", numpy: "NumPy", torch: "PyTorch", tensorflow: "TensorFlow",
  transformers: "HuggingFace Transformers", langchain: "LangChain", openai: "OpenAI SDK",
  "spring-boot": "Spring Boot", "spring-boot-starter": "Spring Boot", "spring-boot-starter-web": "Spring Boot",
  "gin-gonic/gin": "Gin", "github.com/gin-gonic/gin": "Gin", actix_web: "Actix Web", "actix-web": "Actix Web",
  rocket: "Rocket", rails: "Ruby on Rails", "laravel/framework": "Laravel", symfony: "Symfony",
  axios: "axios", lodash: "lodash", pinia: "Pinia", "vue-router": "Vue Router",
};

/** 正则分组取值（noUncheckedIndexedAccess 下的窄化：match 非空时必填组一定存在）。 */
function group(match: RegExpExecArray, index: number): string {
  return match[index] ?? "";
}

function component(ecosystem: Ecosystem, name: string, rawConstraint: string, source_file: string): Component {
  const constraint = rawConstraint.trim();
  const literal = firstVersionLiteral(constraint);
  const rangeFloor = isRangeFloor(constraint);
  // 范围约束（^/~/>= 等）保留下界字面量进 version，并靠 version_is_range_floor 提醒匹配器
  // "实际安装的可能是更高版本"；通配符（1.x / *）与属性占位符不猜，version 留空。
  const wildcard = /(^|[^a-z0-9])x([^a-z0-9]|$)/i.test(constraint) || constraint.includes("*");
  return {
    ecosystem,
    name: name.trim(),
    version: wildcard || !literal ? "" : literal,
    constraint_raw: constraint,
    version_is_range_floor: rangeFloor,
    source_file,
  };
}

/** 取出约束里的第一个数字点分版本字面量；找不到返回 null。 */
function firstVersionLiteral(constraint: string): string | null {
  const match = /(\d+(?:\.\d+){0,7})/.exec(constraint);
  return match ? group(match, 1) : null;
}

/**
 * 是否"范围约束"（只能保留下界）：
 * - 空约束 / 通配符 / 属性占位符 → true（未锁定）；
 * - == 精确钉死、裸版本字面量、生态 tag（20-alpine）→ false；
 * - 其余（^ ~ >= > < <= ~= != 等）→ true。
 */
function isRangeFloor(constraint: string): boolean {
  const c = constraint.trim();
  if (c === "") return true;
  if (/^==/.test(c)) return false;
  if (/^v?\d+(?:\.\d+){0,7}$/.test(c)) return false;
  if (/^[A-Za-z0-9._-]+$/.test(c) && /\d/.test(c)) return false;
  return true;
}

function push(list: Component[], c: Component | null): void {
  if (c && c.name) list.push(c);
}

/** 入口：按相对路径分发到对应生态解析器。workflows 文件按路径识别。 */
export function parseManifest(relPath: string, content: string): ManifestParseResult {
  const norm = relPath.replaceAll("\\", "/");
  const base = norm.slice(norm.lastIndexOf("/") + 1).toLowerCase();
  const components: Component[] = [];
  const languages: string[] = [];
  const frameworks: string[] = [];

  const isWorkflow = norm.includes(".github/workflows/") && (norm.endsWith(".yml") || norm.endsWith(".yaml"));

  if (isWorkflow) {
    parseWorkflowUses(content, norm, components);
    languages.push("CI");
    frameworks.push("GitHub Actions");
    return { components, languages, frameworks };
  }

  const ecosystem = MANIFEST_ECOSYSTEM[base];
  if (!ecosystem) return { components, languages, frameworks };
  const language = LANGUAGE_BY_MANIFEST[base];
  if (language) languages.push(language);

  switch (ecosystem) {
    case "npm":
      parsePackageJson(content, norm, components, frameworks, languages);
      break;
    case "pypi":
      if (base === "pyproject.toml") parsePyproject(content, norm, components);
      else if (base === "pipfile") parsePipfile(content, norm, components);
      else parseRequirements(content, norm, components);
      break;
    case "go":
      parseGoMod(content, norm, components);
      break;
    case "cargo":
      parseCargoToml(content, norm, components);
      break;
    case "maven":
      parsePomXml(content, norm, components);
      break;
    case "composer":
      parseComposerJson(content, norm, components);
      break;
    case "gem":
      parseGemfile(content, norm, components);
      break;
    case "docker":
      if (base === "dockerfile") parseDockerfile(content, norm, components);
      else parseComposeYaml(content, norm, components);
      frameworks.push("Docker");
      break;
    default:
      break;
  }

  for (const c of components) {
    const hint = FRAMEWORK_HINTS[c.name.toLowerCase()];
    if (hint && !frameworks.includes(hint)) frameworks.push(hint);
  }
  return { components, languages, frameworks };
}

function parsePackageJson(content: string, rel: string, out: Component[], frameworks: string[], languages: string[]): void {
  let pkg: Record<string, unknown>;
  try {
    pkg = JSON.parse(content) as Record<string, unknown>;
  } catch {
    return; // 坏 JSON：无组件产出，由调用方记录 manifests 即可
  }
  const depFields = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"];
  for (const field of depFields) {
    const deps = pkg[field];
    if (!deps || typeof deps !== "object") continue;
    for (const [name, range] of Object.entries(deps as Record<string, unknown>)) {
      if (typeof range !== "string") continue;
      push(out, component("npm", name, range, rel));
    }
  }
  const engines = pkg.engines;
  if (engines && typeof engines === "object" && typeof (engines as Record<string, unknown>).node === "string") {
    languages.push("Node " + String((engines as Record<string, unknown>).node));
  }
  if (typeof pkg.packageManager === "string") frameworks.push(pkg.packageManager.split("@")[0] ?? "");
}

function parseRequirements(content: string, rel: string, out: Component[]): void {
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.replace(/#.*$/, "").trim();
    if (!line || line.startsWith("-")) continue;
    const match = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$/.exec(line);
    if (!match) continue;
    const name = group(match, 1);
    const spec = (group(match, 3)).split(";")[0] ?? "";
    if (!spec) {
      push(out, component("pypi", name, "", rel));
      continue;
    }
    const specMatch = /^(===|==|>=|<=|~=|!=|>|<)\s*([^,\s]+)/.exec(spec);
    push(out, component("pypi", name, specMatch ? group(specMatch, 1) + group(specMatch, 2) : spec, rel));
  }
}

function parsePyproject(content: string, rel: string, out: Component[]): void {
  // PEP 621：dependencies = ["a>=1", ...]（[project] 或 optional-dependencies 内）
  const arrayRegex = /dependencies\s*=\s*\[((?:[^\[\]]|\[[^\]]*\])*)\]/g;
  let m: RegExpExecArray | null;
  while ((m = arrayRegex.exec(content)) !== null) {
    const items = group(m, 1).match(/["']([^"']+)["']/g) ?? [];
    for (const item of items) {
      const spec = item.slice(1, -1);
      const match = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$/.exec(spec);
      if (!match) continue;
      const specPart = group(match, 3).split(";")[0] ?? "";
      push(out, component("pypi", group(match, 1), specPart, rel));
    }
  }
  // Poetry：[tool.poetry.dependencies] 表
  let section = "";
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    const header = /^\[([^\]]+)\]/.exec(line);
    if (header) { section = group(header, 1); continue; }
    if (section !== "tool.poetry.dependencies" && section !== "tool.poetry.dev-dependencies") continue;
    const kv = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*=\s*(.+)$/.exec(line);
    if (!kv || group(kv, 1) === "python") continue;
    const value = group(kv, 2).replace(/#.*$/, "").trim();
    const versionMatch = /["']([^"']+)["']/.exec(value);
    push(out, component("pypi", group(kv, 1), versionMatch ? group(versionMatch, 1) : value, rel));
  }
}

function parsePipfile(content: string, rel: string, out: Component[]): void {
  let section = "";
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    const header = /^\[([^\]]+)\]/.exec(line);
    if (header) { section = group(header, 1); continue; }
    if (section !== "packages" && section !== "dev-packages") continue;
    const kv = /^["']?([A-Za-z0-9][A-Za-z0-9._-]*)["']?\s*=\s*(.+)$/.exec(line);
    if (!kv) continue;
    const versionMatch = /["']([^"']+)["']/.exec(group(kv, 2));
    push(out, component("pypi", group(kv, 1), versionMatch ? group(versionMatch, 1) : group(kv, 2), rel));
  }
}

function parseGoMod(content: string, rel: string, out: Component[]): void {
  let inRequireBlock = false;
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (inRequireBlock) {
      if (line.startsWith(")")) { inRequireBlock = false; continue; }
      const m = /^(\S+)\s+(\S+)/.exec(line);
      if (m) push(out, component("go", group(m, 1), group(m, 2), rel));
      continue;
    }
    const single = /^require\s+(\S+)\s+(\S+)/.exec(line);
    if (single) { push(out, component("go", group(single, 1), group(single, 2), rel)); continue; }
    if (/^require\s*\($/.test(line)) inRequireBlock = true;
  }
}

function parseCargoToml(content: string, rel: string, out: Component[]): void {
  let section = "";
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    const header = /^\[([^\]]+)\]/.exec(line);
    if (header) { section = group(header, 1); continue; }
    if (section !== "dependencies" && section !== "dev-dependencies" && section !== "build-dependencies") continue;
    const kv = /^["']?([A-Za-z0-9][A-Za-z0-9._-]*)["']?\s*=\s*(.+)$/.exec(line);
    if (!kv) continue;
    const versionMatch = /["']([^"']+)["']/.exec(group(kv, 2));
    push(out, component("cargo", group(kv, 1), versionMatch ? group(versionMatch, 1) : group(kv, 2), rel));
  }
}

function parsePomXml(content: string, rel: string, out: Component[]): void {
  const blockRegex = /<dependency>([\s\S]*?)<\/dependency>/g;
  let m: RegExpExecArray | null;
  while ((m = blockRegex.exec(content)) !== null) {
    const block = group(m, 1);
    const groupMatch = /<groupId>([^<]+)<\/groupId>/.exec(block);
    const artifact = /<artifactId>([^<]+)<\/artifactId>/.exec(block);
    const version = /<version>([^<]+)<\/version>/.exec(block);
    if (!artifact) continue;
    const name = groupMatch ? group(groupMatch, 1) + ":" + group(artifact, 1) : group(artifact, 1);
    push(out, component("maven", name, version ? group(version, 1) : "", rel));
  }
}

function parseComposerJson(content: string, rel: string, out: Component[]): void {
  let pkg: Record<string, unknown>;
  try {
    pkg = JSON.parse(content) as Record<string, unknown>;
  } catch {
    return;
  }
  for (const field of ["require", "require-dev"]) {
    const deps = pkg[field];
    if (!deps || typeof deps !== "object") continue;
    for (const [name, range] of Object.entries(deps as Record<string, unknown>)) {
      if (typeof range !== "string") continue;
      if (name === "php" || name.startsWith("ext-") || name.startsWith("lib-")) continue;
      push(out, component("composer", name, range, rel));
    }
  }
}

function parseGemfile(content: string, rel: string, out: Component[]): void {
  const regex = /^\s*gem\s+["']([^"']+)["'](?:\s*,\s*["']([^"']+)["'])?/gm;
  let m: RegExpExecArray | null;
  while ((m = regex.exec(content)) !== null) {
    push(out, component("gem", group(m, 1), group(m, 2), rel));
  }
}

function parseDockerfile(content: string, rel: string, out: Component[]): void {
  for (const rawLine of content.split(/\r?\n/)) {
    const m = /^\s*FROM\s+(\S+)(?:\s+[Aa][Ss]\s+\S+)?\s*$/.exec(rawLine);
    if (!m) continue;
    const image = group(m, 1);
    if (image === "scratch" || image.includes("$")) continue;
    const at = image.indexOf("@");
    if (at > 0) {
      push(out, component("docker", image.slice(0, at), image.slice(at + 1), rel));
      continue;
    }
    const colon = image.lastIndexOf(":");
    if (colon > image.lastIndexOf("/")) {
      push(out, component("docker", image.slice(0, colon), image.slice(colon + 1), rel));
    } else {
      push(out, component("docker", image, "", rel));
    }
  }
}

function parseComposeYaml(content: string, rel: string, out: Component[]): void {
  const regex = /^\s*image:\s*["']?([^"'\s#]+)/gm;
  let m: RegExpExecArray | null;
  while ((m = regex.exec(content)) !== null) {
    const image = group(m, 1);
    if (image === "scratch" || image.includes("$")) continue;
    const at = image.indexOf("@");
    if (at > 0) {
      push(out, component("docker", image.slice(0, at), image.slice(at + 1), rel));
      continue;
    }
    const colon = image.lastIndexOf(":");
    if (colon > image.lastIndexOf("/")) {
      push(out, component("docker", image.slice(0, colon), image.slice(colon + 1), rel));
    } else {
      push(out, component("docker", image, "", rel));
    }
  }
}

function parseWorkflowUses(content: string, rel: string, out: Component[]): void {
  const regex = /^\s*-?\s*uses:\s*["']?([^"'\s#]+)/gm;
  let m: RegExpExecArray | null;
  while ((m = regex.exec(content)) !== null) {
    const ref = group(m, 1);
    if (ref.startsWith("docker://") || ref.startsWith("./")) continue;
    const at = ref.lastIndexOf("@");
    if (at <= 0) continue;
    const name = ref.slice(0, at);
    const version = ref.slice(at + 1).replace(/^v(?=\d)/, "");
    push(out, component("github-actions", name, version, rel));
  }
}
