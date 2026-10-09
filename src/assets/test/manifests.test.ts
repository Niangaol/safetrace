import assert from "node:assert/strict";
import test from "node:test";
import { parseManifest } from "../src/manifests.js";

const DOLLAR = "$";
const PROP_VERSION = "<version>" + DOLLAR + "{revision}</version>";
const ARG_IMAGE = "FROM argimage:" + DOLLAR + "{TAG}";

test("package.json：依赖分级 + 范围下界 + 精确锁定 + 框架识别", () => {
  const content = JSON.stringify({
    dependencies: { vue: "^3.5.0", axios: "1.7.2" },
    devDependencies: { typescript: "~5.7.0" },
    peerDependencies: { react: "*" },
    engines: { node: ">=20" },
    packageManager: "npm@10.9.0",
  });
  const result = parseManifest("package.json", content);
  const byName = new Map(result.components.map((c) => [c.name, c]));
  assert.equal(byName.get("vue")!.version, "3.5.0", "范围约束保留下界字面量");
  assert.equal(byName.get("vue")!.version_is_range_floor, true);
  assert.equal(byName.get("vue")!.constraint_raw, "^3.5.0");
  assert.equal(byName.get("axios")!.version, "1.7.2");
  assert.equal(byName.get("axios")!.version_is_range_floor, false);
  assert.equal(byName.get("typescript")!.version, "5.7.0");
  assert.equal(byName.get("typescript")!.version_is_range_floor, true);
  assert.equal(byName.get("react")!.version, "", "通配符不猜版本");
  assert.equal(byName.get("react")!.version_is_range_floor, true);
  assert.equal(byName.get("react")!.constraint_raw, "*");
  assert.ok(result.languages.includes("Node.js"));
  assert.ok(result.languages.some((l) => l.startsWith("Node ")));
  assert.ok(result.frameworks.includes("Vue"));
  assert.ok(result.frameworks.includes("TypeScript"));
});

test("package.json：坏 JSON 不抛错，产出空组件", () => {
  const result = parseManifest("package.json", "{ not json");
  assert.deepEqual(result.components, []);
  assert.ok(result.languages.includes("Node.js"));
});

test("requirements.txt：== 锁定 / >= 范围 / 注释与 -r 跳过", () => {
  const result = parseManifest("requirements.txt", [
    "# 注释",
    "-r base.txt",
    "flask==3.0.0",
    "requests>=2.31.0 ; python_version >= '3.8'",
    "django",
  ].join("\n"));
  const byName = new Map(result.components.map((c) => [c.name, c]));
  assert.equal(byName.get("flask")!.version, "3.0.0");
  assert.equal(byName.get("flask")!.version_is_range_floor, false);
  assert.equal(byName.get("requests")!.version, "2.31.0");
  assert.equal(byName.get("requests")!.version_is_range_floor, true);
  assert.equal(byName.get("django")!.version, "");
  assert.ok(result.languages.includes("Python"));
  assert.ok(result.frameworks.includes("Flask"));
  assert.ok(result.frameworks.includes("Django"));
});

test("pyproject.toml：PEP 621 数组 + Poetry 表双形态", () => {
  const content = [
    "[project]",
    "name = \"demo\"",
    "dependencies = [",
    "  \"fastapi>=0.110\",",
    "  \"uvicorn[standard]==0.29.0\",",
    "]",
    "[tool.poetry.dependencies]",
    "python = \"^3.11\"",
    "pandas = \"^2.2.0\"",
    "numpy = { version = \"1.26.4\", optional = true }",
  ].join("\n");
  const result = parseManifest("pyproject.toml", content);
  const byName = new Map(result.components.map((c) => [c.name, c]));
  assert.equal(byName.get("fastapi")!.version, "0.110");
  assert.equal(byName.get("fastapi")!.version_is_range_floor, true);
  assert.equal(byName.get("uvicorn")!.version, "0.29.0", "extras 方括号不能截断数组解析");
  assert.equal(byName.get("uvicorn")!.version_is_range_floor, false);
  assert.equal(byName.get("pandas")!.version, "2.2.0");
  assert.equal(byName.get("numpy")!.version, "1.26.4");
  assert.ok(!byName.has("python"), "poetry 的 python 约束不是组件");
  assert.ok(result.frameworks.includes("FastAPI"));
});

test("go.mod：require 块与单行两种形态，版本去 v 前缀", () => {
  const content = [
    "module demo",
    "go 1.22",
    "require (",
    "\tgithub.com/gin-gonic/gin v1.9.1",
    "\tgolang.org/x/text v0.14.0 // indirect",
    ")",
    "require github.com/stretchr/testify v1.8.4",
  ].join("\n");
  const result = parseManifest("go.mod", content);
  const byName = new Map(result.components.map((c) => [c.name, c]));
  assert.equal(byName.get("github.com/gin-gonic/gin")!.version, "1.9.1");
  assert.equal(byName.get("github.com/gin-gonic/gin")!.version_is_range_floor, false);
  assert.equal(byName.get("golang.org/x/text")!.version, "0.14.0");
  assert.equal(byName.get("github.com/stretchr/testify")!.version, "1.8.4");
  assert.ok(result.languages.includes("Go"));
  assert.ok(result.frameworks.includes("Gin"));
});

test("Cargo.toml：字符串与内联表两种版本写法", () => {
  const content = [
    "[dependencies]",
    "serde = \"1.0.197\"",
    "tokio = { version = \"1.38.0\", features = [\"full\"] }",
    "[dev-dependencies]",
    "criterion = \"0.5.1\"",
  ].join("\n");
  const result = parseManifest("Cargo.toml", content);
  const byName = new Map(result.components.map((c) => [c.name, c]));
  assert.equal(byName.get("serde")!.version, "1.0.197");
  assert.equal(byName.get("tokio")!.version, "1.38.0");
  assert.equal(byName.get("criterion")!.version, "0.5.1");
  assert.ok(result.languages.includes("Rust"));
});

test("pom.xml：groupId:artifactId 命名，属性版本视为未锁定", () => {
  const content = [
    "<project>",
    "  <dependencies>",
    "    <dependency>",
    "      <groupId>org.springframework.boot</groupId>",
    "      <artifactId>spring-boot-starter-web</artifactId>",
    "      <version>3.2.0</version>",
    "    </dependency>",
    "    <dependency>",
    "      <groupId>com.example</groupId>",
    "      <artifactId>widget</artifactId>",
    "      " + PROP_VERSION,
    "    </dependency>",
    "  </dependencies>",
    "</project>",
  ].join("\n");
  const result = parseManifest("pom.xml", content);
  const byName = new Map(result.components.map((c) => [c.name, c]));
  assert.equal(byName.get("org.springframework.boot:spring-boot-starter-web")!.version, "3.2.0");
  assert.equal(byName.get("com.example:widget")!.version, "");
  assert.equal(byName.get("com.example:widget")!.version_is_range_floor, true);
  assert.ok(result.languages.includes("Java"));
});

test("composer.json / Gemfile / Dockerfile / compose / workflow", () => {
  const composer = parseManifest("composer.json", JSON.stringify({ require: { php: ">=8.1", "ext-json": "*", "laravel/framework": "^10.0" } }));
  assert.equal(composer.components.length, 1);
  assert.equal(composer.components[0]!.name, "laravel/framework");
  assert.equal(composer.components[0]!.version, "10.0");

  const gem = parseManifest("Gemfile", "source 'https://rubygems.org'\ngem 'rails', '7.1.2'\ngem 'puma'");
  const gemByName = new Map(gem.components.map((c) => [c.name, c]));
  assert.equal(gemByName.get("rails")!.version, "7.1.2");
  assert.equal(gemByName.get("puma")!.version, "");

  const docker = parseManifest("Dockerfile", [
    "FROM node:20-alpine AS build",
    "RUN echo hi",
    "FROM scratch",
    "FROM myimg:1.2.3",
    "FROM no-tag-image",
    ARG_IMAGE,
  ].join("\n"));
  const dockerByName = new Map(docker.components.map((c) => [c.name, c]));
  assert.equal(dockerByName.get("node")!.version, "20", "tag 取字面量");
  assert.equal(dockerByName.get("node")!.version_is_range_floor, false);
  assert.equal(dockerByName.get("myimg")!.version, "1.2.3");
  assert.equal(dockerByName.get("no-tag-image")!.version, "");
  assert.ok(!dockerByName.has("scratch"));
  assert.ok(!dockerByName.has("argimage"));
  assert.ok(docker.frameworks.includes("Docker"));

  const compose = parseManifest("docker-compose.yml", "services:\n  web:\n    image: nginx:1.25\n  db:\n    image: postgres");
  assert.equal(compose.components.length, 2);

  const workflow = parseManifest(".github/workflows/ci.yml", "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/setup-node@v4.0.2\n      - uses: ./local-action");
  const wfByName = new Map(workflow.components.map((c) => [c.name, c]));
  assert.equal(wfByName.get("actions/checkout")!.version, "4");
  assert.equal(wfByName.get("actions/setup-node")!.version, "4.0.2");
  assert.equal(wfByName.size, 2);
  assert.equal(workflow.components[0]!.ecosystem, "github-actions");
});

test("未知文件名返回空结果", () => {
  const result = parseManifest("README.md", "# hello");
  assert.deepEqual(result.components, []);
  assert.deepEqual(result.languages, []);
});
