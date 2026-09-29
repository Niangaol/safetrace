import { fetchPageWithFallback } from "../src/ingest/src/firecrawl.js";

const url = process.argv[2];
if (!url) {
  console.error("用法：FIRECRAWL_ENABLED=true FIRECRAWL_ALLOWED_HOSTS=vendor.example npm run crawl:page -- https://vendor.example/advisory");
  process.exitCode = 2;
} else {
  const allowedHosts = (process.env.FIRECRAWL_ALLOWED_HOSTS ?? "").split(",").map((host) => host.trim()).filter(Boolean);
  if (process.env.FIRECRAWL_ENABLED !== "true") {
    console.error("采集默认关闭；显式设置 FIRECRAWL_ENABLED=true 后再运行。未发起请求。");
    process.exitCode = 2;
  } else if (allowedHosts.length === 0) {
    console.error("必须设置精确的 FIRECRAWL_ALLOWED_HOSTS；未发起请求。");
    process.exitCode = 2;
  } else {
    try {
      const result = await fetchPageWithFallback(url, {
        enabled: true,
        respect_robots: true,
        allowed_hosts: allowedHosts,
        firecrawl_api_key: process.env.FIRECRAWL_API_KEY,
        firecrawl_base_url: process.env.FIRECRAWL_BASE_URL,
        firecrawl_api_hosts: (process.env.FIRECRAWL_API_HOSTS ?? "api.firecrawl.dev").split(",").map((host) => host.trim()).filter(Boolean),
      });
      console.log(JSON.stringify({
        status: "untrusted_page_fetched_not_ingested",
        source_url: result.source_url,
        final_url: result.final_url,
        title: result.title,
        fetched_via: result.fetched_via,
        stale: result.stale,
        degraded_to: result.degraded_to,
        content_sha256: result.content_sha256,
        fallback_reasons: result.fallback_reasons,
        text_preview: result.text.slice(0, 500),
      }, null, 2));
    } catch (error) {
      console.error(error instanceof Error ? error.message : String(error));
      process.exitCode = 1;
    }
  }
}
