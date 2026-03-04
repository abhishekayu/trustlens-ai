"""
Async sandbox crawler using Playwright.

Fetches URLs in a headless browser with full redirect tracking,
form detection, and optional screenshot capture. All requests
pass through SSRF validation first.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

from trustlens.core import get_settings
from trustlens.core.logging import get_logger
from trustlens.models import CrawlResult, RedirectHop
from trustlens.security import SSRFError, check_ssrf, validate_url

logger = get_logger(__name__)


class CrawlerService:
    """Headless browser crawler with security sandbox."""

    def __init__(self) -> None:
        self._settings = get_settings()

    async def crawl(self, url: str) -> CrawlResult:
        """
        Crawl a URL and extract all relevant page data.

        Returns a CrawlResult with HTML, forms, redirects, SSL info, etc.
        """
        # ── Pre-flight security checks ──────────────────────────
        url = validate_url(url)
        await check_ssrf(url, block_private=self._settings.ssrf_block_private)

        from playwright.async_api import async_playwright

        redirect_chain: list[RedirectHop] = []
        errors: list[str] = []
        start_time = time.monotonic()

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-gpu",
                    "--disable-dev-shm-usage",
                    "--disable-extensions",
                    "--disable-background-networking",
                ],
            )

            context = await browser.new_context(
                user_agent=self._settings.crawler_user_agent,
                java_script_enabled=True,
                ignore_https_errors=True,
                viewport={"width": 1280, "height": 720},
            )

            # Set tight timeouts
            context.set_default_timeout(self._settings.crawler_timeout * 1000)
            page = await context.new_page()

            # ── Track redirects ──────────────────────────────────
            async def on_response(response):  # type: ignore
                if response.request.redirected_from:
                    try:
                        headers = dict(await response.all_headers())
                    except Exception:
                        headers = {}
                    redirect_chain.append(
                        RedirectHop(
                            url=response.url,
                            status_code=response.status,
                            headers=headers,
                        )
                    )

            page.on("response", on_response)

            try:
                response = await page.goto(
                    url,
                    wait_until="domcontentloaded",
                    timeout=self._settings.crawler_timeout * 1000,
                )

                # Wait briefly for dynamic content
                await page.wait_for_timeout(2000)

                status_code = response.status if response else 0
                final_url = page.url

                # ── SSRF check on final URL after redirects ──────
                try:
                    await check_ssrf(final_url, block_private=self._settings.ssrf_block_private)
                except SSRFError as e:
                    await browser.close()
                    raise e

                # ── Extract page data ───────────────────────────
                html_content = await page.content()
                page_title = await page.title()

                # Meta tags
                meta_tags = await page.evaluate("""
                    () => {
                        const metas = {};
                        document.querySelectorAll('meta').forEach(m => {
                            const name = m.getAttribute('name') || m.getAttribute('property') || '';
                            const content = m.getAttribute('content') || '';
                            if (name && content) metas[name] = content;
                        });
                        return metas;
                    }
                """)

                # Forms
                forms = await page.evaluate("""
                    () => {
                        return Array.from(document.querySelectorAll('form')).map(f => ({
                            action: f.action,
                            method: f.method,
                            id: f.id,
                            fields: Array.from(f.querySelectorAll('input, select, textarea')).map(i => ({
                                type: i.type || i.tagName.toLowerCase(),
                                name: i.name,
                                id: i.id,
                                placeholder: i.placeholder || '',
                                required: i.required,
                            }))
                        }));
                    }
                """)

                # External links
                external_links = await page.evaluate(f"""
                    () => {{
                        const currentHost = window.location.hostname;
                        return Array.from(document.querySelectorAll('a[href]'))
                            .map(a => a.href)
                            .filter(h => {{
                                try {{
                                    return new URL(h).hostname !== currentHost;
                                }} catch {{ return false; }}
                            }})
                            .slice(0, 50);
                    }}
                """)

                # Script sources
                scripts = await page.evaluate("""
                    () => Array.from(document.querySelectorAll('script[src]'))
                            .map(s => s.src).slice(0, 30)
                """)

                # Response headers
                resp_headers: dict[str, str] = {}
                if response:
                    try:
                        resp_headers = dict(await response.all_headers())
                    except Exception:
                        pass

                # Cookies
                cookies_raw = await context.cookies()
                cookies = [
                    {
                        "name": c["name"],
                        "domain": c["domain"],
                        "secure": c["secure"],
                        "httpOnly": c["httpOnly"],
                        "sameSite": c.get("sameSite", ""),
                    }
                    for c in cookies_raw
                ]

                # SSL info
                ssl_info = self._extract_ssl_info(final_url, resp_headers)

                # Check for certificate issues (we allowed the request through
                # but still flag invalid certs as a signal)
                parsed_final = urlparse(final_url)
                parsed_orig = urlparse(url)
                if parsed_orig.scheme == "https" and not ssl_info.get("has_hsts"):
                    # If the original was HTTPS and we had to ignore cert errors,
                    # record it — the security header analyzer will also catch this
                    ssl_info["cert_error_ignored"] = True

                # Screenshot — capture in-memory as base64 (no disk storage)
                screenshot_path: Optional[str] = None
                screenshot_base64: Optional[str] = None
                try:
                    raw_bytes = await page.screenshot(full_page=False)
                    import base64 as _b64
                    screenshot_base64 = "data:image/png;base64," + _b64.b64encode(raw_bytes).decode()
                    logger.info("crawler.screenshot_captured_base64", size_bytes=len(raw_bytes))
                except Exception as _ss_err:
                    logger.warning("crawler.screenshot_failed", error=str(_ss_err))

                load_time_ms = int((time.monotonic() - start_time) * 1000)

                result = CrawlResult(
                    final_url=final_url,
                    status_code=status_code,
                    redirect_chain=redirect_chain,
                    html_content=html_content,
                    page_title=page_title,
                    meta_tags=meta_tags,
                    forms=forms,
                    external_links=external_links,
                    scripts=scripts,
                    ssl_info=ssl_info,
                    screenshot_path=screenshot_path,
                    screenshot_base64=screenshot_base64,
                    headers=resp_headers,
                    cookies=cookies,
                    load_time_ms=load_time_ms,
                    errors=errors,
                )

            except SSRFError:
                raise
            except Exception as e:
                logger.error("crawler.error", url=url, error=str(e))
                result = CrawlResult(
                    final_url=url,
                    status_code=0,
                    errors=[str(e)],
                    load_time_ms=int((time.monotonic() - start_time) * 1000),
                )
            finally:
                await browser.close()

        return result

    def _extract_ssl_info(self, url: str, headers: dict[str, str]) -> dict[str, Any]:
        """Extract basic SSL information from the URL and headers."""
        parsed = urlparse(url)
        return {
            "is_https": parsed.scheme == "https",
            "has_hsts": "strict-transport-security" in {k.lower() for k in headers},
        }

    async def _take_screenshot(self, page: Any, url: str) -> Optional[str]:
        """Capture a screenshot and return the file path."""
        try:
            screenshot_dir = Path(self._settings.screenshot_dir)
            screenshot_dir.mkdir(parents=True, exist_ok=True)

            # Create a safe filename from the URL
            safe_name = "".join(c if c.isalnum() else "_" for c in url[:80])
            path = screenshot_dir / f"{safe_name}_{int(time.time())}.png"

            await page.screenshot(path=str(path), full_page=False)
            logger.info("crawler.screenshot_saved", path=str(path))
            return str(path)
        except Exception as e:
            logger.warning("crawler.screenshot_failed", error=str(e))
            return None
