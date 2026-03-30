import datetime
import httpx
from sqlalchemy.orm import Session

from database import Scan, Endpoint, Finding, ScanStatus, Severity
from crawler.crawler import APICrawler, build_auth_headers
from scanner import nuclei_runner
from scanner.tests import sql_injection, xss, auth, cors, headers, rate_limit, info_disclosure, graphql


def run_scan(scan_id: int, base_url: str, db: Session,
             cookies: str = None, headers_json: str = None,
             enable_nuclei: bool = False, nuclei_tags: str = None):
    """Execute the full scan pipeline: crawl → security tests → save results."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return

    total_findings = 0

    def _save_results(test_name, results):
        nonlocal total_findings
        for r in results:
            finding = Finding(
                scan_id=scan_id,
                endpoint_url=r.endpoint_url,
                test_type=test_name,
                severity=Severity(r.severity),
                title=r.title,
                description=r.description,
                evidence=r.evidence,
            )
            db.add(finding)
            total_findings += 1
        scan.total_findings = total_findings
        db.commit()

    try:
        # Phase 1: Crawl
        scan.status = ScanStatus.CRAWLING
        db.commit()

        crawler = APICrawler(base_url, cookies=cookies, headers_json=headers_json)
        crawl_result = crawler.crawl()

        # Save discovered endpoints
        for ep in crawl_result.endpoints:
            db_endpoint = Endpoint(
                scan_id=scan_id,
                url=ep.url,
                method=ep.method,
                status_code=ep.status_code,
                content_type=ep.content_type,
                response_time=ep.response_time,
                source=ep.source,
                request_content_type=ep.request_content_type,
                request_params=ep.request_params,
                request_example=ep.request_example,
                response_body_sample=ep.response_body_sample,
            )
            db.add(db_endpoint)

        scan.total_endpoints = len(crawl_result.endpoints)
        db.commit()

        # Phase 2: Security tests
        scan.status = ScanStatus.SCANNING
        db.commit()

        # Prepare endpoint dicts — focus on endpoints that responded
        endpoint_dicts = [
            {
                "url": ep.url,
                "method": ep.method,
                "status_code": ep.status_code,
                "content_type": ep.content_type,
                "request_content_type": ep.request_content_type,
                "request_params": ep.request_params,
                "request_example": ep.request_example,
                "response_body_sample": ep.response_body_sample,
            }
            for ep in crawl_result.endpoints
            if ep.status_code is not None
        ]

        # Authenticated client (with cookies + headers)
        extra_headers = build_auth_headers(cookies, headers_json)
        client = httpx.Client(
            timeout=5.0,
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": "SecDashboard-Scanner/1.0", **extra_headers},
        )

        # Bare client (NO auth) for auth bypass tests
        noauth_client = httpx.Client(
            timeout=5.0,
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": "SecDashboard-Scanner/1.0"},
        )

        try:
            # Run tests — fast ones first, expensive ones last
            test_modules = [
                ("headers",          headers,          client),
                ("info_disclosure",  info_disclosure,  client),
                ("graphql",          graphql,          client),
                ("cors",             cors,             client),
                ("auth",             auth,             None),     # special: needs both clients
                ("rate_limit",       rate_limit,       client),
                ("sql_injection",    sql_injection,    client),
                ("xss",              xss,              client),
            ]

            for test_name, module, test_client in test_modules:
                try:
                    if test_name == "auth":
                        results = module.run(endpoint_dicts, client, noauth_client)
                    else:
                        results = module.run(endpoint_dicts, test_client)
                    _save_results(test_name, results)
                except Exception as e:
                    _save_results(test_name, [type('R', (), {
                        'endpoint_url': base_url, 'severity': 'info',
                        'title': f'Test module error: {test_name}',
                        'description': f'Error: {str(e)}', 'evidence': '',
                    })()])

            if enable_nuclei:
                try:
                    nuclei_results = nuclei_runner.run(
                        endpoint_dicts or [{"url": base_url}],
                        headers={"User-Agent": "SecDashboard-Scanner/1.0", **extra_headers},
                        tags=nuclei_tags,
                    )
                    _save_results("nuclei", nuclei_results)
                except Exception as e:
                    _save_results("nuclei", [type('R', (), {
                        'endpoint_url': base_url, 'severity': 'info',
                        'title': 'Test module error: nuclei',
                        'description': f'Error: {str(e)}', 'evidence': '',
                    })()])
        finally:
            client.close()
            noauth_client.close()

        # Finalize
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.datetime.utcnow()
        db.commit()

    except Exception as e:
        scan.status = ScanStatus.FAILED
        scan.completed_at = datetime.datetime.utcnow()
        failure_finding = Finding(
            scan_id=scan_id,
            endpoint_url=base_url,
            test_type="scan_runner",
            severity=Severity.INFO,
            title="Scan execution failed",
            description=str(e),
            evidence="",
        )
        db.add(failure_finding)
        scan.total_findings = (scan.total_findings or 0) + 1
        db.commit()
        raise e
