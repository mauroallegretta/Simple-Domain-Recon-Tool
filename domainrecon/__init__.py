"""
domain-recon: profile suspicious domains - registration, DNS, mail and a rendered capture of the
site - describe each page with AI, compare it with the domain being monitored, and prepare
takedown reports.

    collect/   gathering the facts about a domain (no AI)
    ai/        describing a page with whichever AI service the key belongs to
    report/    turning results into text: summary, email prose, Markdown, JSONL
    store/     the optional results database and the history of checks
    takedown/  qualification, abuse contacts, evidence and draft reports (nothing is sent)
    web/       the browser interface
    pipeline   collect -> describe -> summarise, for a list of domains
    cli        the command line:  python -m domainrecon --help   (or ./recon --help)
"""
