#!-*-coding:UTF-8-*-
import optparse, random, re, string, urllib, urllib2,difflib,itertools,httplib

NAME = "Scanner for RXSS and SQLI"
AUTHOR = "Lishuze"
PREFIXES = (" ", ") ", "' ", "') ", "\"")
SUFFIXES = ("", "-- -", "#")
BOOLEAN_TESTS = ("AND %d=%d", "OR NOT (%d=%d)")
TAMPER_SQL_CHAR_POOL = ('(', ')', '\'', '"''"')
TAMPER_XSS_CHAR_POOL = ('\'', '"', '>', '<', ';')
GET, POST = "GET", "POST"
COOKIE, UA, REFERER = "Cookie", "User-Agent", "Referer"
TEXT, HTTPCODE, TITLE, HTML = xrange(4)
_headers = {}

USER_AGENTS = (
    "Mozilla/5.0 (X11; Linux i686; rv:38.0) Gecko/20100101 Firefox/38.0",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.101 Safari/537.36",
    "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_7_0; en-US) AppleWebKit/534.21 (KHTML, like Gecko) Chrome/11.0.678.0 Safari/534.21",
)

XSS_PATTERNS = (
    (r"<!--[^>]*%(chars)s|%(chars)s[^<]*-->","\"<!--.'.xss.'.-->\", inside the comment", None),
    (r"(?s)<script[^>]*>[^<]*?'[^<']*%(chars)s|%(chars)s[^<']*'[^<]*</script>","\"<script>.'.xss.'.</script>\", enclosed by <script> tags, inside single-quotes", None),
    (r'(?s)<script[^>]*>[^<]*?"[^<"]*%(chars)s|%(chars)s[^<"]*"[^<]*</script>',"'<script>.\".xss.\".</script>', enclosed by <script> tags, inside double-quotes", None),
    (r"(?s)<script[^>]*>[^<]*?%(chars)s|%(chars)s[^<]*</script>","\"<script>.xss.</script>\", enclosed by <script> tags", None),
    (r">[^<]*%(chars)s[^<]*(<|\Z)", "\">.xss.<\", outside of tags", r"(?s)<script.+?</script>|<!--.*?-->"),
    (r"<[^>]*'[^>']*%(chars)s[^>']*'[^>]*>", "\"<.'.xss.'.>\", inside the tag, inside single-quotes", r"(?s)<script.+?</script>|<!--.*?-->"),
    (r'<[^>]*"[^>"]*%(chars)s[^>"]*"[^>]*>', "'<.\".xss.\".>', inside the tag, inside double-quotes", r"(?s)<script.+?</script>|<!--.*?-->"),
    (r"<[^>]*%(chars)s[^>]*>", "\"<.xss.>\", inside the tag, outside of quotes", r"(?s)<script.+?</script>|<!--.*?-->")
)

# DBMS_ERRORS = {
#     "MySQL": (r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result", r"MySqlClient\."),
#     "Microsoft SQL Server": (r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server", r"(\W|\A)SQL Server.*Driver", r"Warning.*mssql_.*", r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}", r"(?s)Exception.*\WSystem\.Data\.SqlClient\.", r"(?s)Exception.*\WRoadhouse\.Cms\."),
#     "Microsoft Access": (r"Microsoft Access Driver", r"JET Database Engine", r"Access Database Engine"),
#     "Oracle": (r"ORA-[0-9][0-9][0-9][0-9]", r"Oracle error", r"Oracle.*Driver", r"Warning.*\Woci_.*", r"Warning.*\Wora_.*")
# }

DBMS_ERRORS = {# regular expressions used for DBMS recognition based on error message response
    "MySQL": (r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result", r"MySqlClient\."),
    "PostgreSQL": (r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*", r"valid PostgreSQL result", r"Npgsql\."),
    "Microsoft SQL Server": (r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server", r"(\W|\A)SQL Server.*Driver", r"Warning.*mssql_.*", r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}", r"(?s)Exception.*\WSystem\.Data\.SqlClient\.", r"(?s)Exception.*\WRoadhouse\.Cms\."),
    "Microsoft Access": (r"Microsoft Access Driver", r"JET Database Engine", r"Access Database Engine"),
    "Oracle": (r"\bORA-[0-9][0-9][0-9][0-9]", r"Oracle error", r"Oracle.*Driver", r"Warning.*\Woci_.*", r"Warning.*\Wora_.*"),
    "IBM DB2": (r"CLI Driver.*DB2", r"DB2 SQL error", r"\bdb2_\w+\("),
    "SQLite": (r"SQLite/JDBCDriver", r"SQLite.Exception", r"System.Data.SQLite.SQLiteException", r"Warning.*sqlite_.*", r"Warning.*SQLite3::", r"\[SQLITE_ERROR\]"),
    "Sybase": (r"(?i)Warning.*sybase.*", r"Sybase message", r"Sybase.*Server message.*"),
}

def _retrieve_content_xss(url, data=None):
    surl=""
    for i in xrange(len(url)):
        if i > url.find('?'):
            surl+=surl.join(url[i]).replace(' ',"%20")
        else:
            surl+=surl.join(url[i])
        try:
            req = urllib2.Request(surl, data, _headers)
            retval = urllib2.urlopen(req, timeout=30).read()
        except Exception as ex:
            retval = getattr(ex, "message", "")
        return retval or ""

def scan_page_xss(url, data=None):
    retval, usable = False, False
    url = re.sub(r"=(&|\Z)", "=1\g<1>", url) if url else url
    data=re.sub(r"=(&|\Z)", "=1\g<1>", data) if data else data
    try:
        for phase in (GET, POST):
            current = url if phase is GET else (data or "")
            for match in re.finditer(r"((\A|[?&])(?P<parameter>[\w]+)=)(?P<value>[^&]+)", current):
                found, usable = False, True
                print("Scanning %s parameter '%s'" % (phase, match.group("parameter")))
                prefix = ("".join(random.sample(string.ascii_lowercase, 5)))
                suffix = ("".join(random.sample(string.ascii_lowercase, 5)))
                if not found:
                    tampered = current.replace(match.group(0), "%s%s" % (match.group(0), urllib.quote("%s%s%s%s" % ("'", prefix, "".join(random.sample(TAMPER_XSS_CHAR_POOL, len(TAMPER_XSS_CHAR_POOL))), suffix))))
                    content = _retrieve_content_xss(tampered, data) if phase is GET else _retrieve_content_xss(url, tampered)
                for sample in re.finditer("%s([^ ]+?)%s" % (prefix, suffix), content, re.I):
                #print sample.group()
        for regex, info, content_removal_regex in XSS_PATTERNS:
        context = re.search(regex % {"chars": re.escape(sample.group(0))}, re.sub(content_removal_regex or "", "", content), re.I)
        if context and not found and sample.group(1).strip():
            print "!!!%s parameter '%s' appears to be XSS vulnerable (%s)" % (phase, match.group("parameter"), info)
        found = retval = True
        if not usable:
            print " (x) no usable GET/POST parameters found"
    except KeyboardInterrupt:
        print "\r (x) Ctrl-C pressed"
        return retval

def _retrieve_content_sql(url, data=None):
    retval = {HTTPCODE: httplib.OK}
    surl=""
    for i in xrange(len(url)):
        if i > url.find('?'):
            surl+=surl.join(url[i]).replace(' ',"%20")
        else:
            surl+=surl.join(url[i])
        try:
            req = urllib2.Request(surl, data, _headers)
            retval[HTML] = urllib2.urlopen(req, timeout=30).read()
        except Exception as ex:
            retval[HTTPCODE] = getattr(ex, "code", None)
            retval[HTML] = getattr(ex, "message", "")
            match = re.search(r"<title>(?P<result>[^<]+)</title>", retval[HTML], re.I)
            retval[TITLE] = match.group("result") if match else None
            retval[TEXT] = re.sub(r"(?si)<script.+?</script>|<!--.+?-->|<style.+?</style>|<[^>]+>|\s+", " ", retval[HTML])
            return retval

def scan_page_sql(url, data=None):
    print("Start scanning SQLI:\n")
    retval, usable = False, False
    url = re.sub(r"=(&|\Z)", "=1\g<1>", url) if url else url
    data=re.sub(r"=(&|\Z)", "=1\g<1>", data) if data else data
    try:
        for phase in (GET, POST):
        current = url if phase is GET else (data or "")
        for match in re.finditer(r"((\A|[?&])(?P<parameter>\w+)=)(?P<value>[^&]+)", current):
        vulnerable, usable = False, True
        original=None
        print "Scanning %s parameter '%s'" % (phase, match.group("parameter"))
        tampered = current.replace(match.group(0), "%s%s" % (match.group(0), urllib.quote("".join(random.sample(TAMPER_SQL_CHAR_POOL, len(TAMPER_SQL_CHAR_POOL))))))
        content = _retrieve_content_sql(tampered, data) if phase is GET else _retrieve_content_sql(url, tampered)
        for (dbms, regex) in ((dbms, regex) for dbms in DBMS_ERRORS for regex in DBMS_ERRORS[dbms]):
        if not vulnerable and re.search(regex, content[HTML], re.I):
        print "!!!%s parameter '%s' could be error SQLi vulnerable (%s)" % (phase, match.group("parameter"), dbms)
        retval = vulnerable = True
        vulnerable = False
        original = original or (_retrieve_content_sql(current, data) if phase is GET else _retrieve_content_sql(url, current))
        for prefix,boolean,suffix in itertools.product(PREFIXES,BOOLEAN_TESTS,SUFFIXES):
        if not vulnerable:
        template = "%s%s%s" % (prefix,boolean, suffix)
        payloads = dict((_, current.replace(match.group(0), "%s%s" % (match.group(0), urllib.quote(template % (1 if _ else 2, 1), safe='%')))) for _ in (True, False))
        contents = dict((_, _retrieve_content_sql(payloads[_], data) if phase is GET else _retrieve_content_sql(url, payloads[_])) for _ in (False, True))
        if all(_[HTTPCODE] for _ in (original, contents[True], contents[False])) and (any(original[_] == contents[True][_] != contents[False][_] for _ in (HTTPCODE, TITLE))):
        vulnerable = True
        else:
            ratios = dict((_, difflib.SequenceMatcher(None, original[TEXT], contents[_][TEXT]).quick_ratio()) for _ in (True, False))
            vulnerable = all(ratios.values()) and ratios[True] > 0.95 and ratios[False] < 0.95
        if vulnerable:
            print("!!!%s parameter '%s' could be error Blind SQLi vulnerable" % (phase, match.group("parameter")))
            retval = True
        if not usable:
            print(" (x) no usable GET/POST parameters found")
    except KeyboardInterrupt as e:
        print("\r (x) Ctrl-C pressed")
        return retval

def init_options(proxy=None, cookie=None, ua=None, referer=None):
    global _headers
    _headers = dict(filter(lambda _: _[1], ((COOKIE, cookie), (UA, ua or NAME), (REFERER, referer))))
    urllib2.install_opener(urllib2.build_opener(urllib2.ProxyHandler({'http': proxy})) if proxy else None)
    if __name__ == "__main__":
        print
        "----------------------------------------------------------------------------------"
    print
    "%s\nBy:%s" % (NAME, AUTHOR)
    print
    "----------------------------------------------------------------------------------"
    parser = optparse.OptionParser()
    parser.add_option("--url", dest="url", help="Target URL")
    parser.add_option("--data", dest="data", help="POST data")
    parser.add_option("--cookie", dest="cookie", help="HTTP Cookie header value")
    parser.add_option("--user-agent", dest="ua", help="HTTP User-Agent header value")
    parser.add_option("--random-agent", dest="randomAgent", action="store_true",
                      help="Use randomly selected HTTP User-Agent header value")
    parser.add_option("--referer", dest="referer", help="HTTP Referer header value")
    parser.add_option("--proxy", dest="proxy", help="HTTP proxy address")
    options, _ = parser.parse_args()
    if options.url:
        init_options(options.proxy, options.cookie,
                     options.ua if not options.randomAgent else random.choice(USER_AGENTS), options.referer)
    result_xss = scan_page_xss(options.url if options.url.startswith("http") else "http://%s" % options.url,
                               options.data)
    print
    "\nScan results: %s vulnerabilities found" % ("possible" if result_xss else "no")
    print
    "----------------------------------------------------------------------------------"
    result_sql = scan_page_sql(options.url if options.url.startswith("http") else "http://%s" % options.url,
                               options.data)
    print
    "\nScan results: %s vulnerabilities found" % ("possible" if result_sql else "no")
    print
    "----------------------------------------------------------------------------------"
    else:
        parser.print_help()