import re
from collections import Counter
from itertools import groupby

def is_likely_date(s):
    patterns_date = [
        r'\d{2,4}-\d{2,4}-\d{2,4}',
        r'\d{2,4}/\d{2,4}/\d{2,4}',
    ]

    patterns_time = [
        r'\d{2}:\d{2}:\d{2}',
        r'\d{2}:\d{2}:\d{2}\.\d+',
    ]

    patterns_tz = [
        r'\+\d{2}:\d{2}'
    ]
    
    def total_match(p, s):
        # return re.match("^" + p + "$", s)
        return re.search(p, s)

    for p in patterns_date:
        if total_match(p, s):
            return True
    for p in patterns_time:
        if total_match(p, s):
            return True
    for p in patterns_tz:
        if total_match(p, s):
            return True

    for p1 in patterns_date:
        for p2 in patterns_time:
            if total_match(p1 + " " + p2, s):
                return True
            for tz in patterns_tz:
                if total_match(p1 + " " + p2 + " " + tz, s):
                    return True
    return False

def is_like_log_level(s):
    patterns = [
        "TRACE",
        "DEBUG",
        "INFO",
        "WARN",
        "WARNING",
        "ERROR",
        "FATAL",
        "CRIT",
    ]

    def total_match(p, s):
        # return re.match("^" + p + "$", s)
        return re.search(p, s)

    for p in patterns:
        if total_match(p, s):
            return True
    return False

def distance(me, other):
    ns = len(me)
    no = len(other)
    dp = [[0 for i in range(no)] for j in range(ns)]
    for i in range(no):
        dp[0][i] = i
    for i in range(ns):
        dp[i][0] = i
    for i in range(1, ns):
        for j in range(1, no):
            if me[i] == other[j]:
                dp[i][j] = dp[i - 1][j - 1]
            else:
                dp[i][j] = 1 + min([dp[i - 1][j - 1], dp[i - 1][j], dp[i][j - 1]])
    return dp[ns - 1][no - 1]

class DSU:
    def __init__(self):
        self.fa = {}
        self.nodes = set()
        self.prec = {}
        self.need_reprec = True

    def find(self, x):
        if (not self.need_reprec) and x in self.prec:
            return self.prec[x]
        while x != self.fa[x]:
            x = self.fa[x]
        return x

    def union(self, x, y):
        self.need_reprec = True
        self.fa[x] = self.find(y)

    def add(self, x):
        self.need_reprec = True
        if x not in self.nodes:
            self.fa[x] = x
            self.nodes.add(x)

    def prehandle(self):
        for x in self.nodes:
            self.prec[x] = self.find(x)
        self.need_reprec = False

class Context:
    def __init__(self):
        self.digest_tree = DSU()

    def joint_summary(self, a, b):
        s1 = a.summary()
        s2 = b.summary()
        keys = set(list(s1.keys()) + list(s2.keys()))
        only_in_s1 = []
        only_in_s2 = []
        for k in keys:
            if k in s1 and not k in s2:
                only_in_s1.append((k, a.digests_family[k]))
            elif k in s2 and not k in s1:
                only_in_s2.append((k, b.digests_family[k]))

        f = open("joint.md", "w")
        f.write("\n====== Abnormal logs on Left ======\n".format(k))
        for (k, l) in only_in_s1:
            f.write("{}\n".format(k))
            f.write("```\n")
            for x in l:
                f.write("{}\n".format(x.replace("\n", "")))
            f.write("```\n")
        f.write("\n\n====== Abnormal logs on Right ======\n".format(k))
        for (k, l) in only_in_s2:
            f.write("{}\n".format(k))
            f.write("```\n")
            for x in l:
                f.write("{}\n".format(x.replace("\n", "")))
            f.write("```\n")
        f.close()

class LogItemExtractorOpts:
    def __init__(self):
        self.min_digest_feat = 3
        self.max_digest_feat = 10

class LogItemExtractor:
    def __init__(self, ctx, line):
        self.ctx = ctx
        self.line = line
        self.features = []
        self.opts = LogItemExtractorOpts()
        self.extract()

    def extract(self):
        elements = self.line.split()
        for e in elements:
            if e.isnumeric():
                self.features.append("")
            elif is_likely_date(e):
                self.features.append("")
            elif is_like_log_level(e):
                self.features.append("")
            elif len(e) > 45:
                self.features.append("")
            else:
                self.features.append(e)

    def digest(self):
        c = dict(Counter(self.features))
        # topk = [(k, c[k]) for k in sorted(c, key = c.get, reverse = True) if k != ""]
        topk = [(k, c[k]) for k in self.features if k != ""]
        n = int(len(topk) * 0.3)
        if n < self.opts.min_digest_feat:
            n = self.opts.min_digest_feat
        elif n > self.opts.max_digest_feat:
            n = self.opts.max_digest_feat
        if n > len(topk):
            n = len(topk)
        topk = topk[:n]
        digest_str = ','.join(["{}_{}".format(kv[0], kv[1]) for kv in topk])
        return digest_str

class LogSummary:
    def __init__(self, ctx, lines):
        self.ctx = ctx
        self.lines = []
        self.digests = {}
        self.digests_family = {}
        self.features = []
        for line in lines:
            self.features.append(LogItemExtractor(self.ctx, line))

    def digest(self):
        for f in self.features:
            d = f.digest()
            if len(d) == 0:
                continue
            if d in self.digests:
                self.digests[d] += 1
                self.digests_family[d].append(f.line)
            else:
                ctx.digest_tree.add(d)
                self.digests[d] = 1
                self.digests_family[d] = [f.line]

        for d in self.digests.keys():
            for dt in ctx.digest_tree.nodes:
                if distance(d, dt) < min(len(d), len(dt)) * 0.5:
                    ctx.digest_tree.union(d, dt)

        ctx.digest_tree.prehandle()
        # prepared = [(ctx.digest_tree.find(d), v) for (d, v) in self.digests.items()]
        # return {key: sum(j for i, j in group) for key, group in groupby(prepared, key=lambda x: x[0])}
        return self.digests

    def summary(self):
        digests = self.digest()
        result = {}
        for d in digests:
            fa = ctx.digest_tree.find(d)
            if not fa in result:
                result[fa] = []
            result[fa].extend(self.digests_family[d])
        return result

    def output_summary(self):
        result = self.summary()
        f = open("result.md", "w")
        for fa in result:
            f.write("{}\n".format(fa))
            f.write("```\n")
            for x in result[fa]:
                f.write("{}\n".format(x.replace("\n", "")))
            f.write("```\n")
        f.close()

def test_distance():
    ex = LogItemExtractor("a b c d")
    ex2 = LogItemExtractor("a b c d")
    assert distance(ex.features, ex2.features) == 0
    ex2 = LogItemExtractor("a b c")
    assert distance(ex.features, ex2.features) == 1
    ex2 = LogItemExtractor("a e c")
    assert distance(ex.features, ex2.features) == 2

def test_dsu():
    dsu = DSU()
    dsu.add(1)
    dsu.add(2)
    dsu.add(3)
    dsu.add(4)
    assert dsu.find(1) == 1
    assert dsu.find(3) == 3
    dsu.union(1, 2)
    assert dsu.find(1) == dsu.find(2)
    assert dsu.find(1) != dsu.find(3)

def test_digest():
    ctx = Context()
    ex = LogItemExtractor(ctx, "a b c d a a c e")
    print(ex.digest())
    ex = LogItemExtractor(ctx, "[2024/02/28 23:58:15.114 +08:00] [DEBUG] [SegmentReader.cpp:45] [Stopped] [thread_id=1]")
    print(ex.features, ex.digest())
    ex = LogItemExtractor(ctx, "[2024/02/28 23:58:14.547 +08:00] [INFO] [ComputeLabelHolder.cpp:47] [\"get cluster id: unknown\"] [thread_id=1]")
    print(ex.features, ex.digest())
    ex = LogItemExtractor(ctx, '''[2024/02/28 23:58:15.045 +08:00] [DEBUG] [DMVersionFilterBlockInputStream.h:86] ["Total rows: 0, pass: -nan%, complete pass: -nan%, complete not pass: -nan%, not clean: -nan%, is deleted: -nan%, effective: -nan%, start_ts: 0"] [source="mode=COMPACT"] [thread_id=148]''')
    print(ex.features, ex.digest())
    
if __name__ == '__main__':
    # test_dsu()
    # exit()
    test_digest()
    # exit()
    ctx = Context()
    f = open("samples/snap1.txt", "r")
    lines1 = f.readlines()
    f.close()
    f = open("samples/snap2.txt", "r")
    lines2 = f.readlines()
    f.close()
    s1 = LogSummary(ctx, lines1)
    s2 = LogSummary(ctx, lines2)
    # d1 = s1.digest()
    # print(len(d1))
    # for (k, v) in d1.items():
    #     if v > 0:
    #         # print(v, "====>", k, "<=====", s1.digests_family[k].line)
    #         print(v, "====>", k)
    # s1.output_summary()
    ctx.joint_summary(s1, s2)


