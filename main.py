import re
from collections import Counter

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

class LogItemExtractor:
    def __init__(self, line):
        self.line = line
        self.features = []
        self.extract()

    def extract(self):
        elements = self.line.split(" ")
        for e in elements:
            if e.isnumeric():
                self.features.append("")
            elif is_likely_date(e):
                self.features.append("")
            elif len(e) > 15:
                self.features.append("")
            else:
                self.features.append(e)

    def distance(self, other):
        ns = len(self.features)
        no = len(other.features)
        dp = [[0 for i in range(no)] for j in range(ns)]
        for i in range(no):
            dp[0][i] = i
        for i in range(ns):
            dp[i][0] = i
        for i in range(1, ns):
            for j in range(1, no):
                if self.features[i] == other.features[j]:
                    dp[i][j] = dp[i - 1][j - 1]
                else:
                    dp[i][j] = 1 + min([dp[i - 1][j - 1], dp[i - 1][j], dp[i][j - 1]])
        return dp[ns - 1][no - 1]

    def digest(self):
        c = dict(Counter(self.features))
        topk = [(k, c[k]) for k in sorted(c, key = c.get, reverse = True) if k != ""]
        if len(topk) == 0:
            return ""
        n = int(len(topk) * 0.3)
        if n < 1:
            n = 1
        elif n > 10:
            n = 10
        topk = topk[:n]
        return ','.join(["{}_{}".format(kv[0], kv[1]) for kv in topk])

class LogSummary:
    def __init__(self, lines):
        self.lines = []
        self.digests = {}
        self.features = []
        for line in lines:
            self.features.append(LogItemExtractor(line))

    def digest(self):
        for f in self.features:
            d = f.digest()
            if d in self.digests:
                self.digests[d] += 1
            else:
                self.digests[d] = 1
        return self.digests

def test_distance():
    ex = LogItemExtractor("a b c d")
    ex2 = LogItemExtractor("a b c d")
    assert ex.distance(ex2) == 0
    ex2 = LogItemExtractor("a b c")
    assert ex.distance(ex2) == 1
    ex2 = LogItemExtractor("a e c")
    assert ex.distance(ex2) == 2

def test_digest():
    ex = LogItemExtractor("a b c d a a c e")
    print(ex.digest())
    ex = LogItemExtractor("[2024/02/28 23:58:15.114 +08:00] [DEBUG] [SegmentReader.cpp:45] [Stopped] [thread_id=1]")
    print(ex.features, ex.digest())

if __name__ == '__main__':
    # test_digest()
    # exit()
    f = open("samples/snap1.txt", "r")
    lines1 = f.readlines()
    f.close()
    f = open("samples/snap2.txt", "r")
    lines2 = f.readlines()
    f.close()
    s1 = LogSummary(lines1)
    s2 = LogSummary(lines2)
    d1 = s1.digest()
    print(d1.values())
    for (k, v) in d1.items():
        if v > 1:
            print(v, "====>", k)


