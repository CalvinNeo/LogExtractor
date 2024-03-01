from extractor import *
from utils import *
import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('filename1') 
    parser.add_argument('filename2') 
    args = parser.parse_args()
    
    ctx = Context()

    f = open(args.filename1, "r")
    lines1 = f.readlines()
    f.close()
    f = open(args.filename2, "r")
    lines2 = f.readlines()
    f.close()
    s1 = LogSummary(ctx, lines1)
    s2 = LogSummary(ctx, lines2)

    ctx.joint_summary(s1, s2)