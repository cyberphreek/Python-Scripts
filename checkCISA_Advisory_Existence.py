import hashlib
import array

oldList=''
newList=''
hashlist=[]

with open(oldList) as f:
    for line in f:
        line=line.strip()
        linehash=hashlib.sha256(line.encode()).hexdigest()
        hashlist.append(linehash)
    with open(newList) as f2:
        for line in f2:
            line=line.strip()
            hash=hashlib.sha256(line.encode()).hexdigest()
            if hash not in hashlist:
                print('New Advisory Found: '+line)
                