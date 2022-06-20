
def test():
    for i,j in zip(range(10),range(10,20)):
        yield i,j

for i,j in test():
    print(i,j)


