# coding: utf-8
from concurrent.futures import ThreadPoolExecutor, as_completed
import time


# def spider(page):
#     time.sleep(page)
#     print(f"crawl task{page} finished")
#     return page
#
# def main():
#     with ThreadPoolExecutor(max_workers=5) as t:
#         obj_list = []
#         for page in range(1, 5):
#             obj = t.submit(spider, page)
#             obj_list.append(obj)
#
#         for future in as_completed(obj_list):
#             data = future.result()
#             print(f"main: {data}")
#
# main()


# def job(*x):
# 	# 解包
#     pid, url = x
# 	# to do something
#     print(pid,url)
#
# item_list = []
# a = [1,2,3]
# b = [4,5,6]
# for pid,url in zip(a,b):
# 	item_list.append((pid, url))
#
# executor = ThreadPoolExecutor(max_workers=12)
# executor.map(job, item_list, chunksize=6)


def doFileParse(filepath, segment, wordslist):
    print(filepath)
    print(segment)
    print(wordslist)

# 调用方法
args = ("filepath", "thu1", "Words")
executor = ThreadPoolExecutor(max_workers=12)
# newTask = executor.submit(lambda p: doFileParse(*p), args)
newTask = executor.submit(doFileParse, "filepath", "thu1", "Words")
