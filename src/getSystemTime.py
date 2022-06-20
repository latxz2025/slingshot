import time,datetime,random

class GetTime:
    def __init__(self):
        pass

    # 时间格式 202241515578832
    def getSystemTime1():
        nowTime = datetime.datetime.now()
        t = str(nowTime.year)+str(nowTime.month)+str(nowTime.day)+str(nowTime.hour)+str(nowTime.minute)+str(nowTime.second)+str(random.randint(100,999))
        return t

    # 时间格式 2016-04-07 10:25:09
    def getSystemTime2():
        nowTime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        # print(nowTime)
        return nowTime

    # 时间格式 datetime.datetime(2022, 5, 26, 15, 24, 58, 427333)
    def getSystemTime3():
        nowTime = datetime.datetime.now()
        # 时间格式 202241515578832
        # t = str(nowTime.year)+str(nowTime.month)+str(nowTime.day)+str(nowTime.hour)+str(nowTime.minute)+str(nowTime.second)+str(random.randint(100,999))
        t = nowTime
        return t

    # 时间格式 2020-4-15-3 15点15分15秒
    def getSystemTime4():
        nowTime = time.localtime(time.time())
        t = ("{}-{}-{} {}点{}分{}秒".format(nowTime[0], nowTime[1], nowTime[2], nowTime[3], nowTime[4], nowTime[5]))
        return t

    # 时间格式 time.struct_time(tm_year=2022, tm_mon=4, tm_mday=18, tm_hour=13, tm_min=56, tm_sec=50, tm_wday=0, tm_yday=108, tm_isdst=0)
    def getSystemTime5():
        nowTime = time.localtime(time.time())
        t = ("{}{}{}".format(nowTime[0], nowTime[1], nowTime[2]))
        return t

# if __name__ == "__main__":
#     getTime = GetTime()
# GetTime().getSystemTime3()