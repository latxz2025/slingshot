import re

avdict = {'360tray.exe': '360安全卫士-实时保护', '360safe.exe': '360安全卫士-主程序',
          '360skylarsvc': '360终端安全管理系统', '360sd.exe': '360杀毒'}
newtasklist = ['360Tray.exe:508', '360skylarsvc:716', '360:832']
avlist = []
for task in newtasklist:
    pattern3 = re.compile('.*%s.*' % (task.split(":")[0]), re.I)
    print(task.split(":")[0]+"+++++")
    for item in list(avdict.items()):
        print(item[0]+"-----")
        avname = pattern3.search(item[0])
        if avname:
            avlist.append(task + ":" + avname.group())

print(avlist)