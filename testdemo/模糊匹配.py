import re

file_list = [
    {
        "type": "dir",
        "size": "123",
        "name": "access.log",
    },
    {
        "type": "dir",
        "size": "123",
        "name": "access.log.gz",
    },
    {
        "type": "dir",
        "size": "123",
        "name": "error.log",
    },
    {
        "type": "dir",
        "size": "123",
        "name": "access-auth.log",
    },
]


def fuzzy_finder(key, data):
    """
    模糊查找器
    :param key: 关键字
    :param data: 数据
    :return: list
    """
    # 结果列表
    suggestions = []
    # 非贪婪匹配，转换 'djm' 为 'd.*?j.*?m'
    # pattern = '.*?'.join(key)
    pattern = '.*%s.*'%(key)
    # print("pattern",pattern)
    # 编译正则表达式
    regex = re.compile(pattern)
    for item in data:
        # print("item",item['name'])
        # 检查当前项是否与regex匹配。
        match = regex.search(item['name'])
        if match:
            # 如果匹配，就添加到列表中
            suggestions.append(item)

    return suggestions

# 搜索关键字
keys = "access"
result = fuzzy_finder(keys,file_list)
print(result)