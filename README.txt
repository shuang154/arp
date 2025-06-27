arp欺骗


启动指令.txt     里面有启动项目arp.py的指令和说明
arp.py              欺骗主脚本，获得用户名密码写入temporary.txt  
wash.py           对temporary.txt 中的用户密码清洗，以用户密码为标准删去重复的保留最新的记录，将数据提取放入wifi.txt,再加工成图书馆登录格式存入lib.txt
get_info.py         用lib.txt中的每行用户密码登录图书馆获取真实姓名和预约信息
lib_analyse.txt   get_info.py 用lib.txt中的信息登录后获得的姓名预约，座位时间等信息
temporary.txt    初始获取的get包中的用户名密码
hunter_ultimate.log   arp.py运行日志
lib.txt                可以图书馆登录的用户名密码格式 
wash_old.py      
wifi.txt                可以登录校园网的用户名密码，就是捕捉的temporary.txt中的用户名密码单独提炼


arp.py获取原始数据---->wash.py清洗整理----------->get_info.py从图书馆获取信息
                                                    /|\
                                                  /  |  \
                                                /    |    \                                
                                              /      |      \
                                            /        |        \
               去重temporary.txt    wifi.txt   lib.txt  