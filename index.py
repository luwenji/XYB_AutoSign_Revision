# -*- coding: utf-8 -*-
import base64
import hmac
from urllib import parse
import requests
import sys
import json
import json5
from datetime import datetime, timedelta, timezone
import time
import hashlib
import logging
'''
2022-10-21 [bylengfeng]修复：
1、修复因账户密码错误以及未注册等原因导致登陆不上，影响后续账户执行问题
2、修复因为打卡任务到期，影响后续账户执行问题
3、修复因为没有打卡计划，影响后续账户执行问题
4、修复user.json文件多了一个','导致运行失败问题（现在可加可不加）
5、新增json5（在使用的时候请安装模块）
6、新增logging（在使用的时候请安装模块）
github原仓库地址：https://github.com/heiwa9/XYB_AutoSign_Revision
喜欢请给Star
修复代码仓库地址：
'''
urls = {
    # 'login': 'https://xcx.xybsyw.com/login/login!wx.action',
    'login': 'https://xcx.xybsyw.com/login/login.action',
    'loadAccount': 'https://xcx.xybsyw.com/account/LoadAccountInfo.action',
    'ip': 'https://xcx.xybsyw.com/behavior/Duration!getIp.action',
    'trainId': 'https://xcx.xybsyw.com/student/clock/GetPlan!getDefault.action',
    # 'position':'https://xcx.xybsyw.com/student/clock/GetPlan!detail.action',
    'sign': 'https://app.xybsyw.com/behavior/Duration.action',
    'autoSign': 'https://xcx.xybsyw.com/student/clock/Post!autoClock.action',
    'newSign': 'https://xcx.xybsyw.com/student/clock/PostNew!updateClock.action',
    'status': 'https://xcx.xybsyw.com/student/clock/GetPlan!detail.action'
}

host1 = 'xcx.xybsyw.com'
host2 = 'app.xybsyw.com'


def getTimeStr():
    utc_dt = datetime.utcnow().replace(tzinfo=timezone.utc)
    bj_dt = utc_dt.astimezone(timezone(timedelta(hours=8)))
    return bj_dt.strftime("%Y-%m-%d %H:%M:%S")

# 日志
def init_log(level=logging.DEBUG):
    logging.basicConfig(
        level=level,  # 控制台打印的日志级别
        filename='xiaoyoub.log',
        filemode='w',  ##模式，有w和a追加，w就是写模式，每次都会重新写日志，覆盖之前的日志
        format='%(asctime)s - [%(levelname)s] - %(message)s'
        # 日志格式
    )
    # logging.basicConfig(
    #     level=level,
    #     format='%(asctime)s - [%(levelname)s] - %(message)s',
    #     datefmt='%Y-%m-%d %H:%M:%S'
    # )
    log = logging.getLogger('script log')
    return log


__all__ = [
    'log',

]

log = init_log(logging.INFO)

# 日志
def str2md5(str):
    return hashlib.md5(str.encode(encoding='UTF-8')).hexdigest()


def log(content):
    print(getTimeStr() + ' ' + str(content))
    sys.stdout.flush()


# 获取Header
def getHeader(host):
    userAgent = 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36 MicroMessenger/7.0.9.501 NetType/WIFI MiniProgramEnv/Windows WindowsWechat'
    contentType = 'application/x-www-form-urlencoded'
    headers = {
        'user-agent': userAgent,
        'content-type': contentType,
        'host': host,
        'Connection': 'keep-alive'
    }
    return headers


# 获取账号和密码
def getuser(userInfo):
    data = {
        'username': userInfo['token']['username'],
        'password': str2md5(userInfo['token']['password'])
    }
    return data


# 登录获取sessionId和loginerId
def login(userInfo):
    data = getuser(userInfo)
    headers = getHeader(host1)
    url = urls['login']
    resp = requests.post(url=url, headers=headers, data=data).json()
    print(1)
    print(resp)
    if ('登录成功' in resp['msg']):
        ret = {
            'sessionId': resp['data']['sessionId'],
            'loginerId': resp['data']['loginerId']
        }
        log(f"sessionId:{resp['data']['sessionId']}")
        log(f"loginerId:{resp['data']['loginerId']}")
        return ret
    # 成功返回数据继续往下
    else:
        # log(resp['msg'])
        # logging.info("##" + phone + "##" + resp['msg'])
        return 'error'
        # 错误返回error
        # 修复登录密码错误不自动停止避免影响到其他的账户
        # exit(-1)


# 获取姓名
def getUsername(sessionId):
    headers = getHeader(host1)
    headers['cookie'] = f'JSESSIONID={sessionId}'
    url = urls['loadAccount']
    resp = requests.post(url=url, headers=headers).json()
    print(2)
    print(resp)
    if ('操作成功' in resp['msg']):
        ret = resp['data']['loginer']
        log(f"姓名:{ret}")
        return ret
    else:
        log('获取姓名失败')
        return 'error'
        # exit(-1)


# 获取ip
def getIP(sessionId):
    headers = getHeader(host1)
    headers['cookie'] = f'JSESSIONID={sessionId}'
    url = urls['ip']
    resp = requests.post(url=url, headers=headers).json()
    print(3)
    print(resp)
    if ('success' in resp['msg']):
        ret = resp['data']['ip']
        log(f'ip:{ret}')
        return ret
    else:
        return 'error'
        log('ip获取失败')
        # exit(-1)


# 获取trainID
def getTrainID(sessionId):
    headers = getHeader(host1)
    headers['cookie'] = f'JSESSIONID={sessionId}'
    url = urls['trainId']
    resp = requests.post(url=url, headers=headers).json()
    print(4)
    print(resp)
    #总的判断接口正确性
    if ('200' in resp['code'] ):# 20221019修改 建议使用code
        if 'endClockVo' in resp['data']:
            print("实习计划已经到期")
            return 'error'  # 返回错误 20221021
        else:
            print("实习计划没有到期")
            if (resp['data']['clockVo']==None):#没有计划任务的
                # 获取数据成功且计划任务为空的时候说明计划任务失败
                log('没有计划任务')#打印到控制台
                # 存在计划任务但是已经过期
                return 'error'#返回错误 20221021
            else:
                ret = resp['data']['clockVo']['traineeId']  # 获取签到任务计划
                log(f'traineeId:{ret}')
                return ret
    else:
        return 'error'  # 返回错误 20221021


# 获取经纬度\签到地址
def getPosition(sessionId, trainId):
    headers = getHeader(host1)
    headers['cookie'] = f'JSESSIONID={sessionId}'
    url = urls['status']
    data = {
        'traineeId': trainId
    }
    resp = requests.post(url=url, headers=headers, data=data).json()
    print(5)
    print(resp)
    if ('操作成功' in resp['msg']):
        address = resp['data']['postInfo']['address']
        lat = resp['data']['postInfo']['lat']
        lng = resp['data']['postInfo']['lng']
        ret = {
            'lat': lat,
            'lng': lng
        }
        log(f'经度:{lng}|纬度:{lat}')
        log(f'签到地址:{address}')
        return ret
    else:
        logging.info("##" + phone + "##" + "经纬度获取失败，可能原因：没有找到计划打卡的任务")  # 打印到文件log
        log('经纬度获取失败')
        return 'error'
        # exit(-1)


def getSignForm(data, user):
    timeStamp = int(time.time())
    form = {
        'login': '1',
        'appVersion': '1.5.75',
        'operatingSystemVersion': '10',
        'deviceModel': 'microsoft',
        'operatingSystem': 'android',
        'screenWidth': '415',
        'screenHeight': '692',
        'reportSrc': '2',
        'eventTime': timeStamp,
        'eventType': 'click',
        'eventName': 'clickSignEvent',
        'clientIP': data['ip'],
        'pageId': data['pageId'],  # 30
        'itemID': 'none',
        'itemType': '其他',
        'stayTime': 'none',
        'deviceToken': '',
        'netType': 'WIFI',
        'app': 'wx_student',
        'preferName': '成长',
        'pageName': '成长-签到',
        'userName': data['userName'],
        'userId': data['loginerId'],
        'province': user['location']['province'],
        'country': user['location']['country'],
        'city': user['location']['city'],
    }
    return form


# 签到请求
def signReq(sessionId, data):
    headers = getHeader(host2)
    headers['cookie'] = f'JSESSIONID={sessionId}'
    url = urls['sign']
    resp = requests.post(url=url, headers=headers, data=data).json()
    print(6)
    print(resp)
    if ('success' in resp['msg']):
        log(f'签到请求执行成功')
    else:
        log('签到请求执行失败')
        exit(-1)


# 执行签到
def autoSign(sessionId, data):
    headers = getHeader(host1)
    headers['cookie'] = f'JSESSIONID={sessionId}'
    url = urls['autoSign']
    resp = requests.post(url=url, headers=headers, data=data).json()
    print(7)
    print(resp)
    log(resp['msg'])
    if resp['msg']=='操作成功':
        return resp['msg']
        logging.info("#@" + phone + "#@" + "打卡成功")
    else:
        logging.info("##" + phone + "##" + '打卡失败')


# 重新签到
def newSign(sessionId, data):
    headers = getHeader(host1)
    headers['cookie'] = f'JSESSIONID={sessionId}'
    url = urls['newSign']
    resp = requests.post(url=url, headers=headers, data=data).json()
    print(8)
    print(resp)
    log(resp['msg'])
    return resp['msg']


# 获取签到状态
def getSignStatus(sessionId, trainId, sence):
    headers = getHeader(host1)
    headers['cookie'] = f'JSESSIONID={sessionId}'
    url = urls['status']
    data = {'traineeId': trainId}

    resp = requests.post(url=url, headers=headers, data=data).json()
    print(9)
    print(resp)
    if sence == '1':
        return True if len(resp['data']['clockInfo']['outTime']) > 0 else False
    else:
        return True if len(resp['data']['clockInfo']['inTime']) > 0 else False


# Server酱通知
def sendNoice(msg):
    log('正在发送通知')
    config = readJsonInfo()
    if config['server_send_key'] == "":
        log('不发送通知……')
        return
    resp = requests.post(url='https://sctapi.ftqq.com/{0}.send'.format(config['server_send_key']),
                         data={'title': '校友邦签到通知', 'desp': '时间：' + getTimeStr() + "\n消息：" + str(msg)})
    print(10)
    print(resp)
    if resp.status_code == 200:
        log('推送成功')
    else:
        log('推送失败')


def dingTalkNoice(msg):
    log('正在发送通知')
    config = readJsonInfo()
    if config['ding_talk_secret'] == "":
        log('不发送通知……')
        return
    timestamp = str(round(time.time() * 1000))
    secret_enc = config['ding_talk_secret'].encode('utf-8')
    string_to_sign = '{}\n{}'.format(timestamp, config['ding_talk_secret'])
    string_to_sign_enc = string_to_sign.encode('utf-8')
    hmac_code = hmac.new(secret_enc, string_to_sign_enc,
                         digestmod=hashlib.sha256).digest()
    sign = parse.quote_plus(base64.b64encode(hmac_code))
    resp = requests.post(url='https://oapi.dingtalk.com/robot/send?access_token={0}&timestamp={1}&sign={2}'.
                         format(config["ding_talk_access_token"],
                                timestamp, sign,), headers={'content-type': 'application/json'}, data=json.dumps({
                                    "msgtype": "text",
                                    "text": {
                                        "content": '校友帮签到通知\n时间:' + getTimeStr() + '\n消息:' + str(msg),
                                    }
                                }))
    print(11)
    print(resp)
    if resp.status_code == 200:
        log('推送成功')
    else:
        log('推送失败')


def signHandler(userInfo, sence):
    sessions = login(userInfo)
    if sessions=='error':
        logging.info("##" + phone + "##" + '账户密码错误')
    else:
        sessionId = sessions['sessionId']
        loginerId = sessions['loginerId']
        trainId = getTrainID(sessionId)
        if trainId == 'error':
            logging.info("##" + phone + "##" + "没有计划任务")#打印到文件log
        else:
            userName = getUsername(sessionId)
            if userName == 'error':
                logging.info("##" + phone + "##" + "名字获取失败")  # 打印到文件log
            else:
                ip = getIP(sessionId)
                if ip == 'error':
                    logging.info("##" + phone + "##" + "ip获取失败")  # 打印到文件log
                else:
                    position = getPosition(sessionId, trainId)
                    if position == 'error':
                        logging.info("##" + phone + "##" + "经纬度获取失败")  # 打印到文件log
                    else:
                        lng = position['lng']
                        lat = position['lat']
                        data = {
                            'pageId': '30',
                            'userName': userName,
                            'loginerId': loginerId,
                            'ip': ip
                        }
                        formData = getSignForm(data, userInfo)
                        signReq(sessionId, formData)
                        signFormData = {
                            'traineeId': trainId,
                            'adcode': userInfo['location']['adcode'],
                            'lat': lat,
                            'lng': lng,
                            'address': userInfo['location']['address'],
                            'deviceName': 'microsoft',
                            'punchInStatus': '1',
                            'clockStatus': sence,
                            'imgUrl': '',
                            'reason': userInfo['reason']
                        }
                        if sence == '1':
                            autoSign(sessionId, signFormData)
                            if getSignStatus(sessionId, trainId, sence):
                                sendNoice(userName + '签退成功')
                                dingTalkNoice(userName + '签退成功')
                                log('校友邦实习任务签退成功\n\n')
                            else:
                                sendNoice(userName + '签退失败')
                                dingTalkNoice(userName + '签退失败')
                                log('校友邦实习任务签退失败!')
                        else:
                            if getSignStatus(sessionId, trainId, sence):
                                log('已签到,不做重复签到')
                                # 即使打卡过了，也要再次打卡
                                autoSign(sessionId, signFormData)
                            else:
                                autoSign(sessionId, signFormData)
                            if getSignStatus(sessionId, trainId, sence):
                                sendNoice(userName + '签到成功')
                                dingTalkNoice(userName + '签到成功')
                                log('校友邦实习任务签到成功\n\n')

                            else:
                                sendNoice(userName + '签到失败')
                                dingTalkNoice(userName + '签到失败')
                                log('校友邦实习任务签到失败!')
                                # logging.info("##" + phone + "##" + '校友邦实习任务签到失败')


# 读取user.json
def readJsonInfo():
    with open('user.json', "r", encoding='utf-8') as json_file:
        data = json5.load(json_file)
    json_file.close()

    return data


# 腾讯云函数使用
def main_handler(event, context):
    sence = 1 if event['Message'] == 'signout' else 0
    users = readJsonInfo()
    for user in users['user']:
        signHandler(user, sence)
        time.sleep(1.5)


if __name__ == '__main__':
    global phone #定义全局账号
    users = readJsonInfo()
    for user in users['user']:
        # 读取第一个账户的手机号
        # print(user['token']['username'])
        phone=user['token']['username']
        signHandler(user, sence=1)
        print("准备下个账号")
        time.sleep(1.5)
